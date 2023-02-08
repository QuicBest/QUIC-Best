package doq_verify

import (
	"DoX-Scan/clients"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"time"
)

var DefaultQUICVersions = []quic.VersionNumber{
	quic.Version1,
	quic.VersionDraft29,
	quic.Version2,
}

type DOQResult struct {
	Ip                     string `json:"ip"`
	Port                   string `json:"port"`
	TLSVer                 string `json:"tls_ver"`
	QUICVer                string `json:"quic_ver"`
	QUICNegotiatedProtocol string `json:"quic_negotiated_protocol"`
	SuccessFlag            bool   `json:"success_flag"`
	// 证书
	CertChain     string  `json:"cert_chain"`
	CertValid     bool    `json:"cert_valid"`
	CertTimeValid bool    `json:"cert_time_valid"`
	CertLifetime  float64 `json:"cert_lifetime"`
	CertLevel     string  `json:"cert_level"`
	CAName        string  `json:"caName"`
	CertError     string  `json:"cert_error"`
}

type DOQPer struct {
	Ip                     string `json:"ip"`
	Port                   string `json:"port"`
	TLSVer                 string `json:"tls_ver"`
	QUICVer                string `json:"quic_ver"`
	QUICNegotiatedProtocol string `json:"quic_negotiated_protocol"`
	SuccessFlag            bool   `json:"success_flag"`

	QueryTime    float64 `json:"query_time"`
	TotalTime    float64 `json:"total_time"`
	QUICUsed0RTT bool    `json:"quic_used0RTT"`

	HandshakeTime float64 `json:"handshake_time"`
}

type DOQLog struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	QLogMessage string `json:"qlog_message"`
}

func Verify(ip string, queryport string, scanType string) (string, string) {
	tokenStore := quic.NewLRUTokenStore(5, 50)
	clientSessionCache := tls.NewLRUClientSessionCache(1000)

	timeout := 10
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	_, portString, _ := net.SplitHostPort(udpConn.LocalAddr().String())
	udpConn.Close()
	port, _ := strconv.Atoi(portString)

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: clientSessionCache,
			SkipCommonName:     true,
			InsecureSkipVerify: true,
		},
		QuicOptions: &clients.QuicOptions{
			TokenStore:   tokenStore,
			QuicVersions: DefaultQUICVersions,
			LocalPort:    port,
		},
	}

	queryadderss := "quic" + "://" + ip + ":" + queryport

	u, err := clients.AddressToClient(queryadderss, opts)
	if err != nil {
		return ip, "Cannot create an upstream"
	}

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "example.com" + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	if scanType == "verify" {
		reply := u.Exchange(&req, scanType)
		if reply.GetError() != nil {
			fmt.Println(reply.GetError())
			return ip, "Cannot make the DNS request"
		}
		DOQTarget := new(DOQResult)
		DOQTarget.Ip = ip
		DOQTarget.Port = queryport

		result := reply.GetMetrics()
		DOQTarget.QUICVer = *result.QUICVersion
		DOQTarget.QUICNegotiatedProtocol = *result.QUICNegotiatedProtocol
		DOQTarget.TLSVer = *result.TLSVersion
		DOQTarget.SuccessFlag = *result.SuccessFlag

		DOQTarget.CertChain = *result.CertChain
		DOQTarget.CertValid = *result.CertValid
		DOQTarget.CertTimeValid = *result.CertTimeValid
		DOQTarget.CertLifetime = *result.CertLifetime
		DOQTarget.CertLevel = *result.CertLevel
		DOQTarget.CAName = *result.CAName
		DOQTarget.CertError = *result.CertError

		resultjson, errjson := json.Marshal(DOQTarget)
		if errjson != nil {
			return ip, "json error"
		}
		return string(resultjson), "success"

	} else {
		DOQTarget := new(DOQPer)
		DOQTarget.Ip = ip
		DOQTarget.Port = queryport
		
		qlogmessage := ""
		resultstr := ""

		for i := 1; i <= 3; i++ {
			reply := u.Exchange(&req, scanType)
			if reply.GetError() != nil {
				fmt.Println(reply.GetError())
				return ip, "Cannot make the DNS request"
			}

			DOQTarget.Ip = ip
			DOQTarget.Port = queryport
			result := reply.GetMetrics()
			if result.SuccessFlag == nil {
				return ip, "fail"
			}

			DOQTarget.QUICVer = *result.QUICVersion
			DOQTarget.QUICNegotiatedProtocol = *result.QUICNegotiatedProtocol
			DOQTarget.TLSVer = *result.TLSVersion
			DOQTarget.SuccessFlag = *result.SuccessFlag

			DOQTarget.QueryTime = float64(*result.QUICHandshakeDuration) / 1e6
			DOQTarget.TotalTime = float64(*result.TotalTime) / 1e6
			DOQTarget.HandshakeTime = float64(*result.QUICHandshakeDuration) / 1e6

			b, err := json.MarshalIndent(reply.GetMetrics().QLogMessages, "", "  ")
			if err != nil {
				fmt.Println("json err")
			}
			qlogmessage = qlogmessage + "||||||" + string(b)

			DOQTarget.QUICUsed0RTT = *result.QUICUsed0RTT
			resultjson, _ := json.Marshal(DOQTarget)

			resultstr = resultstr + "###" + string(resultjson)

			req.Id = dns.Id()
			time.Sleep(time.Second * 1)

		}
		return resultstr + qlogmessage, "success"

	}

}
