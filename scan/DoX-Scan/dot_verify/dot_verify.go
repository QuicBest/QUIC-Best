package dot_verify

import (
	"DoX-Scan/clients"
	"crypto/tls"
	"encoding/json"
	"github.com/miekg/dns"
	"time"
)

type DOTResult struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	TLSVer      string `json:"tls_ver"`
	SuccessFlag bool   `json:"success_flag"`
	// 证书
	CertChain     string  `json:"cert_chain"`
	CertValid     bool    `json:"cert_valid"`
	CertTimeValid bool    `json:"cert_time_valid"`
	CertLifetime  float64 `json:"cert_lifetime"`
	CertLevel     string  `json:"cert_level"`
	CAName        string  `json:"caName"`
	CertError     string  `json:"cert_error"`
}

type DOTPer struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	TLSVer      string `json:"tls_ver"`
	SuccessFlag bool   `json:"success_flag"`

	QueryTime float64 `json:"query_time"`
	TotalTime float64 `json:"total_time"`

	HandshakeTime float64 `json:"handshake_time"`
}

func Verify(ip string, queryport string, scanType string) (string, string) {
	timeout := 10
	clientSessionCache := tls.NewLRUClientSessionCache(1000)

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: clientSessionCache,
			SkipCommonName:     true,
			InsecureSkipVerify: true,
		},
	}

	queryadderss := "tls" + "://" + ip + ":" + queryport

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
			return ip, "Cannot make the DNS request"
		}

		result := reply.GetMetrics()
		DOTTarget := new(DOTResult)
		DOTTarget.Ip = ip
		DOTTarget.Port = queryport

		DOTTarget.TLSVer = *result.TLSVersion
		DOTTarget.CertChain = *result.CertChain
		DOTTarget.CertValid = *result.CertValid
		DOTTarget.CertTimeValid = *result.CertTimeValid
		DOTTarget.CertLifetime = *result.CertLifetime
		DOTTarget.CertLevel = *result.CertLevel
		DOTTarget.CAName = *result.CAName
		DOTTarget.CertError = *result.CertError

		DOTTarget.SuccessFlag = *result.SuccessFlag

		resultjson, errjson := json.Marshal(DOTTarget)
		if errjson != nil {
			return ip, "json error"
		}
		return string(resultjson), "success"
	} else {

		DOTTarget := new(DOTPer)
		DOTTarget.Ip = ip
		DOTTarget.Port = queryport

		resultstr := ""

		for i := 1; i <= 3; i++ {
			reply := u.Exchange(&req, scanType)
			if reply.GetError() != nil {
				return ip, "Cannot make the DNS request"
			}
			result := reply.GetMetrics()
			if result.SuccessFlag == nil {
				return ip, "fail"
			}

			DOTTarget.TLSVer = *result.TLSVersion
			DOTTarget.SuccessFlag = *result.SuccessFlag

			queryTime := float64(*result.QueryTime) / 1e6
			handshakeTime := float64(*result.TLSHandshakeDuration+*result.TCPHandshakeDuration) / 1e6
			totalTime := float64(*result.TotalTime) / 1e6

			DOTTarget.QueryTime = queryTime
			DOTTarget.TotalTime = totalTime
			DOTTarget.HandshakeTime = handshakeTime

			resultjson, errjson := json.Marshal(DOTTarget)
			if errjson != nil {
				return ip, "json error"
			}
			resultstr = resultstr + "###" + string(resultjson)

			req.Id = dns.Id()
			time.Sleep(time.Second * 1)
		}

		return resultstr, "success"
		//return resultstr, "unknown err"
	}

}
