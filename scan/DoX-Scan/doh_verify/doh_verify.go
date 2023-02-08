package doh_verify

import (
	"DoX-Scan/clients"
	"crypto/tls"
	"encoding/json"
	_ "fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type DOHResult struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	Suffix      string `json:"suffix"`
	TLSVer      string `json:"tls_ver"`
	HTTPVer     string `json:"http_ver"`
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

type DOHPer struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	Suffix      string `json:"suffix"`
	TLSVer      string `json:"tls_ver"`
	HTTPVer     string `json:"http_ver"`
	SuccessFlag bool   `json:"success_flag"`

	QueryTime float64 `json:"query_time"`
	TotalTime float64 `json:"total_time"`

	HandshakeTime float64 `json:"handshake_time"`
}

func Verify(line string, queryport string, scanType string) (string, string) {

	timeout := 10
	clientSessionCache := tls.NewLRUClientSessionCache(1000)

	ip := line
	suffix := "/dns-query"

	if len(strings.Split(line, ",")) > 1 {
		ip = strings.Split(line, ",")[0]
		suffix = "/" + strings.Split(line, ",")[1]
	}

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			ClientSessionCache: clientSessionCache,
		},
	}

	queryadderss := "https" + "://" + ip + suffix + ":" + queryport
	//fmt.Println(queryadderss)

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

		DOHTarget := new(DOHResult)
		DOHTarget.Ip = ip
		DOHTarget.Port = queryport
		DOHTarget.Suffix = suffix

		result := reply.GetMetrics()

		DOHTarget.TLSVer = *result.TLSVersion
		DOHTarget.HTTPVer = *result.HTTPVersion
		DOHTarget.CertChain = *result.CertChain
		DOHTarget.CertValid = *result.CertValid
		DOHTarget.CertTimeValid = *result.CertTimeValid
		DOHTarget.CertLifetime = *result.CertLifetime
		DOHTarget.CertLevel = *result.CertLevel
		DOHTarget.CAName = *result.CAName
		DOHTarget.CertError = *result.CertError

		DOHTarget.SuccessFlag = *result.SuccessFlag

		resultjson, errjson := json.Marshal(DOHTarget)
		if errjson != nil {
			return ip, "json error"
		}
		return string(resultjson), "success"

	} else {

		DOHTarget := new(DOHPer)
		DOHTarget.Ip = ip
		DOHTarget.Port = queryport
		DOHTarget.Suffix = suffix

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
			DOHTarget.SuccessFlag = *result.SuccessFlag

			DOHTarget.TLSVer = *result.TLSVersion
			DOHTarget.HTTPVer = *result.HTTPVersion

			queryTime := float64(*result.QueryTime) / 1e6
			handshakeTime := float64(*result.TLSHandshakeDuration+*result.TCPHandshakeDuration) / 1e6
			totalTime := float64(*result.TotalTime) / 1e6

			DOHTarget.QueryTime = queryTime
			DOHTarget.TotalTime = totalTime
			DOHTarget.HandshakeTime = handshakeTime

			resultjson, errjson := json.Marshal(DOHTarget)
			if errjson != nil {
				return ip, "json error"
			}
			resultstr = resultstr + "###" + string(resultjson)
		}

		return resultstr, "success"
	}

}
