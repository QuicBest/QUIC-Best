package dnstcp_verify

import (
	"DoX-Scan/clients"
	"encoding/json"
	"github.com/miekg/dns"
	"time"
)

type DNSTCPResult struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	SuccessFlag bool   `json:"success_flag"`
}

type DNSTCPPer struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	SuccessFlag bool   `json:"success_flag"`

	QueryTime     float64 `json:"query_time"`
	TotalTime     float64 `json:"total_time"`
	HandshakeTime float64 `json:"handshake_time"`
}

func Verify(ip string, queryport string, scanType string) (string, string) {
	timeout := 10

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
	}

	queryadderss := "tcp" + "://" + ip + ":" + queryport

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
		DNSTCPTarget := new(DNSTCPResult)
		DNSTCPTarget.Ip = ip
		DNSTCPTarget.Port = queryport

		result := reply.GetMetrics()
		if result.SuccessFlag == nil {
			return ip, "scan error"
		}
		DNSTCPTarget.SuccessFlag = *result.SuccessFlag

		resultjson, errjson := json.Marshal(DNSTCPTarget)
		if errjson != nil {
			return ip, "json error"
		}
		return string(resultjson), "success"
	} else {
		resultstr := ""

		for i := 1; i <= 3; i++ {
			reply := u.Exchange(&req, scanType)
			if reply.GetError() != nil {
				return ip, "Cannot make the DNS request"
			}

			DNSTCPTarget := new(DNSTCPPer)
			DNSTCPTarget.Ip = ip
			DNSTCPTarget.Port = queryport

			result := reply.GetMetrics()
			if result.SuccessFlag == nil {
				return ip, "scan error"
			}

			DNSTCPTarget.SuccessFlag = *result.SuccessFlag

			DNSTCPTarget.QueryTime = float64(*result.QueryTime) / 1e6
			DNSTCPTarget.TotalTime = float64(*result.TotalTime) / 1e6
			DNSTCPTarget.HandshakeTime = float64(*result.TCPHandshakeDuration) / 1e6

			resultjson, errjson := json.Marshal(DNSTCPTarget)
			if errjson != nil {
				return ip, "json error"
			}
			resultstr = resultstr + "###" + string(resultjson)

			req.Id = dns.Id()
			time.Sleep(time.Second * 1)
		}
		return resultstr, "unknown err"

	}

}
