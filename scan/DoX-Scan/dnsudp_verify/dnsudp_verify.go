package dnsudp_verify

import (
	"DoX-Scan/clients"
	"encoding/json"
	"github.com/miekg/dns"
	"time"
)

type DNSUDPResult struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	SuccessFlag bool   `json:"success_flag"`
}

type DNSUDPPer struct {
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

	queryadderss := "udp" + "://" + ip + ":" + queryport

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
		DNSUDPTarget := new(DNSUDPResult)
		DNSUDPTarget.Ip = ip
		DNSUDPTarget.Port = queryport

		result := reply.GetMetrics()
		if result.SuccessFlag == nil {
			return ip, "scan error"
		}
		DNSUDPTarget.SuccessFlag = *result.SuccessFlag

		resultjson, errjson := json.Marshal(DNSUDPTarget)
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

			DNSUDPTarget := new(DNSUDPPer)
			DNSUDPTarget.Ip = ip
			DNSUDPTarget.Port = queryport

			result := reply.GetMetrics()
			if result.SuccessFlag == nil {
				return ip, "scan error"
			}
			DNSUDPTarget.SuccessFlag = *result.SuccessFlag

			DNSUDPTarget.QueryTime = float64(*result.QueryTime) / 1e6
			DNSUDPTarget.HandshakeTime = float64(*result.UDPSocketSetupDuration) / 1e6
			DNSUDPTarget.TotalTime = float64(*result.TotalTime) / 1e6

			resultjson, errjson := json.Marshal(DNSUDPTarget)
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
