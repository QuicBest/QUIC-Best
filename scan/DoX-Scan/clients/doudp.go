package clients

import (
	"DoX-Scan/metrics"
	"context"
	"github.com/miekg/dns"
	"time"
)

type DoUDPClient struct {
	baseClient *baseClient
}

func (c *DoUDPClient) Exchange(m *dns.Msg, scanType string) *metrics.WithResponseOrError {
	collector := metrics.NewCollector()
	dialContext := c.baseClient.getDialContext(collector)

	collector.ExchangeStarted()

	rawCon, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return collector.WithError(err)
	}

	cn := dns.Conn{Conn: rawCon}
	_ = cn.SetDeadline(time.Now().Add(c.baseClient.options.Timeout))

	collector.QuerySend()
	err = cn.WriteMsg(m)
	if err != nil {
		return collector.WithError(err)
	}
	r, err := cn.ReadMsg()
	collector.QueryReceive()
	if err != nil {
		return collector.WithError(err)
	}
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return collector.WithResponseAndError(r, err)
	}

	collector.ExchangeFinished()

	if len(r.Answer) != 0 {
		collector.SuccessFlag(true)
	} else {
		collector.SuccessFlag(false)
	}

	return collector.WithResponse(r)
}
