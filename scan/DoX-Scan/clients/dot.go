package clients

import (
	"DoX-Scan/metrics"
	"context"
	"github.com/miekg/dns"
	"time"
)

const dialTimeout = 10 * time.Second

type DoTClient struct {
	baseClient *baseClient
}

func (c *DoTClient) Exchange(m *dns.Msg, scanType string) *metrics.WithResponseOrError {
	collector := metrics.NewCollector()
	collector.ExchangeStarted()
	rawCon, err := c.baseClient.getTLSDialContext(collector, scanType)(context.TODO(), "tcp", "")
	if err != nil {
		return collector.WithError(err)
	}
	cn := dns.Conn{Conn: rawCon}
	_ = cn.SetDeadline(time.Now().Add(c.baseClient.options.Timeout))

	collector.QuerySend()
	err = cn.WriteMsg(m)
	if err != nil {
		rawCon.Close()
		return collector.WithError(err)
	}

	reply, err := cn.ReadMsg()
	collector.QueryReceive()
	if err != nil {
		rawCon.Close()
		return collector.WithError(err)
	}

	collector.ExchangeFinished()

	if len(reply.Answer) != 0 {
		collector.SuccessFlag(true)
	} else {
		collector.SuccessFlag(false)
	}

	return collector.WithResponseAndError(reply, err)
}
