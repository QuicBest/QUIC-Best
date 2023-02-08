package clients

import (
	"DoX-Scan/metrics"
	"bytes"
	"context"
	"encoding/base64"
	_ "fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// WrappedTransport wraps the default http.Transport so that we can set the query finish time
type WrappedTransport struct {
	collector *metrics.Collector
	transport *http.Transport
}

func (w *WrappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := w.transport.RoundTrip(r)
	w.collector.QueryReceive()
	return response, err
}

// DoHMaxConnsPerHost controls the maximum number of connections per host.
const DoHMaxConnsPerHost = 1

type DoHClient struct {
	baseClient *baseClient
}

func (c *DoHClient) exchangeHTTPSClient(m *dns.Msg, client *http.Client, collector *metrics.Collector) (*dns.Msg, error) {
	buf, err := m.Pack()
	//url := strings.Split(c.baseClient.URL.String(), ":443")[0]
	//requestURL := url + "/dns-query" + "?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	url := strings.Replace(c.baseClient.URL.String(), ":443", "", -1)

	//	fmt.Println(url)
	requestURL := url + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	//	fmt.Println(requestURL)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Proto = "HTTP/2.0"

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	collector.HTTPVersion(resp.Proto)
	//if resp.StatusCode != http.StatusOK {
	//	return nil, err
	//}

	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, err
	}

	//	collector.ExchangeFinished()

	return &response, err
}

func (c *DoHClient) PostHTTPSClient(m *dns.Msg, client *http.Client, collector *metrics.Collector) (*dns.Msg, error) {
	//url := strings.Split(c.baseClient.URL.String(), ":443")[0]
	//requestURL := url + "/dns-query"
	//mpost := new(dns.Msg)
	//fqdn := dns.Fqdn("example.com")
	//mpost.SetQuestion(fqdn, dns.TypeA)
	url := strings.Replace(c.baseClient.URL.String(), ":443", "", -1)

	data, err := m.Pack()
	if err != nil {
		return nil, err
	}
	PostBody := bytes.NewReader(data)
	req, err := http.NewRequest(http.MethodPost, url, PostBody)
	if err != nil {
		return nil, err
	}
	//req.Proto = "HTTP/2.0"
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	collector.HTTPVersion(resp.Proto)
	//if resp.StatusCode != http.StatusOK {
	//	return nil, err
	//}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, err
	}

	collector.ExchangeFinished()

	return &response, err
}

func (c *DoHClient) Exchange(m *dns.Msg, scanType string) *metrics.WithResponseOrError {
	collector := &metrics.Collector{}
	collector.ExchangeStarted()
	client := c.createClient(collector, scanType)
	collector.QuerySend()
	reply, err := c.exchangeHTTPSClient(m, client, collector)
	if err != nil {
		collector.QuerySend()
		reply, err = c.PostHTTPSClient(m, client, collector)
		if err != nil {
			return collector.WithError(err)
		}
	}
	collector.QueryReceive()
	collector.ExchangeFinished()

	if len(reply.Answer) != 0 {
		collector.SuccessFlag(true)
	} else {
		collector.SuccessFlag(false)
	}

	return collector.WithResponse(reply)
}

func (c *DoHClient) wrappedTLSDial(collector *metrics.Collector, scanType string) func(context context.Context, network string, addr string) (net.Conn, error) {
	tlsDial := c.baseClient.getTLSDialContext(collector, scanType)

	return func(context context.Context, network string, addr string) (net.Conn, error) {
		conn, err := tlsDial(context, network, addr)
		//collector.QuerySend()
		return conn, err
	}
}

func (c *DoHClient) createTransport(collector *metrics.Collector, scanType string) *WrappedTransport {
	tlsConfig := c.baseClient.resolvedConfig

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialTLSContext:     c.wrappedTLSDial(collector, scanType),
		MaxConnsPerHost:    DoHMaxConnsPerHost,
		MaxIdleConns:       1,
	}

	// It appears that this is important to explicitly configure transport to use HTTP2
	// Relevant issue: https://github.com/AdguardTeam/dnsproxy/issues/11
	http2.ConfigureTransports(transport) // nolint

	return &WrappedTransport{collector: collector, transport: transport}
}

func (c *DoHClient) createClient(collector *metrics.Collector, scanType string) *http.Client {
	transport := c.createTransport(collector, scanType)

	client := &http.Client{
		Transport: transport,
		Timeout:   c.baseClient.options.Timeout,
		Jar:       nil,
	}

	return client
}
