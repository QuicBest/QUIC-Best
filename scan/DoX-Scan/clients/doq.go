package clients

import (
	"DoX-Scan/checkcert"
	"DoX-Scan/metrics"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/mgranderath/dnsperf/qerr"
	"github.com/miekg/dns"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"
)

var QUICVerDict = map[uint64]string{
	0x1:        "ver_1",
	0xff00001d: "draft_29",
	0xff000020: "draft_32",
	0xff000022: "draft_34",
}

type DoQVersion string

// DOQ Version
var defaultDoQVersions = []string{"doq", "doq-i00", "doq-i02", "dq"}

const handshakeTimeout = time.Second * 5

type DoQClient struct {
	baseClient *baseClient
}

type qLogWriter struct {
	collector *metrics.Collector
}

func (w qLogWriter) Write(p []byte) (n int, err error) {
	if string(p[:]) == "\n" {
		return 0, nil
	}
	w.collector.QLogMessage(p)
	return len(p), nil
}

func (w qLogWriter) Close() error {
	return nil
}

func newWriterCloser(collector *metrics.Collector) io.WriteCloser {
	return &qLogWriter{collector: collector}
}

func (c *DoQClient) getConnection(collector *metrics.Collector, scanType string) (quic.Connection, error) {
	tlsConfig := c.baseClient.resolvedConfig
	dialContext := c.baseClient.getDialContext(nil)
	tokenStore := c.baseClient.options.QuicOptions.TokenStore
	quicVersions := c.baseClient.options.QuicOptions.QuicVersions
	port := c.baseClient.options.QuicOptions.LocalPort

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses)
	rawConn, err := dialContext(context.TODO(), "udp", "")
	if err != nil {
		return nil, err
	}
	// It's never actually used
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, err
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		Versions:             quicVersions,
		Tracer: qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
			return newWriterCloser(collector)
		}),
		TokenStore: tokenStore,
	}

	// Moved here because code above is misc
	collector.ExchangeStarted()

	collector.QUICHandshakeStart()
	session, err := quic.DialAddrEarlyContext(context.Background(), addr, tlsConfig, quicConfig, port)
	if err != nil {
		reflectErr := reflect.ValueOf(err)
		if reflectErr.IsValid() && reflectErr.Elem().Type().String() == "qerr.QuicError" {
			errorCode := reflectErr.Elem().FieldByName("ErrorCode").Uint()
			collector.QUICError(qerr.ErrorCode(errorCode))
		}
		return nil, err
	}
	collector.QUICHandshakeDone()
	collector.TLSVersion(TLSVerDict[session.ConnectionState().TLS.Version])
	collector.QUICNegotiatedProtocol(session.ConnectionState().TLS.NegotiatedProtocol)
	collector.QUICVersion(QUICVerDict[reflect.ValueOf(session).Elem().FieldByName("version").Uint()])

	if scanType == "verify" {
		// new
		certchain := ""
		for _, cert := range session.ConnectionState().TLS.PeerCertificates {
			var block = &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}

			aa := pem.EncodeToMemory(block)
			enc := base64.StdEncoding.EncodeToString(aa)
			certchain = certchain + "###" + enc
		}
		collector.CertChain(strings.TrimLeft(certchain, "###"))

		certvalid, certerror := checkcert.CheckCertsChain(session.ConnectionState().TLS.PeerCertificates)
		collector.CertValid(certvalid)
		collector.CertError(certerror)

		peercert := session.ConnectionState().TLS.PeerCertificates[0]
		collector.CertLevel(checkcert.GetCertLevel(session.ConnectionState().TLS.PeerCertificates))
		collector.CertLifetime(peercert.NotAfter.Sub(peercert.NotBefore).Hours() / 24)
		if len(peercert.Issuer.Organization) > 0 {
			collector.CAName(peercert.Issuer.Organization[0])
		} else {
			collector.CAName("")
		}
		//collector.CAName(peercert.Issuer.Organization[0])

		now := time.Now()
		collector.CertTimeValid(true)
		if now.Before(peercert.NotBefore) {
			collector.CertTimeValid(false)
		} else if now.After(peercert.NotAfter) {
			collector.CertTimeValid(false)
		}
	}

	return session, nil
}

func (c *DoQClient) openStream(session quic.Connection) (quic.Stream, error) {
	ctx := context.Background()

	if c.baseClient.options.Timeout > 0 {
		deadline := time.Now().Add(c.baseClient.options.Timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel() // avoid resource leak
	}

	return session.OpenStreamSync(ctx)
}

func (c *DoQClient) getBytesPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return make([]byte, dns.MaxMsgSize)
		},
	}
}

func (c *DoQClient) Exchange(m *dns.Msg, scanType string) *metrics.WithResponseOrError {
	collector := &metrics.Collector{}
	session, err := c.getConnection(collector, scanType)
	if err != nil {
		fmt.Println("session:" + err.Error())
		return collector.WithError(err)
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := m.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(0, "") // Already closing the connection so we don't care about the error
				return collector.WithError(errors.New("EDNS0 TCP keepalive option is set"))
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	id := m.Id
	var reply *dns.Msg
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if reply != nil {
			reply.Id = id
		}
	}()

	stream, err := c.openStream(session)
	if err != nil {
		return collector.WithError(err)
	}

	buf, err := m.Pack()
	if err != nil {
		collector.WithError(err)
	}

	collector.QuerySend()
	_, err = stream.Write(buf)
	if err != nil {
		collector.WithError(err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	pool := c.getBytesPool()
	respBuf := pool.Get().([]byte)

	defer pool.Put(respBuf)

	n, err := stream.Read(respBuf)
	collector.QueryReceive()
	if err != nil && n == 0 {
		collector.WithError(err)
	}

	reply = new(dns.Msg)
	err = reply.Unpack(respBuf)
	if err != nil {
		collector.WithError(err)
	}

	collector.ExchangeFinished()

	collector.QUICUsed0RTT(session.ConnectionState().TLS.Used0RTT)

	session.CloseWithError(0, "")

	if len(reply.Answer) != 0 {
		collector.SuccessFlag(true)
	} else {
		collector.SuccessFlag(false)
	}

	return collector.WithResponse(reply)
}
