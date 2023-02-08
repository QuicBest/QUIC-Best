package metrics

import (
	"bytes"
	"os/exec"
	"time"
)

type Result struct {
	collector *Collector

	UDPSocketSetupDuration *time.Duration `json:"udp_socket_setup_duration,omitempty"`

	TCPHandshakeDuration *time.Duration `json:"tcp_handshake_duration,omitempty"`

	TLSHandshakeDuration *time.Duration `json:"tls_handshake_duration,omitempty"`
	TLSVersion           *string        `json:"tls_version,omitempty"`
	TLSError             *int           `json:"tls_error,omitempty"`

	QUICHandshakeDuration  *time.Duration           `json:"quic_handshake_duration,omitempty"`
	QUICVersion            *string                  `json:"quic_version,omitempty"`
	QUICNegotiatedProtocol *string                  `json:"quic_negotiated_protocol,omitempty"`
	QUICUsed0RTT           *bool                    `json:"quic_used0RTT"`
	QUICError              *uint64                  `json:"quic_error,omitempty"`
	QLogMessages           []map[string]interface{} `json:"qlog_messages,omitempty"`

	HTTPVersion *string `json:"http_version,omitempty"`

	QueryTime *time.Duration `json:"query_time,omitempty"`

	TotalTime *time.Duration `json:"total_time,omitempty"`

	SuccessFlag   *bool    `json:"success_flag"`
	CertChain     *string  `json:"cert_chain"`
	CertValid     *bool    `json:"cert_valid"`
	CertTimeValid *bool    `json:"cert_time_valid"`
	CertLifetime  *float64 `json:"cert_lifetime"`
	CertLevel     *string  `json:"cert_level"`
	CAName        *string  `json:"ca_name"`
	CertError     *string  `json:"cert_error"`
}

func fromCollector(collector *Collector) *Result {
	result := &Result{
		collector: collector,
	}

	result.transformUDP()
	result.transformTCP()
	result.transformTLS()
	result.transformQUIC()
	result.transformCommon()
	result.transformHTTPS()

	return result
}

func toPointer(duration time.Duration) *time.Duration {
	return &duration
}

func (r *Result) transformUDP() {
	if !r.collector.udpSocketSetupDoneTime.IsZero() {
		r.UDPSocketSetupDuration = toPointer(r.collector.udpSocketSetupDoneTime.Sub(r.collector.udpSocketSetupStartTime))
	}
}

func (r *Result) transformTCP() {
	if !r.collector.tcpHandshakeDoneTime.IsZero() {
		r.TCPHandshakeDuration = toPointer(r.collector.tcpHandshakeDoneTime.Sub(r.collector.tcpHandshakeStartTime))
	}
}

func (r *Result) transformTLS() {
	if !r.collector.tlsHandshakeDoneTime.IsZero() {
		r.TLSHandshakeDuration = toPointer(r.collector.tlsHandshakeDoneTime.Sub(r.collector.tlsHandshakeStartTime))
	}
	r.TLSVersion = r.collector.tlsVersion
	r.TLSError = (*int)(r.collector.tlsError)
	r.SuccessFlag = r.collector.successFlag
	r.CertChain = r.collector.certChain
	r.CertValid = r.collector.certValid
	r.CertTimeValid = r.collector.certTimeValid
	r.CertLifetime = r.collector.certLifetime
	r.CertLevel = r.collector.certLevel
	r.CAName = r.collector.cAName
	r.CertError = r.collector.certError
}

func (r *Result) transformQUIC() {
	if !r.collector.quicHandshakeDoneTime.IsZero() {
		r.QUICHandshakeDuration = toPointer(r.collector.quicHandshakeDoneTime.Sub(r.collector.quicHandshakeStartTime))
	}
	r.QUICVersion = r.collector.quicVersion
	r.QUICError = (*uint64)(r.collector.quicError)
	r.QUICNegotiatedProtocol = r.collector.quicNegotiatedProtocol
	r.QUICUsed0RTT = r.collector.quicUsed0RTT

	if len(r.collector.qLogMessages) != 0 {
		for _, message := range r.collector.qLogMessages {
			r.QLogMessages = append(r.QLogMessages, message)
		}
	}
}

func (r *Result) transformCommon() {
	if !r.collector.endTime.IsZero() {
		r.TotalTime = toPointer(r.collector.endTime.Sub(r.collector.startTime))
	}
	if !r.collector.queryReceiveTime.IsZero() {
		r.QueryTime = toPointer(r.collector.queryReceiveTime.Sub(r.collector.querySendTime))
	}
}

func (r *Result) transformHTTPS() {
	if !r.collector.tlsHandshakeDoneTime.IsZero() {
		r.TLSHandshakeDuration = toPointer(r.collector.tlsHandshakeDoneTime.Sub(r.collector.tlsHandshakeStartTime))
	}
	r.HTTPVersion = r.collector.httpVersion
}

func FileMerge(originalFile string, finalFile string) string {
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")
	cmd.Stdin = in
	in.WriteString("for i in " + originalFile + ";do cat $i >> " + finalFile + ";done\n")
	in.WriteString("sleep 5s\n")
	in.WriteString("rm " + originalFile + "\n")
	in.WriteString("exit\n")
	if err := cmd.Run(); err != nil {
		return "err"
	} else {
		return "success"
	}
}
