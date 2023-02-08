package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/certifi/gocertifi"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	_ "github.com/tumi8/tls"
	sct "github.com/zzylydx/Zsct"
	zocsp "github.com/zzylydx/zcrypto/x509/revocation/ocsp"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var scsvCiphers = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // for TLS < 1.2
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // for TLS < 1.2
	tls.TLS_FALLBACK_SCSV,                    // SCSV 密码套件
}

type DOQResult struct {
	// server info
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	TlsVersion  string `json:"tlsVersion"`
	SuccessFlag bool   `json:"available"`
	ConnError   string `json:"connError"`

	// certificate
	RawCertChain string  `json:"raw_cert_chain"` // 原始证书链
	CertLevel    string  `json:"cert_level"`     // DV,OV,EV
	CertValid    bool    `json:"certValid"`
	CAName       string  `json:"caName"`
	TimeValid    bool    `json:"time_valid"`    // 证书是否在有效期
	CertLifetime float64 `json:"cert_lifetime"` // 证书生命周期
	CertError    string  `json:"cert_error"`

	// CT
	// TLS传递方式
	CTTls       bool   `json:"ct_tls"`
	SCTTlsValid string `json:"sct_tls_valid"` // 保存每一个sct验证结果
	SCTTlsLog   string `json:"sct_tls_log"`   // 保存每一个sct的log
	// Cert传递方式
	CTCert       bool   `json:"ct_cert"`
	SCTCertValid string `json:"sct_cert_valid"`
	SCTCertLog   string `json:"sct_cert_log"`
	// OCSP传递方式
	CTOcsp       bool   `json:"ct_ocsp"`
	SCTOCSPValid string `json:"sct_ocsp_valid"`
	SCTOCSPLog   string `json:"sct_ocsp_log"`

	CTValid bool `json:"ct_valid"` // 只要有一个sct验证成功，即为true

	// cert revoke
	// 传递方式
	CRL            bool     `json:"crLs"`
	CRLServer      []string `json:"crl_server"`
	OCSP           bool     `json:"ocsp"`
	OCSPServer     []string `json:"ocspServer"`
	OCSPStapling   bool     `json:"ocspStapling"`
	OCSPMustStaple bool     `json:"ocspMustStaple"`
	RespectMS      bool     `json:"respect_ms"` // 在证书中包含OCSP Must-Staple时，如果TLS中有OCSP响应则为true
	// 撤销响应，依次使用OCSPStapling, OCSP, CRL进行请求
	ResponseFlag            bool   `json:"response_flag"`    // 收到撤销响应，则为true
	CrlCertStatus           string `json:"crl_cert_status"`  // 证书状态
	CrlResponseSig          bool   `json:"crl_response_sig"` // 响应签名
	OCSPCertStatus          string `json:"ocsp_cert_status"`
	OCSPResponseSig         bool   `json:"ocsp_response_sig"`
	OCSPStaplingCertStatus  string `json:"ocsp_stapling_cert_status"`
	OCSPStaplingResponseSig bool   `json:"ocsp_stapling_response_sig"`
}

var TLSVerDict = map[uint16]string{
	tls.VersionTLS10: "tls1_0",
	tls.VersionTLS11: "tls1_1",
	tls.VersionTLS12: "tls1_2",
	tls.VersionTLS13: "tls1_3",
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

// 检查OCSP响应
func checkOCSP(res *ocsp.Response, leafcert *x509.Certificate) (string, bool) {
	var status string
	var sigflag bool
	switch res.Status {
	case ocsp.Good:
		status = "Good"
	case ocsp.Revoked:
		status = "Revoked"
	case ocsp.ServerFailed:
		status = "ServerFailed"
	case ocsp.Unknown:
		status = "Unknown"
	default:
		status = "Error"
	}
	if res != nil && leafcert != nil {
		if err := res.CheckSignatureFrom(leafcert); err == nil {
			sigflag = true
		} else {
			sigflag = false
		}
	}

	return status, sigflag
}

// 获取url的证书，用于生成OCSP请求
func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return parseCert(in)
}

// 将byte数组解析为证书
func parseCert(in []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		in = p.Bytes
	}

	return x509.ParseCertificate(in)
}

// 验证域名的证书链，参考 https://golang.org/src/crypto/x509/verify.go 以及 https://gist.github.com/devtdeng/4f6adcb5a306f2ae035a2e7d9f724d17
func CheckCertsChain(Certchain []*x509.Certificate) (bool, string) {
	// get Mozilla Root CA Certificates
	roots, _ := gocertifi.CACerts()
	// certNumber
	certNum := len(Certchain)
	// 分情况
	if certNum == 0 {
		return false, "certNum is 0"
	}
	if certNum == 1 {
		// leafcert
		leafCert := Certchain[0]
		// config
		opts := x509.VerifyOptions{
			//DNSName: domain,
			Roots: roots,
		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false, err.Error()
		}
	} else {
		// leafcert
		leafCert := Certchain[0]
		// inter certs
		inter := x509.NewCertPool()
		for _, cert := range Certchain[1:] {
			inter.AddCert(cert)
		}
		// config
		opts := x509.VerifyOptions{
			//DNSName: domain,
			Roots:         roots,
			Intermediates: inter,
		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false, err.Error()
		}
	}

	return true, ""
}

const (
	DoQProtocolError = 0x2 // The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
)

var defaultDoQVersions = []string{"doq", "doq-i00", "doq-i02", "dq", "doq-i11", "h3"}

var DefaultQUICVersions = []quic.VersionNumber{
	quic.Version1,
	quic.VersionDraft29,
}

// Scan 主函数, 对TLS/HTTPS安全进行测量
func Scan(scantarget *DOQResult, scanf *os.File) (bool, string) {

	server := scantarget.Ip + ":" + scantarget.Port
	tlsConfig := &tls.Config{
		ServerName:         scantarget.Ip,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         defaultDoQVersions,
	}

	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = []dns.Question{
		{Name: "example.com" + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	session, err := quic.DialAddrContext(dialCtx, server, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		Versions:             DefaultQUICVersions,
		//TokenStore:tokenStore,
	})

	if err != nil {
		fmt.Println(scantarget.Ip + err.Error())
		return false, err.Error()
	}
	fmt.Println(scantarget.Ip + "quic success")

	// Clients and servers MUST NOT send the edns-tcp-keepalive EDNS(0) Option [RFC7828] in any messages sent
	// on a DoQ connection (because it is specific to the use of TCP/TLS as a transport).
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-12#section-6.4
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(DoQProtocolError, "") // Already closing the connection, so we don't care about the error
				return false, err.Error()
			}
		}
	}

	openStreamCtx, openStreamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer openStreamCancel()
	stream, err := session.OpenStreamSync(openStreamCtx)
	if err != nil {
		return false, err.Error()
	}

	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to zero.  The stream mapping for DoQ allows for unambiguous
	// correlation of queries and responses and so the Message ID field is
	// not required.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-12#section-5.2.1
	msg.Id = 0
	buf, err := msg.Pack()
	if err != nil {
		return false, err.Error()
	}

	_, err = stream.Write(buf)
	if err != nil {
		return false, err.Error()
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-12#section-5.2
	_ = stream.Close()

	respBuf, err := io.ReadAll(stream)
	if err != nil {
		return false, err.Error()
	}
	//if len(respBuf) == 0 {
	//	return nil, fmt.Errorf("empty response from %s", server)
	//}

	reply := dns.Msg{}
	err = reply.Unpack(respBuf)
	if err != nil {
		return false, err.Error()
	}
	if len(reply.Answer) != 0 {
		scantarget.SuccessFlag = true
	}

	resp := session.ConnectionState()
	scantarget.TlsVersion = TLSVerDict[resp.TLS.Version]

	// 分析证书
	// 获取证书链
	certchain := ""
	for _, cert := range resp.TLS.PeerCertificates {
		var block = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		aa := pem.EncodeToMemory(block)
		enc := base64.StdEncoding.EncodeToString(aa)
		certchain = certchain + "###" + enc // 分隔符 ","
	}
	scantarget.RawCertChain = strings.TrimLeft(certchain, "###")

	// 获取证书等级
	chain, err := sct.BuildCertificateChain(resp.TLS.PeerCertificates)
	if err != nil {
		return false, err.Error()
	}
	if len(chain) != 0 {
		scantarget.CertLevel = sct.ValidationLevel(chain[0])
	}

	leafcert := resp.TLS.PeerCertificates[0]

	// 检查证书有效性
	scantarget.CertValid, scantarget.CertError = CheckCertsChain(resp.TLS.PeerCertificates)
	// CA
	if len(leafcert.Issuer.Organization) > 0 {
		scantarget.CAName = leafcert.Issuer.Organization[0]
	}

	// 生命周期，输出天数，float类型
	scantarget.CertLifetime = leafcert.NotAfter.Sub(leafcert.NotBefore).Hours() / 24
	// 证书时间有效性
	now := time.Now()
	scantarget.TimeValid = true
	if now.Before(leafcert.NotBefore) {
		scantarget.TimeValid = false
	} else if now.After(leafcert.NotAfter) {
		scantarget.TimeValid = false
	}

	// 分析CT
	var flagValid string //暂时保存每个sct验证结果

	// sct TLS
	checker := sct.GetDefaultChecker()
	sctTLS := resp.TLS.SignedCertificateTimestamps
	if len(sctTLS) != 0 {
		var checkTLSFlag string   // verify results
		var logDescription string // log Description

		for _, sctTLS := range sctTLS {
			ld, checkTLS := checker.VerifyTLSSCTs(sctTLS, chain)
			checkTLSFlag = checkTLSFlag + strconv.FormatBool(checkTLS) + "#||#"
			logDescription = logDescription + ld + "#||#"
		}

		scantarget.SCTTlsValid = strings.TrimRight(checkTLSFlag, "#||#")
		scantarget.SCTTlsLog = strings.TrimRight(logDescription, "#||#")
		scantarget.CTTls = true
		flagValid = flagValid + checkTLSFlag // 将所有sct的验证结果串起来，后面判断如果包含true，那么该域名的sct是有效的
	} else {
		scantarget.CTTls = false
	}

	// sct cert
	if len(chain[0].SCTList.SCTList) != 0 {
		var checkCertFlag string
		var logDescription string

		for _, sctCert := range chain[0].SCTList.SCTList {
			ld, checkCert := checker.VerifyCertSCTs(&sctCert, chain)
			checkCertFlag = checkCertFlag + strconv.FormatBool(checkCert) + "#||#"
			logDescription = logDescription + ld + "#||#"
		}

		scantarget.SCTCertValid = strings.TrimRight(checkCertFlag, "#||#")
		scantarget.SCTCertLog = strings.TrimRight(logDescription, "#||#")
		flagValid = flagValid + checkCertFlag
		scantarget.CTCert = true
	} else {
		scantarget.CTCert = false
	}

	// sct ocsp
	if len(resp.TLS.OCSPResponse) != 0 {
		// 获取在包含在TLS握手中的OCSP响应中的sct
		ocspEncode := base64.StdEncoding.EncodeToString(resp.TLS.OCSPResponse)
		ocspResponse, err := zocsp.ConvertResponse(ocspEncode)
		if err != nil {
			scantarget.CTOcsp = false
		} else {
			var sctsOcsp [][]byte
			sctsOcsp, err = zocsp.ParseSCTListFromOcspResponseByte(ocspResponse)
			if err != nil {
				scantarget.CTOcsp = false
			} else {
				if sctsOcsp != nil {
					var checkOcspFlag string
					var sctsOcspData string
					var logDescription string

					for _, sctOcsp := range sctsOcsp {
						ld, checkOcsp := checker.VerifyOcspSCTs(sctOcsp, chain)
						enc := base64.StdEncoding.EncodeToString(sctOcsp)
						checkOcspFlag = checkOcspFlag + strconv.FormatBool(checkOcsp) + "#||#"
						sctsOcspData = sctsOcspData + enc + "#||#"
						logDescription = logDescription + ld + "#||#"
					}

					scantarget.SCTOCSPValid = strings.TrimRight(checkOcspFlag, "#||#")
					scantarget.SCTOCSPLog = strings.TrimRight(logDescription, "#||#")
					flagValid = flagValid + checkOcspFlag
					scantarget.CTOcsp = true
				} else {
					scantarget.CTOcsp = false
				}

			}
		}

	}

	// 检查是否有一个sct有效
	if strings.Contains(flagValid, "true") {
		scantarget.CTValid = true
	} else {
		scantarget.CTValid = false
	}

	// 证书撤销

	// 撤销方式
	// CRL
	if len(leafcert.CRLDistributionPoints) > 0 {
		scantarget.CRL = true
		scantarget.CRLServer = leafcert.CRLDistributionPoints
	} else {
		scantarget.CRL = false
	}

	// OCSP
	if len(leafcert.IssuingCertificateURL) > 0 {
		scantarget.OCSPServer = resp.TLS.PeerCertificates[0].OCSPServer
		scantarget.OCSP = true
	} else {
		scantarget.OCSP = false
	}

	// OCSP Stapling
	if len(resp.TLS.OCSPResponse) > 0 {
		scantarget.OCSPStapling = true
	} else {
		scantarget.OCSPStapling = false
	}

	// OCSP must-staple
	// Must-Staple is 1.3.6.1.5.5.7.1.24
	var ocspMustStapleExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	for _, ext := range resp.TLS.PeerCertificates[0].Extensions {
		if ext.Id.Equal(ocspMustStapleExtOid) {
			scantarget.OCSPMustStaple = true
			if scantarget.OCSPStapling == true {
				scantarget.RespectMS = true
			}
			break
		}
	}

	// 撤销响应，检测顺序为OCSPStapling->OCSP->CRL
	var issuercert *x509.Certificate
	// 获取CA提供的URL的证书
	for _, issuingCert := range leafcert.IssuingCertificateURL {
		issuercert, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	// OCSPStapling
	if scantarget.OCSPStapling == true {
		ocspStaplingRes, err := ocsp.ParseResponse(resp.TLS.OCSPResponse, issuercert)
		if err != nil {
			scantarget.ResponseFlag = false
		} else {
			status, sigflag := checkOCSP(ocspStaplingRes, issuercert)
			scantarget.ResponseFlag = true
			scantarget.OCSPStaplingCertStatus = status
			scantarget.OCSPStaplingResponseSig = sigflag
		}
	}

	// OCSP
	if scantarget.OCSP == true {
		ocspURLs := leafcert.OCSPServer
		// 构建OCSP响应
		opts := ocsp.RequestOptions{
			Hash: crypto.SHA1,
		}
		if issuercert != nil {
			ocspRequest, err := ocsp.CreateRequest(leafcert, issuercert, &opts)
			if err != nil {
				scantarget.OCSPCertStatus = "Error"
			} else {
				// 向每一个OCSPServer发出请求
				for _, server := range ocspURLs {
					var resp *http.Response
					// 请求字节数大于256，使用POST
					if len(ocspRequest) > 256 {
						buf := bytes.NewBuffer(ocspRequest)
						resp, err = http.Post(server, "application/ocsp-request", buf)
					} else {
						reqURL := server + "/" + base64.StdEncoding.EncodeToString(ocspRequest)
						resp, err = http.Get(reqURL)
					}

					if err != nil || resp.StatusCode != http.StatusOK {
						scantarget.OCSPCertStatus = "Error"
						continue
					}
					// 读取OCSP响应
					body, err := ioutil.ReadAll(resp.Body)

					resp.Body.Close()
					var ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
					var ocspMalformed = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
					if err != nil || bytes.Equal(body, ocspUnauthorised) || bytes.Equal(body, ocspMalformed) {
						scantarget.OCSPCertStatus = "Error"
						continue
					}
					// 解析OCSP响应
					ocspResponse, err := ocsp.ParseResponse(body, issuercert)
					if err != nil {
						scantarget.OCSPCertStatus = "Error"
						continue
					}

					status, sigflag := checkOCSP(ocspResponse, issuercert)
					scantarget.ResponseFlag = true
					scantarget.OCSPCertStatus = status
					scantarget.OCSPResponseSig = sigflag
				}

			}

		} else {
			scantarget.OCSPCertStatus = "Error"
		}
	}
	// CRL
	if scantarget.CRL == true {
		CRLServer := leafcert.CRLDistributionPoints
		var crlresp *http.Response
		for _, crlurl := range CRLServer {
			// 发出crl请求
			crlresp, err = http.Get(crlurl)
			if err != nil {
				scantarget.CrlCertStatus = "Error"
				continue
			}
			// 读取CRL响应
			body, err := ioutil.ReadAll(crlresp.Body)
			if err != nil {
				scantarget.CrlCertStatus = "Error"
				continue
			}
			crlresp.Body.Close()
			// 解析CRL响应
			crlresponce, err := x509.ParseDERCRL(body)
			if err != nil {
				scantarget.CrlCertStatus = "Error"
				continue
			}
			scantarget.ResponseFlag = true

			rawsernum := leafcert.SerialNumber
			crlrevokeflag := false
			// 检测证书是否包含在CRL列表
			for _, signalcrl := range crlresponce.TBSCertList.RevokedCertificates {
				if signalcrl.SerialNumber == rawsernum {
					crlrevokeflag = true
					break
				}
			}

			if crlrevokeflag == true {
				scantarget.CrlCertStatus = "Revoked"
			} else {
				scantarget.CrlCertStatus = "Good"
			}

			// 检查CRL响应签名
			if issuercert != nil {
				if errcrl := issuercert.CheckCRLSignature(crlresponce); errcrl == nil {
					scantarget.CrlResponseSig = true
				} else {
					scantarget.CrlResponseSig = false
				}
			}

		}
	}

	scanresult, errjson := json.Marshal(scantarget)
	if errjson != nil {
		return false, errjson.Error()
	}

	scanf.Write(scanresult)
	scanf.WriteString("\n")

	return true, ""
}

// 读取通道，准备扫描
func start(jobs <-chan string, ScanFile string, queryPort string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()

	// 创建输出文件
	scanf, err_ := os.Create(ScanFile)
	if err_ != nil {
		println(err_.Error())
	}

	// 读取通道
	for line := range jobs {
		limiter.Wait(ctx)
		// 创建结构体
		scantarget := new(DOQResult)

		scantarget.Ip = line
		scantarget.Port = queryPort

		// 开始扫描
		success, err := Scan(scantarget, scanf)
		// 扫描失败
		if !success {
			err = strings.Replace(err, "\n", " ", -1)
			scantarget.ConnError = err

			tlserr, errJson := json.Marshal(scantarget)
			if errJson != nil {
				fmt.Println("Out-errJson:", errJson, scantarget.Ip)
				continue
			}
			scanf.Write(tlserr)
			scanf.WriteString("\n")
		}

	}
	// 关闭输出文件
	scanf.Close()
}

func main() {
	var numThreads = flag.Int("n", 100, "Number of threads")
	var inputFile = flag.String("i", "./input.txt", "Input File")
	var resultDir = flag.String("o", "./result/", "Output File")
	var queryPort = flag.String("p", "853", "Query Port")

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()

	QPS := *numThreads // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()
	// 创建进程
	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)
			// 四个输出文件
			ScanFile := *resultDir + "Doq-" + strconv.Itoa(i) + ".txt"
			// 开始扫描
			start(jobs, ScanFile, *queryPort, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}
	// 读取输入文件
	inputf, err := os.Open(*inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)
	// 将输入写入通道
	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	mergeErr := FileMerge(*resultDir+"Doq-*", *resultDir+"result_doq.txt")
	if mergeErr != "success" {
		fmt.Println("scan file merge err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())
}
