package checkcert

import (
	_ "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/certifi/gocertifi"
	sct "github.com/zzylydx/Zsct"
)

// 将byte数组解析为证书
func ParseCert(in []byte) (*x509.Certificate, error) {
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
func CheckCertsChain(Certchain []*x509.Certificate) (bool,string) {
	// get Mozilla Root CA Certificates
	roots, _ := gocertifi.CACerts()
	// certNumber
	certNum := len(Certchain)
	// 分情况
	if certNum == 0 {
		return false,"certNum is 0"
	}
	if certNum == 1{
		// leafcert
		leafCert := Certchain[0]
		// config
		opts := x509.VerifyOptions{
			//DNSName: domain,
			Roots:   roots,
		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false,err.Error()
		}
	}else{
		// leafcert
		leafCert := Certchain[0]
		// inter certs
		inter := x509.NewCertPool()
		for _, cert := range Certchain[1:]{
			inter.AddCert(cert)
		}
		// config
		opts := x509.VerifyOptions{
			//DNSName: domain,
			Roots:   roots,
			Intermediates: inter,

		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false,err.Error()
		}
	}

	return true,""
}


func GetCertLevel(PeerCert []*x509.Certificate) string{
	chain, err := sct.BuildCertificateChain(PeerCert)
	if err != nil {
		return "error"
	}
	if len(chain) != 0{
		return sct.ValidationLevel(chain[0])
	}
	return "error"
}