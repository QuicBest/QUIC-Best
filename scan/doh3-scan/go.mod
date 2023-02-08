module doh3-scan

replace github.com/Sirupsen/logrus v1.8.1 => github.com/sirupsen/logrus v1.8.1

replace github.com/lucas-clemente/quic-go => ./replacement_modules/quic-go


go 1.16

require (
	github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d
	github.com/lucas-clemente/quic-go v0.27.2
	github.com/miekg/dns v1.1.49
	github.com/zzylydx/Zgoscanner v0.0.0-20210703051523-6f279f18f6bc
	github.com/zzylydx/Zsct v0.1.7
	github.com/zzylydx/zcrypto v0.1.18
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	golang.org/x/net v0.0.0-20220614195744-fb05da6f9022
	golang.org/x/time v0.0.0-20220609170525-579cf78fd858
)
