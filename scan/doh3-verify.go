package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

const(
	QueryDomain = "example.com"
	DohJsonType = "application/dns-json"
	DohDnsType = "application/dns-message"
	GetQuery = "?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	JsonQuery = "?name=example.com&type=A"
)

type DoH3Result struct {
	Ip		string	`json:"ip"`
	Suffix	string	`json:"suffix"`
	ResFlag	bool	`json:"res_flag"`
	GetH3	bool	`json:"get_h3"`
	PostH3	bool	`json:"post_h3"`
}


func FileMerge(originalFile string, finalFile string) string{
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")
	cmd.Stdin = in
	in.WriteString("for i in " + originalFile + ";do cat $i >> " + finalFile + ";done\n")
	in.WriteString("sleep 5s\n")
	in.WriteString("rm " + originalFile + "\n")
	in.WriteString("exit\n")
	if err := cmd.Run();
		err != nil {
		return "err"
	} else {
		return "success"
	}
}


func getDns(target *DoH3Result) {
	host := target.Ip
	suffix := target.Suffix
	//target.Suffix = suffix
	url := "https://" + host + "/" + suffix + GetQuery

	h3Client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion: 0,
			},
		},

	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	//fmt.Println(req.TLS.ServerName)
	req.Header["User-Agent"] = []string{"http3.client.dilfish.dev"}

	resp, err := h3Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK{
		bt, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		reply := &dns.Msg{}
		err = reply.Unpack(bt)
		if err != nil {
			return
		}
		if len(reply.Answer) != 0{
			target.GetH3 = true
		}

	}

}

func postDns(target *DoH3Result) {
	host := target.Ip
	suffix := target.Suffix
	//target.Suffix = suffix
	url := "https://" + host + "/" + suffix

	m := new(dns.Msg)
	fqdn := dns.Fqdn(QueryDomain)
	m.SetQuestion(fqdn, dns.TypeA)

	data, err := m.Pack()
	if err != nil {
		fmt.Println(err)
	}
	PostBody := bytes.NewReader(data)

	h3Client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion: 0,
			},
		},

	}

	req, err := http.NewRequest(http.MethodPost, url, PostBody)
	if err != nil {
		return
	}
	req.Header["User-Agent"] = []string{"http3.client.dilfish.dev"}

	resp, err := h3Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK{
		bt, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		reply := &dns.Msg{}
		err = reply.Unpack(bt)
		if err != nil {
			return
		}
		if len(reply.Answer) != 0{
			target.PostH3 = true
		}
	}

}

func DoH3Scan(target *DoH3Result, scanF *os.File, port string){
	getDns(target)
	postDns(target)


	if target.GetH3 || target.PostH3 {
		target.ResFlag = true
		scanF.WriteString(target.Ip + "," + target.Suffix + "," +  strconv.FormatBool(target.ResFlag) + "," + strconv.FormatBool(target.GetH3) + "," +  strconv.FormatBool(target.PostH3) + "\n")
	}

}


// 读取通道，准备扫描
func start(jobs <-chan string, queryPort string, ScanFile string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()

	scanF, err_ := os.Create(ScanFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}
	

	var suffixList = [...]string{"dns-query","query","resolve",""}

	for line := range jobs {

		limiter.Wait(ctx)
		for _, suffix := range suffixList {
			target := new(DoH3Result)
			target.Ip = line
			target.Suffix = suffix
			DoH3Scan(target, scanF, queryPort)

		}

	}


	// 关闭输出文件
	scanF.Close()
}


func main() {
	var numThreads = flag.Int("n",100,"Number of threads")
	var inputFile = flag.String("i","./input.txt","Input File")
	var resultDir =  flag.String("o","./result/","Output File")
	var queryPort = flag.String("p","443","Query Port")


	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()

	QPS := 100                               // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()
	// 创建进程
	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)
			// 四个输出文件
			scanFile := *resultDir + "Doh3-" + strconv.Itoa(i) + ".txt"
			//successFile := *resultDir + "success-" + strconv.Itoa(i) + ".txt"
			//failFile := *resultDir + "fail-" + strconv.Itoa(i) + ".txt"
			// 开始扫描
			start(jobs, *queryPort, scanFile, wgScoped, limiterScoped, ctxScoped)
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

	mergeErr := FileMerge(*resultDir + "Doh3-*",*resultDir + "result_doh3_verify.txt")
	if mergeErr != "success"{
		fmt.Println("scan file merge err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())
}


