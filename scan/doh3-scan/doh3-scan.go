package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"crypto/tls"

	"flag"
	"fmt"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"net"

	//_ "github.com/tumi8/tls"

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

func GetAllFiles(dirPth string) (files []string, err error) {
	var dirs []string
	dir, err := ioutil.ReadDir(dirPth)
	if err != nil {
		return nil, err
	}

	PthSep := string(os.PathSeparator)
	//suffix = strings.ToUpper(suffix) //忽略后缀匹配的大小写

	for _, fi := range dir {
		if fi.IsDir() { // 目录, 递归遍历
			dirs = append(dirs, dirPth+PthSep+fi.Name())
			GetAllFiles(dirPth + PthSep + fi.Name())
		} else {
			// 过滤指定格式
			ok := strings.HasSuffix(fi.Name(), ".csv")
			if ok {
				files = append(files, dirPth+PthSep+fi.Name())
			}
		}
	}

	// 读取子目录下文件
	for _, table := range dirs {
		temp, _ := GetAllFiles(table)
		for _, temp1 := range temp {
			files = append(files, temp1)
		}
	}

	return files, nil
}

// 读取通道，准备扫描
func start(jobs <-chan string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()

	// 读取通道
	for line := range jobs {
		ip := line
		suffix := "dns-query"
		if len(strings.Split(line, ",")) == 2 {
			ip = strings.Split(line, ",")[0]
			suffix = strings.Split(line, ",")[1]
		}

		limiter.Wait(ctx)

		tokenStore := quic.NewLRUTokenStore(5, 50)
		clientSessionCache := tls.NewLRUClientSessionCache(100)
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			fmt.Println(err)
		}
		_, portString, _ := net.SplitHostPort(udpConn.LocalAddr().String())
		udpConn.Close()
		port, _ := strconv.Atoi(portString)

		url := "https://" + ip + "/" + suffix + "/?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
		//url := "https://203.76.245.200/?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
		//url := "https://doh3.dns.NextDNS.io/?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

		h3Client := http.Client{
			Timeout: 5 * time.Second,
			Transport: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify:     true,
					MaxVersion:             0,
					ClientSessionCache:     clientSessionCache,
					SessionTicketsDisabled: false,
				},
				QuicConfig: &quic.Config{
					TokenStore:           tokenStore,
					HandshakeIdleTimeout: 5 * time.Second,
					Port:                 port,
				},
			},
		}

		for i := 1; i <= 3; i++ {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				fmt.Println(err)
			}

			req.Header["User-Agent"] = []string{"http3.client.dilfish.dev"}

			resp, err := h3Client.Do(req)
			if err != nil {
				fmt.Println(err)
			}
			if resp != nil{
				if resp.StatusCode == http.StatusOK {
					bt, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						fmt.Println(err)
					}
					reply := &dns.Msg{}
					err = reply.Unpack(bt)
					if err != nil {
						fmt.Println(err)
					}
				//if len(reply.Answer) != 0 {
				//	fmt.Println(reply.Answer)
				//	fmt.Println("---------")
				//}
				}

			
			resp.Body.Close()
			}
			time.Sleep(2 * time.Second)

		}
	}
}

func Filerm(originalFile string) string {
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")
	cmd.Stdin = in
	//in.WriteString("for i in " + originalFile + ";do cat $i >> " + finalFile + ";done\n")
	in.WriteString("sleep 2s\n")
	in.WriteString("rm " + originalFile + "\n")
	//in.WriteString("sleep 1s\n")
	in.WriteString("exit\n")
	if err := cmd.Run(); err != nil {
		return "err"
	} else {
		return "success"
	}
}

func main() {
	var numThreads = flag.Int("n", 50, "Number of threads")
	var inputFile = flag.String("i", "./input.txt", "Input File")
	//var resultDir = flag.String("o", "./result/", "Output File")
	//var queryPort = flag.String("p","443","Query Port")

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
			//ScanFile := *resultDir + "DOH3-" + strconv.Itoa(i) + ".txt"
			// 开始扫描
			start(jobs, wgScoped, limiterScoped, ctxScoped)
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

	//mergeErr := FileMerge(*resultDir+"DOH3-*", *resultDir+"result_doh3.txt")
	//if mergeErr != "success" {
	//	fmt.Println("scan file merge err")
	//}

	file_list, _ := GetAllFiles("/root/doq_doh3/world_scan/performance/result/doh3")
	scan_f, _ := os.Create("/root/doq_doh3/world_scan/performance/result/doh3/result_scan.txt")
	reuse_f, _ := os.Create("/root/doq_doh3/world_scan/performance/result/doh3/result_reuse.txt")

	for _, file := range file_list {
		//fmt.Println(file)
		f, _ := os.OpenFile(file, os.O_RDWR|os.O_APPEND, 0666)
		reader := bufio.NewReader(f)
		i := 1
		var temp_dict http3.DOH3Per
		var min_hand float64
		var max_hand float64
		var min_query float64
		var max_query float64

		for {

			str, err := reader.ReadString('\n')
			if err == io.EOF {
				break
			}
			if i == 1 {
				errs := json.Unmarshal([]byte(str), &temp_dict)
				if errs != nil {
					fmt.Println("json unmarshal error:", errs)
				}
				//scan_f.WriteString(str)
				min_hand = temp_dict.HandshakeTime
				max_hand = temp_dict.HandshakeTime
				min_query = temp_dict.QueryTime
				max_query = temp_dict.QueryTime
			} else {
				errs := json.Unmarshal([]byte(str), &temp_dict)
				if errs != nil {
					fmt.Println("json unmarshal error:", errs)
				}

				if temp_dict.HandshakeTime > max_hand {
					max_hand = temp_dict.HandshakeTime
					max_query = temp_dict.QueryTime
				}
				if temp_dict.HandshakeTime < min_hand {
					min_hand = temp_dict.HandshakeTime
					min_query = temp_dict.QueryTime
				}
				//reuse_f.WriteString(str)
			}
			//fmt.Print(str)
			i++
		} //写入文件时，使用带缓存的 *Writer    write := bufio.NewWriter(file)    for i := 0; i < 5; i++ {        write.WriteString("Hello，C语言中文网。 \r\n")    }

		var final_dict http3.DOH3Per
		final_dict.Ip = temp_dict.Ip
		final_dict.Port = temp_dict.Port
		final_dict.QueryTime = max_query
		final_dict.HandshakeTime = max_hand
		final_dict.TotalTime = max_hand + max_query

		resultjson, _ := json.Marshal(final_dict)
		scan_f.WriteString(string((resultjson)))
		scan_f.WriteString("\n")

		final_dict.QueryTime = min_query
		final_dict.HandshakeTime = min_hand
		final_dict.TotalTime = min_query + min_hand

		resultjson, _ = json.Marshal(final_dict)
		reuse_f.WriteString(string((resultjson)))
		reuse_f.WriteString("\n")

	}
	scan_f.Close()
	reuse_f.Close()

	rmErr := Filerm("/root/doq_doh3/world_scan/performance/result/doh3/*.csv")

	if rmErr != "success" {
		fmt.Println("fail file rm err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())
}

//package main
//
//import (
//	"crypto/tls"
//	"fmt"
//	"github.com/lucas-clemente/quic-go"
//	"github.com/lucas-clemente/quic-go/http3"
//	"github.com/miekg/dns"
//	"io/ioutil"
//	"net"
//	"net/http"
//	"strconv"
//	"time"
//)
//
//func main() {
//	tokenStore := quic.NewLRUTokenStore(5, 50)
//	clientSessionCache := tls.NewLRUClientSessionCache(100)
//	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
//	if err != nil {
//		fmt.Println(err)
//	}
//	_, portString, _ := net.SplitHostPort(udpConn.LocalAddr().String())
//	udpConn.Close()
//	port, _ := strconv.Atoi(portString)
//
//	url := "https://203.76.245.200/?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
//	//url := "https://doh3.dns.NextDNS.io/?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
//
//	h3Client := http.Client{
//		Timeout: 5 * time.Second,
//		Transport: &http3.RoundTripper{
//			TLSClientConfig: &tls.Config{
//				InsecureSkipVerify:     true,
//				MaxVersion:             0,
//				ClientSessionCache:     clientSessionCache,
//				SessionTicketsDisabled: false,
//			},
//			QuicConfig: &quic.Config{
//				TokenStore:           tokenStore,
//				HandshakeIdleTimeout: 5 * time.Second,
//				Port:                 port,
//			},
//		},
//	}
//
//	for i := 1; i <= 3; i++ {
//		req, err := http.NewRequest(http.MethodGet, url, nil)
//		if err != nil {
//			fmt.Println(err)
//		}
//
//		req.Header["User-Agent"] = []string{"http3.client.dilfish.dev"}
//
//		resp, err := h3Client.Do(req)
//		if err != nil {
//			fmt.Println(err)
//		}
//		//fmt.Println(resp.Proto)
//		//fmt.Println(resp.StatusCode)
//		if resp.StatusCode == http.StatusOK {
//			bt, err := ioutil.ReadAll(resp.Body)
//			if err != nil {
//				fmt.Println(err)
//			}
//			reply := &dns.Msg{}
//			err = reply.Unpack(bt)
//			if err != nil {
//				fmt.Println(err)
//			}
//			if len(reply.Answer) != 0 {
//				fmt.Println(reply.Answer)
//			}
//
//		}
//		resp.Body.Close()
//		time.Sleep(2 * time.Second)
//
//	}
//
//}
