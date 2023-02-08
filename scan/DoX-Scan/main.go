package main

import (
	"DoX-Scan/dnstcp_verify"
	"DoX-Scan/dnsudp_verify"
	"DoX-Scan/doh_verify"
	"DoX-Scan/doq_verify"
	"DoX-Scan/dot_verify"
	"DoX-Scan/metrics"
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func run(jobs <-chan string, queryType, queryPort, scanType string, ScanFile string, successFile string, failFile string, scaReuseFile string, logFile string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()
	scanF, err_ := os.Create(ScanFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	successF, err_ := os.Create(successFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	failF, err_ := os.Create(failFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	reuseF, err_ := os.Create(scaReuseFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	logF, err_ := os.Create(logFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	for line := range jobs {

		limiter.Wait(ctx)
		switch queryType {
		case "doq":
			result, err := doq_verify.Verify(line, queryPort, scanType)
			if err != "success" {
				failF.WriteString(line + "," + err)
				failF.WriteString("\n")
			} else {
				successF.WriteString(line)
				successF.WriteString("\n")

				if scanType != "verify" {
					first_result := strings.Split(result, "###")[0]
					final_result := strings.Split(result, "###")[1]
					//qlog_message := strings.Split(result, "###")[2]

					scanF.WriteString(first_result)
					scanF.WriteString("\n")

					reuseF.WriteString(final_result)
					reuseF.WriteString("\n")

					//logF.WriteString(qlog_message)
					//logF.WriteString("\n")

				} else {
					scanF.WriteString(result)
					scanF.WriteString("\n")
				}

			}

		case "dot":
			result, err := dot_verify.Verify(line, queryPort, scanType)
			if err != "success" {
				failF.WriteString(line + "," + err)
				failF.WriteString("\n")
			} else {
				successF.WriteString(line)
				successF.WriteString("\n")

				if scanType != "verify" {
					first_result := strings.Split(result, "###")[0]
					final_result := strings.Split(result, "###")[1]
					scanF.WriteString(first_result)
					scanF.WriteString("\n")

					reuseF.WriteString(final_result)
					reuseF.WriteString("\n")

				} else {
					scanF.WriteString(result)
					scanF.WriteString("\n")
				}
			}

		case "doh":
			result, err := doh_verify.Verify(line, queryPort, scanType)
			if err != "success" {
				failF.WriteString(line + "," + err)
				failF.WriteString("\n")
			} else {
				successF.WriteString(line)
				successF.WriteString("\n")

				if scanType != "verify" {
					first_result := strings.Split(result, "###")[0]
					final_result := strings.Split(result, "###")[1]
					scanF.WriteString(first_result)
					scanF.WriteString("\n")

					reuseF.WriteString(final_result)
					reuseF.WriteString("\n")

				} else {
					scanF.WriteString(result)
					scanF.WriteString("\n")
				}
			}

		case "udp":
			result, err := dnsudp_verify.Verify(line, queryPort, scanType)
			if err != "success" {
				failF.WriteString(line + "," + err)
				failF.WriteString("\n")
			} else {
				successF.WriteString(line)
				successF.WriteString("\n")

				if scanType != "verify" {
					first_result := strings.Split(result, "###")[0]
					final_result := strings.Split(result, "###")[1]
					scanF.WriteString(first_result)
					scanF.WriteString("\n")

					reuseF.WriteString(final_result)
					reuseF.WriteString("\n")

				} else {
					scanF.WriteString(result)
					scanF.WriteString("\n")
				}
			}

		case "tcp":
			result, err := dnstcp_verify.Verify(line, queryPort, scanType)
			if err != "success" {
				failF.WriteString(line + "," + err)
				failF.WriteString("\n")
			} else {
				successF.WriteString(line)
				successF.WriteString("\n")

				if scanType != "verify" {
					first_result := strings.Split(result, "###")[0]
					final_result := strings.Split(result, "###")[1]
					scanF.WriteString(first_result)
					scanF.WriteString("\n")

					reuseF.WriteString(final_result)
					reuseF.WriteString("\n")

				} else {
					scanF.WriteString(result)
					scanF.WriteString("\n")
				}
			}

		default:
			fmt.Println(line + "parameter err")
			os.Exit(3)

		}

	}

	scanF.Close()
	successF.Close()
	failF.Close()
	reuseF.Close()
	logF.Close()

}

func main() {
	var numThreads = flag.Int("n", 100, "Number of threads")
	var inputFile = flag.String("i", "./input.txt", "Input File")
	var resultDir = flag.String("o", "./result/", "Output File")
	var queryType = flag.String("t", "doq", "DOT or DOH or DOQ or DNS")
	var queryPort = flag.String("p", "853", "Query Port")
	var scanType = flag.String("s", "verify", "verify or performance")

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	flag.Parse()

	QPS := *numThreads // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()

	for w := 0; w < *numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)

			scanFile := *resultDir + "scan-" + strconv.Itoa(i) + ".txt"
			scaReuseFile := *resultDir + "reuse-" + strconv.Itoa(i) + ".txt"
			successFile := *resultDir + "success-" + strconv.Itoa(i) + ".txt"
			failFile := *resultDir + "fail-" + strconv.Itoa(i) + ".txt"
			logFile := *resultDir + "qlog-" + strconv.Itoa(i) + ".txt"

			run(jobs, *queryType, *queryPort, *scanType, scanFile, successFile, failFile, scaReuseFile, logFile, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}

	inputf, err := os.Open(*inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)

	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	mergeErr := metrics.FileMerge(*resultDir+"scan-*", *resultDir+"result_scan.txt")
	if mergeErr != "success" {
		fmt.Println("scan file merge err")
	}

	mergeErr = metrics.FileMerge(*resultDir+"success-*", *resultDir+"result_success.txt")
	if mergeErr != "success" {
		fmt.Println("success file merge err")
	}

	mergeErr = metrics.FileMerge(*resultDir+"fail-*", *resultDir+"result_fail.txt")
	if mergeErr != "success" {
		fmt.Println("fail file merge err")
	}

	mergeErr = metrics.FileMerge(*resultDir+"reuse-*", *resultDir+"result_reuse.txt")
	if mergeErr != "success" {
		fmt.Println("fail file merge err")
	}

	mergeErr = metrics.FileMerge(*resultDir+"qlog-*", *resultDir+"result_qlog.txt")
	if mergeErr != "success" {
		fmt.Println("fail file merge err")
	}

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())

}
