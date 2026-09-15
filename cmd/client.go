package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type testCase struct {
	domain string
	qtype  uint16
}

type task struct {
	testCase testCase
	sequence int
}

func (t task) domain() string {
	return strings.ReplaceAll(t.testCase.domain, "{n}", strconv.Itoa(t.sequence))
}

func loadTestCases(path string) ([]testCase, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var testCases []testCase
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 || len(fields) > 2 {
			return nil, fmt.Errorf("%s:%d: expected domain and optional record type", path, lineNumber)
		}

		domain := strings.ReplaceAll(fields[0], "{n}", "0")
		if _, valid := dns.IsDomainName(dns.Fqdn(domain)); !valid {
			return nil, fmt.Errorf("%s:%d: invalid domain %q", path, lineNumber, fields[0])
		}

		qtype := uint16(dns.TypeA)
		if len(fields) == 2 {
			var ok bool
			qtype, ok = dns.StringToType[strings.ToUpper(fields[1])]
			if !ok {
				return nil, fmt.Errorf("%s:%d: unknown record type %q", path, lineNumber, fields[1])
			}
		}
		testCases = append(testCases, testCase{domain: fields[0], qtype: qtype})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(testCases) == 0 {
		return nil, fmt.Errorf("%s: no test cases found", path)
	}
	return testCases, nil
}

func execute(client *dns.Client, server string, job task) error {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(job.domain()), job.testCase.qtype)
	_, _, err := client.Exchange(message, server)
	return err
}

func logProgress(started time.Time, total int, interval time.Duration, completed, failures *atomic.Uint64, stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	if interval == 0 {
		<-stop
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastAt := started
	var lastCompleted uint64
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			current := completed.Load()
			qps := float64(current-lastCompleted) / now.Sub(lastAt).Seconds()
			slog.Info("Load progress",
				"completed", current,
				"total", total,
				"percent", 100*float64(current)/float64(total),
				"failures", failures.Load(),
				"current_qps", qps,
			)
			lastAt = now
			lastCompleted = current
		}
	}
}

func newDNSClient(useTLS bool, server, certFile, keyFile string, timeout time.Duration) (*dns.Client, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("server must use host:port format: %w", err)
	}

	client := &dns.Client{Timeout: timeout}
	if !useTLS {
		client.Net = "udp"
		return client, nil
	}

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	client.Net = "tcp-tls"
	client.TLSConfig = &tls.Config{
		ServerName:   host,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
	}
	return client, nil
}

func main() {
	host := flag.String("server", "127.0.0.1:5356", "DNS server address")
	tcpTLS := flag.Bool("tcp-tls", false, "Use DNS over TLS")
	reqAmount := flag.Int("req", 1, "Amount of requests to make")
	workers := flag.Int("work", 1, "Amount of parallel workers")
	casesFile := flag.String("cases", "cmd/testcases/mixed.txt", "File containing domains and optional record types")
	clientCert := flag.String("client-cert", "client.pem", "mTLS client certificate")
	clientKey := flag.String("client-key", "client-key.pem", "mTLS client private key")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout for each DNS request")
	progressInterval := flag.Duration("progress", time.Second, "Progress logging interval; 0 disables progress logs")
	flag.Parse()

	if *reqAmount <= 0 {
		slog.Error("Request amount must be greater than zero")
		os.Exit(2)
	}
	if *workers <= 0 {
		slog.Error("Worker amount must be greater than zero")
		os.Exit(2)
	}
	if *timeout <= 0 {
		slog.Error("Timeout must be greater than zero")
		os.Exit(2)
	}
	if *progressInterval < 0 {
		slog.Error("Progress interval cannot be negative")
		os.Exit(2)
	}

	testCases, err := loadTestCases(*casesFile)
	if err != nil {
		slog.Error("Failed to load test cases", "err", err)
		os.Exit(2)
	}
	baseClient, err := newDNSClient(*tcpTLS, *host, *clientCert, *clientKey, *timeout)
	if err != nil {
		slog.Error("Failed to configure DNS client", "err", err)
		os.Exit(2)
	}
	transport := "udp"
	if *tcpTLS {
		transport = "dns-over-tls"
	}
	slog.Info("Starting DNS load",
		"server", *host,
		"transport", transport,
		"requests", *reqAmount,
		"workers", *workers,
		"cases_file", *casesFile,
		"cases", len(testCases),
		"timeout", *timeout,
	)
	for index, testCase := range testCases {
		if index == 10 {
			slog.Info("Additional test cases omitted from startup log", "count", len(testCases)-index)
			break
		}
		slog.Info("Loaded test case", "index", index, "domain", testCase.domain, "type", dns.TypeToString[testCase.qtype])
	}

	tasks := make(chan task, *workers)
	var completed atomic.Uint64
	var failures atomic.Uint64
	var workerGroup sync.WaitGroup
	started := time.Now()
	progressStop := make(chan struct{})
	progressStopped := make(chan struct{})
	go logProgress(started, *reqAmount, *progressInterval, &completed, &failures, progressStop, progressStopped)

	workerGroup.Add(*workers)
	for range *workers {
		go func() {
			defer workerGroup.Done()
			client := *baseClient
			for job := range tasks {
				if err := execute(&client, *host, job); err != nil {
					failureNumber := failures.Add(1)
					if failureNumber <= 5 {
						slog.Warn("DNS request failed", "domain", job.domain(), "type", dns.TypeToString[job.testCase.qtype], "err", err)
					} else if failureNumber == 6 {
						slog.Warn("Further request errors will be counted but not logged")
					}
				}
				completed.Add(1)
			}
		}()
	}

	for sequence := range *reqAmount {
		tasks <- task{
			testCase: testCases[sequence%len(testCases)],
			sequence: sequence,
		}
	}
	close(tasks)
	workerGroup.Wait()
	close(progressStop)
	<-progressStopped

	elapsed := time.Since(started)
	averageQPS := float64(completed.Load()) / elapsed.Seconds()
	if failures.Load() > 0 {
		slog.Warn("Load completed with failed requests", "completed", completed.Load(), "failures", failures.Load(), "elapsed", elapsed, "average_qps", averageQPS)
		os.Exit(1)
	}
	slog.Info("Load completed", "completed", completed.Load(), "failures", failures.Load(), "elapsed", elapsed, "average_qps", averageQPS)
}
