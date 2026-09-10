package main

import (
	"crypto/tls"
	"flag"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func handleExchange(c *dns.Client, domain string, serverAddr string){
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	d, _, err := c.Exchange(m, serverAddr)
	slog.Info("msg is", "msg", m)

	if err != nil {
		slog.Warn("err during dns exchange: ", "err", err)
		return
	}

	slog.Info("Response ", "answer", d.Answer, "RR amount", len(d.Answer))
	if d.Truncated {
		c.Net = "tcp"
		d, _, err := c.Exchange(m, serverAddr)

		if err != nil {
			slog.Warn("err during dns exchange: ", "err", err)
		}
		slog.Info("Response ", "answer", d.Answer)
	}
}

func main() {
	host := flag.String("server", "127.0.0.1:5356", "DNS server address")
	tcpTLS := flag.Bool("tcp-tls", false, "Use DNS over TLS")
	reqAmount := flag.Int("req", 1, "Amount of requests to make")
	workers := flag.Int("work", 1, "Amount of parallel workers")
	flag.Parse()

	if *workers > 100 {
		*workers = 100
		slog.Info("Restricted parallel workers to ", "workers", workers)
	}  

	serverAddr := *host
	slog.Info("Bind ", "host", *host)

	c := new(dns.Client)
	if *tcpTLS {
		serverName := strings.Split(*host, ":")
		if len(serverName) < 2 {
			slog.Warn("Expected host in host:port format")
			return
		}

		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{
			ServerName: serverName[0],
			MinVersion: tls.VersionTLS12,
		}
	}

	tasks := make(chan string)
	var wg sync.WaitGroup
	go func() {
		for range *reqAmount{
			tasks <- "google.com"
		}
	}()

	for i := range *workers{
		wg.Add(1)
		go func (id int)  {
			for{
				select {
				case t := <-tasks:
					slog.Info("Worker makes request", "id", id)
					handleExchange(c, t, serverAddr)
				case <-time.After(time.Second):
					slog.Info("Stopping worker ", "id", id)
					wg.Done()
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
