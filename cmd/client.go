package main

import (
	"crypto/tls"
	"flag"
	"log"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	host := flag.String("server", "127.0.0.1:5356", "DNS server address")
	tcpTLS := flag.Bool("tcp-tls", false, "Use DNS over TLS")
	flag.Parse()

	m := new(dns.Msg)
	serverAddr := *host
	log.Println("BIND", *host)

	c := new(dns.Client)
	if *tcpTLS {
		serverName := strings.Split(*host, ":")
		if len(serverName) < 2 {
			log.Println("Expected host in host:port format")
			return
		}

		c.Net = "tcp-tls"
		c.TLSConfig = &tls.Config{
			ServerName: serverName[0],
			MinVersion: tls.VersionTLS12,
		}
	}

	m = new(dns.Msg)
	name := "blog.dnsimple.com"
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	// m.RecursionDesired = false

	d, _, err := c.Exchange(m, serverAddr)
	if err != nil {
		log.Fatalf("err during dns exchange: %v", err)
	}

	log.Println(d)
	log.Println(d.Answer, len(d.Answer))
	log.Println("Is Truncated: ", d.Truncated)
	if d.Truncated {
		c.Net = "tcp"
		d, _, err := c.Exchange(m, serverAddr)

		if err != nil {
			log.Fatalf("err during dns exchange: %v", err)
		}

		log.Println(d)
		log.Println(d.Answer, len(d.Answer))
	}
}
