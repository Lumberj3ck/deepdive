package main

import (
	"log"
	"os"

	"github.com/miekg/dns"
)

func main() {
	host := os.Getenv("CLIENT_BIND_HOST")

	if len(host) == 0{
		host = "127.0.0.1:5356"
	}

	m := new(dns.Msg)
	serverAddr := host

	c := new(dns.Client)
	c.Net = "udp"
	// d, _, err := c.Exchange(m, serverAddr)
	// if err != nil{
	// 	log.Fatalf("err during dns exchange: ", err.Error())
	// }
	// log.Println(d)
	// log.Println(d.Answer)

	log.Println("-----------------------------")
	m = new(dns.Msg)
	name := "blog.dnsimple.com"
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	// m.RecursionDesired = false

	d, _, err := c.Exchange(m, serverAddr)
	if err != nil {
		log.Fatalf("err during dns exchange: ", err.Error())
	}

	log.Println(d)
	log.Println(d.Answer, len(d.Answer))
	log.Println("Is Truncated: ", d.Truncated)
	if d.Truncated {
		c.Net = "tcp"
		d, _, err := c.Exchange(m, serverAddr)

		if err != nil {
			log.Fatalf("err during dns exchange: ", err.Error())
		}

		log.Println(d)
		log.Println(d.Answer, len(d.Answer))
	}
}
