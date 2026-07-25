package main

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func NewMsg(name string, qtype dns.Type) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), uint16(qtype))
	return m
}

func NewQuestion(name string, qtype uint16) dns.Question {
	return dns.Question{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}
}

func NewClient() *dns.Client {
	c := new(dns.Client)
	c.Net = "udp"
	return c
}

func TestCacheMatching(t *testing.T) {
	testCases := []struct {
		test  string
		want  string
		zones []string
	}{
		{
			test:  "blog.dnsimple.com",
			want:  ".",
			zones: []string{"om.", "m.", "net."},
		},
		{
			test:  "blog.dnsimple.com",
			want:  "com.",
			zones: []string{"com."},
		},
		{
			test:  "blog.dnsimple.com",
			want:  "dnsimple.com.",
			zones: []string{"com.", "dnsimple.com."},
		},
		{
			test:  "api.example.org",
			want:  "example.org.",
			zones: []string{"org.", "example.org."},
		},
		{
			test:  "www.example.com",
			want:  "www.example.com.",
			zones: []string{"com.", "example.com.", "www.example.com."},
		},
		{
			test:  "example.net",
			want:  "net.",
			zones: []string{"com.", "net."},
		},
		{
			test:  "localhost",
			want:  ".",
			zones: []string{"com.", "net.", "org."},
		},
		{
			test:  "blog.dnsimple.com.",
			want:  "dnsimple.com.",
			zones: []string{"com.", "dnsimple.com."},
		},
		{
			test:  "sub.example.co.uk",
			want:  "co.uk.",
			zones: []string{"uk.", "co.uk."},
		},
	}

	for _, Tcase := range testCases {
		c := make(Cache)

		for _, zone := range Tcase.zones {
			c[zone] = map[string]NS_RR{}
		}

		t.Run(Tcase.test, func(t *testing.T) {
			resp := c.getClosestZone(Tcase.test, 0)
			if resp != Tcase.want {
				t.Fail()
			}
		})
	}
}

func TestCNAMEResolvePath(t *testing.T) {
	// testCases := []string{"blog.dnsimple.com", "www.github.com", "www.apple.com", "dns1.p01.nsone.net"}
	testCases := []string{"google.com", "gisma.com"} 
	//, "gisma.com"}
	v := os.Getenv("RESOLVY_LOGS")
	var writer io.Writer
	if v == "" {
		writer = io.Discard
	} else {
		writer = os.Stdout
	}
	logger := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))

	for _, test := range testCases {
		t.Run(test, func(t *testing.T) {
			q := NewQuestion(test, dns.TypeA)

			r := Resolver{logger: logger, Cache: make(Cache)}
			answ_rr, err := r.resolveQ(q, 0)

			if err != nil {
				t.Error("err during dns exchange: ", err.Error())
			}
			if len(answ_rr) == 0 {
				t.Error("No domain name found")
			}
			for _, rr := range answ_rr {
				t.Log(rr.String())
			}
		})
	}
}
