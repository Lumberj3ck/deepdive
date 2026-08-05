package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

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
		c := NewCache()

		for _, zone := range Tcase.zones {
			c.PushZoneEntry(zone, map[string]NS_RR{})
		}

		t.Run(Tcase.test, func(t *testing.T) {
			resp := c.getClosestZone(Tcase.test)
			if resp != Tcase.want {
				t.Fail()
			}
		})
	}
}

func TestCacheReturnsZoneSnapshot(t *testing.T) {
	cache := NewCache()
	cache.PushRREntry("example.", "ns.example.", NS_RR{
		NS: dns.NS{
			Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns.example.",
		},
	})

	entries, ok := cache.GetZoneRR("example.")
	if !ok {
		t.Fatal("expected cached zone")
	}
	delete(entries, "ns.example.")

	entries, ok = cache.GetZoneRR("example.")
	if !ok || len(entries) != 1 {
		t.Fatal("mutating returned entries changed the cache")
	}
}

func TestCacheExpiresDelegationAndAddressSeparately(t *testing.T) {
	now := time.Now().Unix()
	cache := NewCache()
	cache.PushRREntry("example.", "expired.example.", NS_RR{
		ttlExpiresAt: now - 1,
		NS: dns.NS{
			Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "expired.example.",
		},
	})
	cache.PushRREntry("parent.", "ns.parent.", NS_RR{
		ip:          net.ParseIP("192.0.2.1"),
		ipExpiresAt: now - 1,
		NS: dns.NS{
			Hdr: dns.RR_Header{Name: "parent.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns.parent.",
		},
	})

	if _, ok := cache.GetZoneRR("example."); ok {
		t.Fatal("expired delegation remained cached")
	}

	rr, ok := cache.GetNsRR("parent.", "ns.parent.")
	if !ok {
		t.Fatal("valid delegation was removed with its expired address")
	}
	if rr.ip != nil {
		t.Fatal("expired nameserver address remained cached")
	}
}

func TestCNAMEResolvePath(t *testing.T) {
	// testCases := []string{"blog.dnsimple.com", "www.github.com", "www.apple.com", "dns1.p01.nsone.net"}
	testCases := []struct {
		name    string
		wantErr error
	}{
		{name: "google.com"},
		{name: "gisma.com"},
		{name: "vercel.com"},
		{name: "apple.com"},
		{name: "blog.dnsimple.com"},
		{name: "www.rfc-editor.org", wantErr: ErrNoSuchRR},
	}
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
		t.Run(test.name, func(t *testing.T) {
			r := Resolver{logger: logger, Cache: NewCache()}
			q := NewQuestion(test.name, dns.TypeMX)
			answ_rr, err := r.resolveQ(q, 0)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("resolve error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal("err during dns exchange: ", err)
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

func TestResolveWithWarmCache(t *testing.T) {
	// testCases := []string{"blog.dnsimple.com", "www.github.com", "www.apple.com", "dns1.p01.nsone.net"}
	testCases := []struct {
		name    string
		wantErr error
	}{
		{name: "google.com"},
		{name: "gisma.com"},
		{name: "vercel.com"},
		{name: "apple.com"},
		{name: "blog.dnsimple.com"},
		{name: "www.rfc-editor.org", wantErr: ErrNoSuchRR},
		{name: "www.github.com"},
	}
	//, "gisma.com"}
	v := os.Getenv("RESOLVY_LOGS")
	var writer io.Writer
	if v == "" {
		writer = io.Discard
	} else {
		writer = os.Stdout
	}
	logger := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := Resolver{logger: logger, Cache: NewCache()}

	for range 2 {
		for _, test := range testCases {
			t.Run(test.name, func(t *testing.T) {
				q := NewQuestion(test.name, dns.TypeMX)
				answ_rr, err := r.resolveQ(q, 0)

				if test.wantErr != nil {
					if !errors.Is(err, test.wantErr) {
						t.Fatalf("resolve error = %v, want %v", err, test.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal("err during dns exchange: ", err)
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
}
