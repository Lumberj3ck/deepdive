package main

import (
	"context"
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

func TestCacheRejectsMalformedZone(t *testing.T) {
	cache := NewCache()
	cache.PushRREntry("gpm.byteoversea.net..", "ns.gpm.byteoversea.net.", NS_RR{
		NS: dns.NS{
			Hdr: dns.RR_Header{Name: "gpm.byteoversea.net..", Rrtype: dns.TypeNS, Class: dns.ClassINET},
			Ns:  "ns.gpm.byteoversea.net.",
		},
	})

	if _, ok := cache.GetZoneRR("gpm.byteoversea.net.."); ok {
		t.Fatal("malformed zone was cached")
	}
}

func TestResolutionDepthLimit(t *testing.T) {
	resolver := &Resolver{}
	_, err := resolver.resolveQ(NewQuestion("example.com", dns.TypeA), maxResolveDepth)
	if !errors.Is(err, ErrResolveDepthExceeded) {
		t.Fatalf("resolve error = %v, want depth limit", err)
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

func TestHandleReferencesQueriesNameServersInParallel(t *testing.T) {
	cache := NewCache()
	cache.PushZoneEntry("example.", map[string]NS_RR{
		"ns1.example.": {
			ip: net.ParseIP("192.0.2.1"),
			NS: dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example."},
		},
		"ns2.example.": {
			ip: net.ParseIP("192.0.2.2"),
			NS: dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns2.example."},
		},
		"ns3.example.": {
			ip: net.ParseIP("192.0.2.3"),
			NS: dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns3.example."},
		},
	})

	started := make(chan struct{}, 3)
	release := make(chan struct{})
	canceled := make(chan struct{}, 1)
	resolver := &Resolver{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:  cache,
		queryFn: func(ctx context.Context, q dns.Question, server string) (*dns.Msg, error) {
			started <- struct{}{}
			<-release

			resp := new(dns.Msg)
			if server == "192.0.2.1" {
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			}
			if server == "192.0.2.3" {
				<-ctx.Done()
				canceled <- struct{}{}
				return nil, ctx.Err()
			}
			resp.Rcode = dns.RcodeSuccess
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("203.0.113.10").To4(),
			}}
			return resp, nil
		},
	}

	type resolveResult struct {
		resp *dns.Msg
		err  error
	}
	resolved := make(chan resolveResult, 1)
	go func() {
		resp, err := resolver.handleRefferences(NewQuestion("www.example.", dns.TypeA), 0)
		resolved <- resolveResult{resp: resp, err: err}
	}()

	for range 3 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("nameserver queries did not run concurrently")
		}
	}
	close(release)

	select {
	case result := <-resolved:
		if result.err != nil {
			t.Fatalf("resolve error = %v", result.err)
		}
		if len(result.resp.Answer) != 1 {
			t.Fatalf("answer count = %d, want 1", len(result.resp.Answer))
		}
	case <-time.After(time.Second):
		t.Fatal("parallel resolve did not complete")
	}

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("losing nameserver query was not canceled")
	}
}

func TestExchangeDNSCancellationClosesConnection(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	received := make(chan struct{})
	stopServer := make(chan struct{})
	defer close(stopServer)
	go func() {
		buf := make([]byte, 512)
		if _, _, err := server.ReadFrom(buf); err != nil {
			return
		}
		close(received)
		<-stopServer
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion("example.", dns.TypeA)
		_, err := exchangeDNS(ctx, &dns.Client{Net: udpNet, Timeout: 5 * time.Second}, msg, server.LocalAddr().String())
		result <- err
	}()

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("test DNS server did not receive the query")
	}
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled DNS exchange returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled DNS exchange remained blocked")
	}
}

func TestCNAMEResolvePath(t *testing.T) {
	testCases := []struct {
		name      string
		wantEmpty bool
	}{
		{name: "google.com"},
		{name: "gisma.com"},
		{name: "vercel.com"},
		{name: "apple.com"},
		{name: "blog.dnsimple.com"},
		{name: "www.rfc-editor.org", wantEmpty: true},
	}
	v := os.Getenv("DEEP_DIVE_LOGS")
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
			resp, err := r.resolveQ(q, 0)
			if err != nil {
				t.Fatal("err during dns exchange: ", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
			}
			if !test.wantEmpty && len(resp.Answer) == 0 {
				t.Error("No domain name found")
			}
			for _, rr := range resp.Answer {
				t.Log(rr.String())
			}
		})
	}

}

func TestResolveWithWarmCache(t *testing.T) {
	testCases := []struct {
		name      string
		wantEmpty bool
	}{
		{name: "google.com"},
		{name: "gisma.com"},
		{name: "vercel.com"},
		{name: "apple.com"},
		{name: "blog.dnsimple.com"},
		{name: "www.rfc-editor.org", wantEmpty: true},
		{name: "www.github.com"},
	}
	v := os.Getenv("DEEP_DIVE_LOGS")
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
				resp, err := r.resolveQ(q, 0)
				if err != nil {
					t.Fatal("err during dns exchange: ", err)
				}
				if resp.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
				}
				if !test.wantEmpty && len(resp.Answer) == 0 {
					t.Error("No domain name found")
				}
				for _, rr := range resp.Answer {
					t.Log(rr.String())
				}
			})
		}
	}
}
