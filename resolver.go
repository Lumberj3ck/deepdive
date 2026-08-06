package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var safeBelt = map[string]NS_RR{
	"a.root-servers.net.": {
		ip: net.ParseIP("198.41.0.4"),
		NS: dns.NS{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: "a.root-servers.net.",
		},
	},
	"b.root-servers.net.": {
		ip: net.ParseIP("199.9.14.201"),
		NS: dns.NS{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: "b.root-servers.net.",
		},
	},
	"c.root-servers.net.": {
		ip: net.ParseIP("192.33.4.12"),
		NS: dns.NS{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: "c.root-servers.net.",
		},
	},
}

var notFoundErr = fmt.Errorf("Couldn't find any answers for given query")

type Resolver struct {
	logger *slog.Logger
	Cache  *Cache
}

const (
	retries               = 2
	maxReferralIterations = 64
)

var dataTruncatedErr = errors.New("Udp datagram truncated, retry with tcp")
var serverNoRespErr = fmt.Errorf("Server didn't respond after %d retries ", retries)

const udpNet = "udp"
const tcpNet = "tcp"

func (r *Resolver) queryQ(q dns.Question, server string, net string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	c := new(dns.Client)
	c.Net = net

	msg.Question = append(msg.Question, q)
	r.logger.Debug(q.String(), "To: ", server)

	r.logger.Info(fmt.Sprintf("Doing %s query to %s with %s", net, server, q.Name))
	if net == udpNet {
		msg.SetEdns0(1232, false)
		for range retries {
			resp, _, err := c.Exchange(msg, server+":53")

			if err != nil {
				r.logger.Warn("Got err during dns query request: ", "err", err)
				continue
			}

			if resp.Truncated {
				return &dns.Msg{}, dataTruncatedErr
			}

			return resp, nil
		}
	} else {
		resp, _, err := c.Exchange(msg, server+":53")
		return resp, err
	}

	return &dns.Msg{}, serverNoRespErr
}

// NS_RR.Hdr.Name -- is actuall ownership of this refference
type NS_RR struct {
	ip           net.IP
	ttlExpiresAt int64
	ipExpiresAt  int64
	dns.NS
}

func cloneNSRR(rr NS_RR) NS_RR {
	rr.ip = append(net.IP(nil), rr.ip...)
	return rr
}

func containsSoa(ns []dns.RR) bool {
	for _, rr := range ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

type Zone = string
type Cache struct {
	store map[Zone]map[string]NS_RR
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		store: make(map[Zone]map[string]NS_RR),
		mu:    sync.RWMutex{},
	}
}

func (c *Cache) PushZoneEntry(zone string, ns_names map[string]NS_RR) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := make(map[string]NS_RR, len(ns_names))
	for name, rr := range ns_names {
		entries[name] = cloneNSRR(rr)
	}
	c.store[zone] = entries
}

func (c *Cache) PushRREntry(zone string, ns_name string, ns_rr NS_RR) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.store[zone]; !ok {
		c.store[zone] = map[string]NS_RR{}
	}

	now := time.Now().Unix()
	if ns_rr.ttlExpiresAt == 0 && ns_rr.Hdr.Ttl > 0 {
		ns_rr.ttlExpiresAt = now + int64(ns_rr.Hdr.Ttl)
	}
	if ns_rr.ip != nil && ns_rr.ipExpiresAt == 0 && ns_rr.Hdr.Ttl > 0 {
		ns_rr.ipExpiresAt = now + int64(ns_rr.Hdr.Ttl)
	}
	c.store[zone][ns_name] = cloneNSRR(ns_rr)
}

func (c *Cache) GetZoneRR(zone string) (map[string]NS_RR, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	z, ok := c.store[zone]
	if !ok {
		return nil, false
	}

	c.removeExpiredLocked(zone, time.Now().Unix())
	z, ok = c.store[zone]
	if !ok {
		return nil, false
	}

	entries := make(map[string]NS_RR, len(z))
	for name, rr := range z {
		entries[name] = cloneNSRR(rr)
	}
	return entries, true
}

func (c *Cache) GetNsRR(zone string, ns_name string) (NS_RR, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeExpiredLocked(zone, time.Now().Unix())

	z, ok := c.store[zone]
	if !ok {
		return NS_RR{}, false
	}

	nsrr, ok := z[ns_name]
	return cloneNSRR(nsrr), ok
}

func (c *Cache) CleanEntry(zone string, ns_name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.store[zone]; !ok {
		return fmt.Errorf("zone to clean doesn't exist")
	}

	delete(c.store[zone], ns_name)
	if len(c.store[zone]) == 0 {
		delete(c.store, zone)
	}
	return nil
}

func (c *Cache) updateNsAddress(zone string, ns_name string, ip net.IP, ttl uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, ok := c.store[zone]
	if !ok {
		return false
	}

	rr, ok := entries[ns_name]
	if !ok {
		return false
	}

	rr.ip = append(net.IP(nil), ip...)
	rr.ipExpiresAt = time.Now().Unix() + int64(ttl)
	entries[ns_name] = rr
	return true
}

func (c *Cache) getClosestZone(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var clossestZone string
	var currMatch int
	now := time.Now().Unix()

	for zone := range c.store {
		c.removeExpiredLocked(zone, now)
		if _, ok := c.store[zone]; !ok {
			continue
		}

		m := dns.CompareDomainName(dns.CanonicalName(zone), dns.CanonicalName(name))
		if dns.IsSubDomain(dns.CanonicalName(zone), dns.CanonicalName(name)) && m >= currMatch {
			clossestZone = zone
			currMatch = m
		}
	}

	if len(clossestZone) == 0 {
		clossestZone = "."
	}
	return clossestZone
}

func (c *Cache) removeExpiredLocked(zone string, now int64) {
	entries, ok := c.store[zone]
	if !ok {
		return
	}

	hadEntries := len(entries) > 0
	for name, rr := range entries {
		if rr.ttlExpiresAt != 0 && rr.ttlExpiresAt <= now {
			delete(entries, name)
			continue
		}

		if rr.ip != nil && rr.ipExpiresAt != 0 && rr.ipExpiresAt <= now {
			rr.ip = nil
			rr.ipExpiresAt = 0
			entries[name] = rr
		}
	}

	if hadEntries && len(entries) == 0 {
		delete(c.store, zone)
	}
}

type Delegation struct {
	servers []NS_RR
}

func newDelegation(servers []NS_RR) *Delegation {
	return &Delegation{
		servers: servers,
	}
}

var ErrNoKnownNsEndpoint = fmt.Errorf("No, known ns endpoints available.")
var ErrNoNsRefferences = fmt.Errorf("All Ns refferences visited")
var ErrServerNotReachable = fmt.Errorf("Server not reachable")
var ErrNoSuchRR = fmt.Errorf("No given rr available for domain")
var ErrReferralLimitExceeded = fmt.Errorf("referral iteration limit exceeded")

func (r *Resolver) GetNextServer(zone string, servers map[string]NS_RR, visited map[string]bool) (net.IP, string, error) {
	var serverIP net.IP
	var nsDomainName string
	for domainName, server_RR := range servers {
		if visited[domainName] {
			continue
		}
		if server_RR.ip != nil {
			serverIP = server_RR.ip
			nsDomainName = domainName
			break
		}
	}

	if serverIP != nil {
		return serverIP, nsDomainName, nil
	}

	for domainName, server_RR := range servers {
		if visited[domainName] {
			continue
		}

		if server_RR.ip == nil {
			return nil, server_RR.Ns, ErrNoKnownNsEndpoint
			// q := dns.Question{Name: server_RR.Ns, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			// resp, err := r.resolveQ(q, depth+1)
			// if err != nil {
			// 	r.logger.Warn("Got err during resolve of NS: ", "err", err)
			// 	continue
			// }
			//
		}
	}
	return nil, "", ErrNoNsRefferences
}

func (r *Resolver) queryQWithRetry(q dns.Question, serverIP string) (*dns.Msg, error) {
	resp, err := r.queryQ(q, serverIP, udpNet)
	r.logger.Info("Received after udp", "err", err)

	if errors.Is(err, dataTruncatedErr) || errors.Is(err, serverNoRespErr) {
		resp, err = r.queryQ(q, serverIP, tcpNet)

		if err != nil {
			// Grab next nameserver refference if available
			return nil, ErrServerNotReachable
		}
	}
	return resp, err
}

func (r *Resolver) handleRefferences(q dns.Question) (*dns.Msg, error) {
	zone := r.Cache.getClosestZone(q.Name)

	if zone == "." {
		r.Cache.PushZoneEntry(".", safeBelt)
	}

	var visited = make(map[string]bool)
	r.logger.Info("Got closest zone: ", "zone", zone)
	servers, _ := r.Cache.GetZoneRR(zone)

	for range maxReferralIterations {
		// it will try to resolve one, if can't it will try to resolve next
		serverIP, nsReff, err := r.GetNextServer(zone, servers, visited)

		if err == ErrNoNsRefferences {
			return nil, fmt.Errorf("Failed to resolve NS refferences")
		}

		if err == ErrNoKnownNsEndpoint {
			// or AAAA
			resp, err := r.resolveQ(dns.Question{Name: nsReff, Qtype: dns.TypeA, Qclass: dns.ClassINET}, 0)
			if err != nil {
				r.logger.Warn("Got err during resolve of NS: ", "err", err)
				visited[nsReff] = true
				continue
			}

			for _, rr := range resp {
				// or AAAA
				if rr, ok := rr.(*dns.A); ok {
					s := servers[nsReff]
					s.ip = append(net.IP(nil), rr.A...)
					s.ipExpiresAt = time.Now().Unix() + int64(rr.Hdr.Ttl)

					servers[nsReff] = s
					r.Cache.updateNsAddress(zone, nsReff, rr.A, rr.Hdr.Ttl)
				}
			}
			serverIP = servers[nsReff].ip
		}

		visited[nsReff] = true
		resp, err := r.queryQWithRetry(q, serverIP.String())

		if err != nil {
			r.logger.Info("Skipping server, because of the err", "serverIP", serverIP)
			continue
		}

		// switch resp {
		// case answer:
		// 	return
		// case refference:
		// 	// check reff brings us clother?
		// 	r.Cache.add(resp)
		// 	r.Cache.getClosestZone(q.Name)
		// 	delegation := newDelegation(resp)
		// }

		if len(resp.Answer) > 0 {
			r.logger.Info("Found resp answer", "resp", resp)
			return resp, nil
		}

		// nodata, name exists, however not such RR type available
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && resp.Authoritative && containsSoa(resp.Ns) {
			return nil, ErrNoSuchRR
		}

		gluedRefferences := map[string]NS_RR{}
		if len(resp.Extra) > 0 {
			for _, extr := range resp.Extra {
				// or AAAA
				extra_rr, ok := extr.(*dns.A)
				if !ok {
					continue
				}

				for _, rr := range resp.Ns {
					rr, ok := rr.(*dns.NS)
					if !ok {
						continue
					}

					if rr.Ns == extr.Header().Name {
						gluedRefferences[rr.Ns] = NS_RR{
							NS:          *rr,
							ip:          append(net.IP(nil), extra_rr.A...),
							ipExpiresAt: time.Now().Unix() + int64(extra_rr.Hdr.Ttl),
						}
					}
				}
			}
		}

		if len(resp.Ns) > 0 {
			for _, rr := range resp.Ns {
				rr, ok := rr.(*dns.NS)
				if !ok {
					continue
				}

				cachedNsRR, rr_exists := r.Cache.GetNsRR(rr.Header().Name, rr.Ns)
				if rr_exists && cachedNsRR.ip != nil {
					continue
				}

				var nsRR NS_RR
				if _, ok := gluedRefferences[rr.Ns]; ok {
					nsRR = gluedRefferences[rr.Ns]
				} else {
					nsRR = NS_RR{NS: *rr}
				}

				r.Cache.PushRREntry(rr.Header().Name, rr.Ns, nsRR)
			}
		}

		zone = r.Cache.getClosestZone(q.Name)
		servers, _ = r.Cache.GetZoneRR(zone)
	}

	return nil, ErrReferralLimitExceeded
}

func (r *Resolver) resolveQ(q dns.Question, depth int) ([]dns.RR, error) {
	// loop
	// s := get_the_closest_server(q.Name)
	// s - is_available? -> no -> resolve in gorutine
	//   |
	//  ask s about q.Name
	//        |
	//      response
	//        |
	//    do we have answer?  -> yes, return, if CNAME and qtype A change SNAME -- to CNAME
	//     /     \
	//    /       \
	//  ns ref     glue
	//  cache       find cache and add type.A IP
	//
	//  what to use for cache
	//  map[responsible_zone]dns.A
	answer := make([]dns.RR, 0, 10)
	for range 20 {
		resp, err := r.handleRefferences(q)

		if err != nil {
			// handle
			return nil, err
		}
		r.logger.Info("Handled reff ", "resp", resp)

		//analyze results
		if len(resp.Answer) > 0 {
			answer = append(answer, resp.Answer...)

			if q.Qtype == dns.TypeA {
				var cnameResolved bool
				var cnameExists bool
				for _, rr := range resp.Answer {
					if rr.Header().Name == q.Name && rr.Header().Rrtype == dns.TypeA {
						cnameResolved = true
						break
					}
					if rr, ok := rr.(*dns.CNAME); ok {
						cnameExists = true
						q.Name = rr.Target
						r.logger.Debug("Resolving CNAME " + q.Name)
					}
				}
				if !cnameResolved && cnameExists {
					continue
				}
			}
			return answer, nil
		}
	}

	return nil, notFoundErr
}

func (r *Resolver) handleAll(w dns.ResponseWriter, m *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(m)

	for _, q := range m.Question {
		rr, err := r.resolveQ(q, 0)
		if err != nil {
			// write err as dns err
			slog.Error("Got err during resolve: ", "err", err)
			return
		}

		if len(rr) > 0 {
			for _, r := range rr {
				msg.Answer = append(msg.Answer, r)
			}
		}
	}

	if w.RemoteAddr().Network() == "udp" {
		size := dns.MinMsgSize

		if opt := m.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}

		msg.Truncate(size)
	}
	// fmt.Println("sent ", len(msg.Answer))
	// fmt.Println(msg.Truncated)
	// fmt.Println(msg.Compress)

	if err := w.WriteMsg(msg); err != nil {
		slog.Error("WriteMsg failed: ", "err: ", err)
	}
}

func main() {
	// name := "www.example.com"
	// answers, err := resolve(name, dns.TypeAAAA)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// for _, rr := range answers {
	// 	fmt.Println(strings.TrimSpace(rr.String()))
	// }

	// logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// q := dns.Question{Name: dns.Fqdn("m.gtld-servers.net."), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	// r := Resolver{logger: logger, Cache: make(Cache)}
	//
	// r.resolveQ(q, 0)
	host := os.Getenv("BIND_HOST")

	if len(host) == 0 {
		host = "127.0.0.1:5356"
	}

	udpServer := dns.Server{Addr: host, Net: "udp"}
	resolver := &Resolver{logger: slog.Default(), Cache: NewCache()}
	dns.HandleFunc(".", resolver.handleAll)
	var wg chan struct{}

	go func() {
		err := udpServer.ListenAndServe()

		if err != nil {
			slog.Error(err.Error())
		}
		wg <- struct{}{}
	}()
	slog.Info("Started udp servers at: ", "host", host)

	tcpTlsServer := dns.Server{Addr: host, Net: "tcp-tls"}

	var certFile string
	var privKeyFile string
	flag.StringVar(&certFile, "cert", "/etc/fullchain.pem", "")
	flag.StringVar(&privKeyFile, "privkey", "/etc/privkey.pem", "")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(certFile, privKeyFile)

	if err == nil {
		tcpTlsServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		go func() {
			err := tcpTlsServer.ListenAndServe()

			if err != nil {
				slog.Error(err.Error())
			}

			wg <- struct{}{}
		}()
		slog.Info("Started tcp tls servers at: ", "host", host)
	} else {
		slog.Info("Couldn't start tcp tls server: ", "err", err)
	}
	<-wg
}
