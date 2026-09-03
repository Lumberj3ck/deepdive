package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	logger       *slog.Logger
	Cache        *Cache
	History      *RequestHistory
	DomainPolicy *DomainPolicy
	queryFn      func(context.Context, dns.Question, string) (*dns.Msg, error)
}

const (
	retries               = 2
	maxReferralIterations = 64
	maxResolveDepth       = 16
	maxParallelQueries    = 4
	blockedResponseTTL    = 60
)

var dataTruncatedErr = errors.New("Udp datagram truncated, retry with tcp")
var serverNoRespErr = fmt.Errorf("Server didn't respond after %d retries ", retries)

const udpNet = "udp"
const tcpNet = "tcp"

func (r *Resolver) queryQ(ctx context.Context, q dns.Question, server string, net string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	c := new(dns.Client)
	c.Net = net

	msg.Question = append(msg.Question, q)
	r.logger.Debug(q.String(), "To: ", server)

	r.logger.Info(fmt.Sprintf("Doing %s query to %s with %s", net, server, q.Name))
	if net == udpNet {
		msg.SetEdns0(1232, false)
		for range retries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			started := time.Now()
			resp, err := exchangeDNS(ctx, c, msg, server+":53")
			r.recordRequest("upstream", net, server, q, responseResult(resp, err), time.Since(started))

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
		started := time.Now()
		resp, err := exchangeDNS(ctx, c, msg, server+":53")
		r.recordRequest("upstream", net, server, q, responseResult(resp, err), time.Since(started))
		return resp, err
	}

	return &dns.Msg{}, serverNoRespErr
}

func exchangeDNS(ctx context.Context, client *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stopCancel := context.AfterFunc(ctx, func() {
		// ExchangeWithConnContext only applies deadlines; closing interrupts an active read immediately.
		_ = conn.Close()
	})
	defer stopCancel()

	resp, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	return resp, err
}

func (r *Resolver) recordRequest(direction, network, peer string, q dns.Question, result string, duration time.Duration) {
	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		qtype = strconv.Itoa(int(q.Qtype))
	}
	r.History.Add(RequestEvent{
		At:        time.Now(),
		Direction: direction,
		Network:   network,
		Peer:      peer,
		Name:      q.Name,
		QType:     qtype,
		Result:    result,
		Duration:  duration,
	})
}

func responseResult(resp *dns.Msg, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp == nil {
		return "empty response"
	}
	result := dns.RcodeToString[resp.Rcode]
	if resp.Truncated {
		result += " (truncated)"
	}
	return result
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

func canonicalDNSName(name string) (string, bool) {
	name = dns.CanonicalName(name)
	_, valid := dns.IsDomainName(name)
	return name, valid
}

func NewCache() *Cache {
	return &Cache{
		store: make(map[Zone]map[string]NS_RR),
		mu:    sync.RWMutex{},
	}
}

func (c *Cache) PushZoneEntry(zone string, ns_names map[string]NS_RR) {
	zone, valid := canonicalDNSName(zone)
	if !valid {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := make(map[string]NS_RR, len(ns_names))
	for name, rr := range ns_names {
		name, valid = canonicalDNSName(name)
		if !valid {
			continue
		}
		rr.Hdr.Name = zone
		rr.Ns, valid = canonicalDNSName(rr.Ns)
		if !valid {
			continue
		}
		entries[name] = cloneNSRR(rr)
	}
	c.store[zone] = entries
}

func (c *Cache) PushRREntry(zone string, ns_name string, ns_rr NS_RR) {
	zone, valid := canonicalDNSName(zone)
	if !valid {
		return
	}
	ns_name, valid = canonicalDNSName(ns_name)
	if !valid {
		return
	}
	ns_rr.Hdr.Name = zone
	ns_rr.Ns = ns_name
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
	zone = dns.CanonicalName(zone)
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
	zone = dns.CanonicalName(zone)
	ns_name = dns.CanonicalName(ns_name)
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
	zone = dns.CanonicalName(zone)
	ns_name = dns.CanonicalName(ns_name)
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

func (c *Cache) removeZoneIfNoEndpoints(zone string) bool {
	zone = dns.CanonicalName(zone)
	c.mu.Lock()
	defer c.mu.Unlock()
	entries, exists := c.store[zone]
	if !exists {
		return true
	}
	for _, rr := range entries {
		if rr.ip != nil {
			return false
		}
	}
	delete(c.store, zone)
	return true
}

func (c *Cache) updateNsAddress(zone string, ns_name string, ip net.IP, ttl uint32) bool {
	zone = dns.CanonicalName(zone)
	ns_name = dns.CanonicalName(ns_name)
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
	name, valid := canonicalDNSName(name)
	if !valid {
		return "."
	}
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

		m := dns.CompareDomainName(zone, name)
		if dns.IsSubDomain(zone, name) && m >= currMatch {
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
var ErrReferralLimitExceeded = fmt.Errorf("referral iteration limit exceeded")
var ErrResolveDepthExceeded = fmt.Errorf("resolution depth limit exceeded")

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
		}
	}
	return nil, "", ErrNoNsRefferences
}

func (r *Resolver) queryQWithRetry(ctx context.Context, q dns.Question, serverIP string) (*dns.Msg, error) {
	if r.queryFn != nil {
		return r.queryFn(ctx, q, serverIP)
	}

	resp, err := r.queryQ(ctx, q, serverIP, udpNet)
	r.logger.Info("Received after udp", "err", err)

	if errors.Is(err, dataTruncatedErr) || errors.Is(err, serverNoRespErr) {
		resp, err = r.queryQ(ctx, q, serverIP, tcpNet)

		if err != nil {
			// Grab next nameserver refference if available
			return nil, ErrServerNotReachable
		}
	}
	return resp, err
}

type nameServerEndpoint struct {
	name string
	ip   net.IP
}

type nameServerQueryResult struct {
	name string
	resp *dns.Msg
	err  error
}

func (r *Resolver) queryNameServers(ctx context.Context, q dns.Question, endpoints []nameServerEndpoint) (<-chan nameServerQueryResult, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan nameServerQueryResult, len(endpoints))
	jobs := make(chan nameServerEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		jobs <- endpoint
	}
	close(jobs)

	workerCount := min(len(endpoints), maxParallelQueries)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case endpoint, ok := <-jobs:
					if !ok {
						return
					}
					resp, err := r.queryQWithRetry(ctx, q, endpoint.ip.String())
					select {
					case results <- nameServerQueryResult{name: endpoint.name, resp: resp, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		workers.Wait()
		close(results)
	}()
	return results, cancel
}

func (r *Resolver) handleRefferences(q dns.Question, depth int) (*dns.Msg, error) {
	return r.handleRefferencesContext(context.Background(), q, depth)
}

func (r *Resolver) handleRefferencesContext(ctx context.Context, q dns.Question, depth int) (*dns.Msg, error) {
	zone := r.Cache.getClosestZone(q.Name)

	if zone == "." {
		r.Cache.PushZoneEntry(".", safeBelt)
	}

	var visited = make(map[string]bool)
	r.logger.Debug("Got closest zone", "zone", zone)
	servers, _ := r.Cache.GetZoneRR(zone)

	for range maxReferralIterations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		endpoints := make([]nameServerEndpoint, 0, len(servers))
		unresolved := make([]string, 0, len(servers))
		for name, server := range servers {
			if visited[name] {
				continue
			}
			if server.ip == nil {
				unresolved = append(unresolved, name)
				continue
			}
			visited[name] = true
			endpoints = append(endpoints, nameServerEndpoint{name: name, ip: append(net.IP(nil), server.ip...)})
		}

		if len(endpoints) == 0 {
			if len(unresolved) == 0 {
				return nil, fmt.Errorf("Failed to resolve NS refferences")
			}

			nsName := unresolved[0]
			// Break circular in-bailiwick lookups by forcing the address lookup through the parent zone.
			// for example cache:
			// zone cvut.cz 
			// ns 	ns.cvut.cz 
			// ip 	none
			// Try to resolve cvut.cz, figure that we need to resolve ns.cvut.cz, it is fine up to moment
			// when they have shared cache and ns.cvut.cz tries to ask closest zone which is again cvut.cz
			if dns.IsSubDomain(dns.CanonicalName(zone), dns.CanonicalName(nsName)) && !r.Cache.removeZoneIfNoEndpoints(zone) {
				visited[nsName] = true
				servers, _ = r.Cache.GetZoneRR(zone)
				continue
			}

			resp, err := r.resolveQContext(ctx, dns.Question{Name: nsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}, depth+1)
			if err != nil {
				r.logger.Warn("Got err during resolve of NS: ", "ns", nsName, "err", err)
				visited[nsName] = true
				continue
			}
			if resp == nil {
				visited[nsName] = true
				continue
			}

			for _, rr := range resp.Answer {
				a, ok := rr.(*dns.A)
				if !ok {
					continue
				}
				server := servers[nsName]
				server.ip = append(net.IP(nil), a.A...)
				server.ipExpiresAt = time.Now().Unix() + int64(a.Hdr.Ttl)
				servers[nsName] = server
				r.Cache.updateNsAddress(zone, nsName, a.A, a.Hdr.Ttl)
			}
			if servers[nsName].ip == nil {
				visited[nsName] = true
			}
			continue
		}

		results, cancel := r.queryNameServers(ctx, q, endpoints)
		for result := range results {
			if result.err != nil {
				if !errors.Is(result.err, context.Canceled) {
					r.logger.Info("Skipping server, because of the err", "server", result.name, "err", result.err)
				}
				continue
			}
			resp := result.resp
			if resp == nil {
				continue
			}
			if resp.Rcode == dns.RcodeNameError && resp.Authoritative {
				cancel()
				return resp, nil
			}

			if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				r.logger.Debug("Found response answer", "resp", resp)
				cancel()
				return resp, nil
			}

			// NODATA means the name exists, but the requested record type does not.
			if resp.Rcode == dns.RcodeSuccess && resp.Authoritative && containsSoa(resp.Ns) {
				cancel()
				return resp, nil
			}

			gluedRefferences := map[string]NS_RR{}
			for _, extr := range resp.Extra {
				extraRR, ok := extr.(*dns.A)
				if !ok {
					continue
				}

				extraName := dns.CanonicalName(extr.Header().Name)
				for _, rr := range resp.Ns {
					nsRR, ok := rr.(*dns.NS)
					if !ok {
						continue
					}

					nsName := dns.CanonicalName(nsRR.Ns)
					zoneName := dns.CanonicalName(nsRR.Hdr.Name)
					if nsName == extraName {
						ns := *nsRR
						ns.Hdr.Name = zoneName
						ns.Ns = nsName
						gluedRefferences[nsName] = NS_RR{
							NS:          ns,
							ip:          append(net.IP(nil), extraRR.A...),
							ipExpiresAt: time.Now().Unix() + int64(extraRR.Hdr.Ttl),
						}
					}
				}
			}

			for _, rr := range resp.Ns {
				nsRR, ok := rr.(*dns.NS)
				if !ok {
					continue
				}

				zoneName := dns.CanonicalName(nsRR.Header().Name)
				nsName := dns.CanonicalName(nsRR.Ns)
				cachedNsRR, exists := r.Cache.GetNsRR(zoneName, nsName)
				// maybe update it
				if exists && cachedNsRR.ip != nil {
					continue
				}

				cached := gluedRefferences[nsName]
				if cached.Ns == "" {
					ns := *nsRR
					ns.Hdr.Name = zoneName
					ns.Ns = nsName
					cached = NS_RR{NS: ns}
				}
				r.Cache.PushRREntry(zoneName, nsName, cached)
			}

			nextZone := r.Cache.getClosestZone(q.Name)
			// figured that nextZone is not current, meaning that cache should be released
			if nextZone != zone {
				// Nameservers may legitimately serve both parent and child zones.
				visited = make(map[string]bool)
				zone = nextZone
				servers, _ = r.Cache.GetZoneRR(zone)
				cancel()
				break
			}
			// if the same server manages parrent and child keep cache and only update servers
			servers, _ = r.Cache.GetZoneRR(zone)
		}
		cancel()
	}

	return nil, ErrReferralLimitExceeded
}

func (r *Resolver) resolveQ(q dns.Question, depth int) (*dns.Msg, error) {
	return r.resolveQContext(context.Background(), q, depth)
}

func (r *Resolver) resolveQContext(ctx context.Context, q dns.Question, depth int) (*dns.Msg, error) {
	if depth >= maxResolveDepth {
		return nil, ErrResolveDepthExceeded
	}

	answer := make([]dns.RR, 0, 10)
	visitedAliases := make(map[string]bool)
	for range 20 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := r.handleRefferencesContext(ctx, q, depth)

		if err != nil {
			return nil, err
		}
		r.logger.Debug("Referral resolution completed", "resp", resp)
		// went for cname resolution, had negative rcode gotta copy at least what we have already resolved
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			resp.Answer = append(answer, resp.Answer...)
			return resp, nil
		}

		//analyze results
		answer = append(answer, resp.Answer...)

		if q.Qtype == dns.TypeCNAME {
			return resp, nil
		}

		var cnameTarget string
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == q.Qtype {
				resp.Answer = answer
				return resp, nil
			}
			if cname, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(cname.Hdr.Name) == dns.CanonicalName(q.Name) {
				cnameTarget = dns.CanonicalName(cname.Target)
			}
		}
		if cnameTarget != "" {
			if visitedAliases[cnameTarget] {
				return nil, notFoundErr
			}
			visitedAliases[cnameTarget] = true
			q.Name = cnameTarget
			r.logger.Debug("Resolving CNAME", "target", q.Name)
			continue
		}
		resp.Answer = answer
		return resp, nil
	}

	return nil, notFoundErr
}

func (r *Resolver) handleAll(w dns.ResponseWriter, m *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(m)

	if len(m.Question) != 1 {
		msg.Rcode = dns.RcodeFormatError
	} else {
		q := m.Question[0]
		started := time.Now()
		if !r.isDomainAllowed(q.Name) {
			msg.Rcode = dns.RcodeNameError
			msg.Ns = append(msg.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: blockedResponseTTL},
				Ns:      "ns.deepdive.invalid.",
				Mbox:    "hostmaster.deepdive.invalid.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  blockedResponseTTL,
			})
			r.recordRequest("client", w.RemoteAddr().Network(), w.RemoteAddr().String(), q, dns.RcodeToString[dns.RcodeNameError], time.Since(started))
		} else {
			resp, err := r.resolveQ(q, 0)
			result := dns.RcodeToString[dns.RcodeServerFailure]
			if err != nil {
				msg.Rcode = dns.RcodeServerFailure
				slog.Error("Got err during resolve: ", "err", err)
			} else {
				msg.Rcode = resp.Rcode
				msg.Answer = append(msg.Answer, resp.Answer...)
				msg.Ns = append(msg.Ns, resp.Ns...)
				for _, rr := range resp.Extra {
					if rr.Header().Rrtype != dns.TypeOPT {
						msg.Extra = append(msg.Extra, rr)
					}
				}
				result = dns.RcodeToString[resp.Rcode]
			}
			r.recordRequest("client", w.RemoteAddr().Network(), w.RemoteAddr().String(), q, result, time.Since(started))
		}
	}

	if w.RemoteAddr().Network() == "udp" {
		size := dns.MinMsgSize

		if opt := m.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}

		msg.Truncate(size)
	}
	if err := w.WriteMsg(msg); err != nil {
		slog.Error("WriteMsg failed: ", "err: ", err)
	}
}

func (r *Resolver) isDomainAllowed(domain string) bool {
	return r.DomainPolicy == nil || r.DomainPolicy.IsAllowed(domain)
}

func main() {
	certFile := flag.String("cert", "/etc/fullchain.pem", "TLS certificate chain")
	privKeyFile := flag.String("privkey", "/etc/privkey.pem", "TLS private key")
	host := flag.String("bind", "127.0.0.1:5356", "DNS server bind address")
	adminUser := flag.String("admin-user", "admin", "Admin dashboard username")
	adminPassword := flag.String("admin-password", "", "Admin dashboard password; empty disables the dashboard")
	adminHost := flag.String("admin-bind", "127.0.0.1:8080", "Admin dashboard bind address")
	policyToken := flag.String("policy-token", "", "Policy API token; empty disables the API")
	policyHost := flag.String("policy-bind", "127.0.0.1:8081", "Policy API bind address")
	flag.Parse()

	udpServer := dns.Server{Addr: *host, Net: "udp"}
	history := NewRequestHistory(500)
	policy, err := NewDomainPolicy()
	if err != nil {
		slog.Error("Failed to load domain policies", "err", err)
		os.Exit(1)
	}
	resolver := &Resolver{logger: slog.Default(), Cache: NewCache(), History: history, DomainPolicy: policy}
	dns.HandleFunc(".", resolver.handleAll)
	var wg chan struct{}

	if *adminPassword == "" {
		slog.Info("Admin dashboard disabled; set -admin-password to enable it")
	} else {
		adminServer := &http.Server{
			Addr:              *adminHost,
			Handler:           newAdminHandler(history, *adminUser, *adminPassword),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("Admin dashboard failed", "err", err)
			}
		}()
		slog.Info("Started admin dashboard", "host", *adminHost, "user", *adminUser)
	}

	if *policyToken == "" {
		slog.Info("Policy API disabled; set -policy-token to enable it")
	} else {
		policyServer := newPolicyServer(*policyHost, policy, *policyToken)

		if strings.HasSuffix(*policyHost, ":443") {
			go func() {
				if err := policyServer.ListenAndServeTLS(*certFile, *privKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("Policy API failed", "err", err)
				}
			}()
		} else {
			go func() {
				if err := policyServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("Policy API failed", "err", err)
				}
			}()
		}
		slog.Info("Started policy API", "host", *policyHost)
	}

	go func() {
		err := udpServer.ListenAndServe()

		if err != nil {
			slog.Error(err.Error())
		}
		wg <- struct{}{}
	}()
	slog.Info("Started udp servers at: ", "host", *host)

	tcpTlsServer := dns.Server{Addr: *host, Net: "tcp-tls"}

	cert, err := tls.LoadX509KeyPair(*certFile, *privKeyFile)

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
		slog.Info("Started tcp tls servers at: ", "host", *host)
	} else {
		slog.Info("Couldn't start tcp tls server: ", "err", err)
	}
	<-wg
}
