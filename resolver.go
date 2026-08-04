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

const retries = 2

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
	ip net.IP
	Ttl_timestamp int64
	dns.NS
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
	mu     sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		store: make(map[Zone]map[string]NS_RR),
		mu: sync.RWMutex{},
	}
}

func (c *Cache) PushZoneEntry(zone string, ns_names map[string]NS_RR){
	c.mu.Lock()
	c.store[zone] = ns_names
	c.mu.Unlock()
}

func (c *Cache) PushRREntry(zone string, ns_name string, ns_rr NS_RR){
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.store[zone]

	if !ok {
		c.store[zone] = map[string]NS_RR{}
	}

	ns_rr.Ttl_timestamp = time.Now().Unix() + int64(ns_rr.Hdr.Ttl)
	c.store[zone][ns_name] = ns_rr

}

func (c *Cache) GetZoneRR(zone string) (map[string]NS_RR, bool){
	c.mu.RLock()
	defer c.mu.RUnlock()

	z, ok := c.store[zone]
	return z, ok
}

func (c *Cache) GetNsRR(zone string, ns_name string) (NS_RR, bool){
	c.mu.RLock()
	defer c.mu.RUnlock()

	z, ok := c.store[zone]
	if !ok {
		return NS_RR{}, false
	}

	nsrr, ok := z[ns_name]
	return nsrr, ok
}

func (c *Cache) CleanEntry(zone string, ns_name string) error {
	if _, ok := c.store[zone]; !ok {
		return fmt.Errorf("Zone to clean doesn't exists")
	}

	c.mu.Lock()
	delete(c.store[zone], ns_name)
	c.mu.Unlock()
	return nil
}

func (c *Cache) updateNsRR(zone string, ns_name string, updated NS_RR) {
	if _, ok := c.store[zone]; !ok {
		c.store[zone] = map[string]NS_RR{}
	}
	
	t := time.Now()
	updated.Hdr.Ttl = uint32(t.Unix()) + updated.Hdr.Ttl
	c.store[zone][ns_name] = updated
}

func (c *Cache) getClosestZone(name string) string {
	// www.apple.com
	var clossestZone string

	var currMatch int
	for zone := range c.store {
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


func (r *Resolver) GetNextServer(zone string, servers map[string]NS_RR, visited map[string]bool) (net.IP, string, error) {
	var serverIP net.IP
	var nsDomainName string
	for domainName, server_RR := range servers {
		if visited[domainName] {
			continue
		}
		if server_RR.Ttl_timestamp < time.Now().Unix() && server_RR.Ttl_timestamp != 0{
			r.logger.Info("Outdated cache entry")
			r.Cache.CleanEntry(zone, domainName)
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
		// r.Cache["."] = safeBelt
		r.Cache.PushZoneEntry(".", safeBelt)
	}

	var visited = make(map[string]bool)
	r.logger.Info("Got closest zone: ", "zone", zone)
	servers, _ := r.Cache.GetZoneRR(zone)

	for {
		// it will try to resolve one, if can't it will try to resolve next
		serverIP, nsReff, err := r.GetNextServer(zone, servers, visited)

		if err == ErrNoNsRefferences{
			return nil, fmt.Errorf("Failed to resolve NS refferences")
		}

		if err == ErrNoKnownNsEndpoint{
			// or AAAA
			resp, err := r.resolveQ(dns.Question{Name: nsReff, Qtype: dns.TypeA, Qclass: dns.ClassINET}, 0)
			if err != nil{
				r.logger.Warn("Got err during resolve of NS: ", "err", err)
				visited[nsReff] = true
				continue
			}

			for _, rr := range resp {
				// or AAAA
				if rr, ok := rr.(*dns.A); ok {
					s := servers[nsReff]
					s.ip = rr.A
					s.Hdr.Ttl = rr.Hdr.Ttl

					servers[nsReff] = s
					// r.Cache[zone] = servers
					r.Cache.updateNsRR(zone, nsReff, s)
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
						gluedRefferences[rr.Ns] = NS_RR{NS: *rr, ip: extra_rr.A}
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
				if rr_exists && cachedNsRR.ip != nil{
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


	// handle refferences.
	// 		check if further refference
	//      add cache
	//      if no cache, handle refferences till the end.
	//  	analyze answer from the resolve refferences func
	//  	if cname retry
	// analyze

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

func handleAll(w dns.ResponseWriter, m *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(m)
	resolver := Resolver{slog.Default(), NewCache()}

	for _, q := range m.Question {
		rr, err := resolver.resolveQ(q, 0)
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
	dns.HandleFunc(".", handleAll)
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
