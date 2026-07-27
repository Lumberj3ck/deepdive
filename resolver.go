package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

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
	Cache  Cache
	mu     sync.RWMutex
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
type Cache map[Zone]map[string]NS_RR

func (c Cache) getClosestZone(name string) string {
	// www.apple.com
	var clossestZone string

	var currMatch int
	for zone := range c {
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
	var visited = make(map[string]bool)
	for range 20 {
		zone := r.Cache.getClosestZone(q.Name)

		if zone == "." {
			r.Cache["."] = safeBelt
		}

		servers := r.Cache[zone]
		r.mu.Lock()
		r.logger.Info("Got closest zone: ", "zone", zone, "depth", depth)
		r.mu.Unlock()

		var serverIP net.IP
		for _, server_RR := range servers {
			if visited[server_RR.ip.String()] {
				continue
			}

			if server_RR.ip != nil {
				serverIP = server_RR.ip
				break
			}
		}
		if serverIP == nil {
			for domainName, server_RR := range servers {
				if visited[server_RR.ip.String()] {
					continue
				}

				if server_RR.ip == nil {
					q := dns.Question{Name: server_RR.Ns, Qtype: dns.TypeA, Qclass: dns.ClassINET}
					resp, err := r.resolveQ(q, depth+1)
					if err != nil {
						r.logger.Warn("Got err during resolve of NS: ", "err", err)
						continue
					}

					for _, rr := range resp {
						if rr, ok := rr.(*dns.A); ok {
							s := servers[domainName]
							s.ip = rr.A
							servers[domainName] = s
						}
					}
				}

				serverIP = servers[domainName].ip
				break
			}
		}

		if serverIP == nil {
			return nil, notFoundErr
		}

		r.mu.Lock()
		r.logger.Info("Resolved ", "server ip", serverIP, "depth", depth)
		r.mu.Unlock()

		resp, err := r.queryQ(q, serverIP.String(), udpNet)
		visited[serverIP.String()] = true
		r.logger.Info("Received after udp err ", "err", err)

		if errors.Is(err, dataTruncatedErr) || errors.Is(err, serverNoRespErr) {
			resp, err = r.queryQ(q, serverIP.String(), tcpNet)

			if err != nil {
				// Grab next nameserver refference if available
				continue
			}
		}

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

		// nodata, name exists, however not such RR type available
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && resp.Authoritative && containsSoa(resp.Ns) {
			return nil, nil
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
			r.mu.Lock()
			for _, rr := range resp.Ns {
				rr, ok := rr.(*dns.NS)
				if !ok {
					continue
				}
				_, zone_exists := r.Cache[rr.Header().Name]
				if !zone_exists {
					r.Cache[rr.Header().Name] = map[string]NS_RR{}
				}

				_, rr_exists := r.Cache[rr.Header().Name][rr.Ns]
				if rr_exists {
					continue
				}

				var nsRR NS_RR
				if _, ok := gluedRefferences[rr.Ns]; ok {
					nsRR = gluedRefferences[rr.Ns]
				} else {
					nsRR = NS_RR{NS: *rr}
				}

				r.Cache[rr.Header().Name][rr.Ns] = nsRR
			}
			r.mu.Unlock()
		}
	}

	return nil, notFoundErr
}

func handleAll(w dns.ResponseWriter, m *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(m)
	resolver := Resolver{slog.Default(), make(Cache), sync.RWMutex{}}

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

	if len(host) == 0{
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

	tcpServer := dns.Server{Addr: host, Net: "tcp"}

	go func() {
		err := tcpServer.ListenAndServe()

		if err != nil {
			slog.Error(err.Error())
		}

		wg <- struct{}{}
	}()
	slog.Info("Started tcp and udp servers at: ", "host", host)
	<-wg
}
