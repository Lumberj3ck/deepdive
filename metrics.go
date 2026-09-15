package main

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type resolverMetrics struct {
	clientRequests       *prometheus.CounterVec
	clientDuration       *prometheus.HistogramVec
	clientResponseSize   *prometheus.HistogramVec
	clientTruncated      *prometheus.CounterVec
	clientInFlight       *prometheus.GaugeVec
	answerCacheLookups   *prometheus.CounterVec
	upstreamQueries      *prometheus.CounterVec
	upstreamDuration     *prometheus.HistogramVec
	upstreamInFlight     *prometheus.GaugeVec
	resolutionErrors     *prometheus.CounterVec
	resolutionSteps      *prometheus.CounterVec
	policyBlockedQueries *prometheus.CounterVec
}

func newResolverMetrics(reg prometheus.Registerer, cache *Cache) *resolverMetrics {
	latencyBuckets := []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	m := &resolverMetrics{
		clientRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "client_requests_total",
			Help: "DNS client requests completed by transport, query type, response code, and answer source.",
		}, []string{"network", "qtype", "rcode", "source"}),
		clientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "client_request_duration_seconds",
			Help: "Time spent processing DNS client requests before writing the response.", Buckets: latencyBuckets,
		}, []string{"network", "source"}),
		clientResponseSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "client_response_size_bytes",
			Help: "Size of DNS responses sent to clients.", Buckets: prometheus.ExponentialBuckets(64, 2, 11),
		}, []string{"network", "source"}),
		clientTruncated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "client_responses_truncated_total",
			Help: "DNS client responses truncated to fit the advertised UDP size.",
		}, []string{"network"}),
		clientInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "client_requests_in_flight",
			Help: "DNS client requests currently being processed.",
		}, []string{"network"}),
		answerCacheLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "answer_cache_lookups_total",
			Help: "Answer cache lookups by result.",
		}, []string{"result"}),
		upstreamQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "upstream_queries_total",
			Help: "DNS exchanges made with upstream authoritative servers.",
		}, []string{"network", "result"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "upstream_query_duration_seconds",
			Help: "Duration of DNS exchanges with upstream authoritative servers.", Buckets: latencyBuckets,
		}, []string{"network"}),
		upstreamInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "upstream_queries_in_flight",
			Help: "Upstream DNS exchanges currently in progress.",
		}, []string{"network"}),
		resolutionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "resolution_errors_total",
			Help: "Recursive resolution failures by normalized reason.",
		}, []string{"reason"}),
		resolutionSteps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "resolution_steps_total",
			Help: "Work performed while recursively resolving client queries.",
		}, []string{"step"}),
		policyBlockedQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "policy_blocked_queries_total",
			Help: "DNS client requests blocked by domain policy.",
		}, []string{"network", "qtype"}),
	}

	reg.MustRegister(
		m.clientRequests,
		m.clientDuration,
		m.clientResponseSize,
		m.clientTruncated,
		m.clientInFlight,
		m.answerCacheLookups,
		m.upstreamQueries,
		m.upstreamDuration,
		m.upstreamInFlight,
		m.resolutionErrors,
		m.resolutionSteps,
		m.policyBlockedQueries,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "answer_cache_entries",
			Help: "Unexpired responses currently stored in the answer cache.",
		}, func() float64 { return float64(cache.answerEntryCount()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "deepdive", Subsystem: "dns", Name: "delegation_cache_entries",
			Help: "Nameserver delegations currently stored in the delegation cache.",
		}, func() float64 { return float64(cache.delegationEntryCount()) }),
	)
	return m
}

func (m *resolverMetrics) observeClient(network string, qtype uint16, rcode int, source string, started time.Time, responseSize int) {
	if m == nil {
		return
	}
	network = metricNetwork(network)
	m.clientRequests.WithLabelValues(network, metricQType(qtype), metricRcode(rcode), source).Inc()
	m.clientDuration.WithLabelValues(network, source).Observe(time.Since(started).Seconds())
	m.clientResponseSize.WithLabelValues(network, source).Observe(float64(responseSize))
}

func metricNetwork(network string) string {
	switch network {
	case udpNet, tcpNet, "tcp-tls":
		return network
	default:
		return "other"
	}
}

func metricQType(qtype uint16) string {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeANY, dns.TypeCAA, dns.TypeCNAME, dns.TypeDNSKEY,
		dns.TypeDS, dns.TypeHTTPS, dns.TypeMX, dns.TypeNS, dns.TypeNSEC, dns.TypeNSEC3,
		dns.TypePTR, dns.TypeRRSIG, dns.TypeSOA, dns.TypeSRV, dns.TypeSVCB, dns.TypeTXT:
		return dns.TypeToString[qtype]
	default:
		return "OTHER"
	}
}

func metricRcode(rcode int) string {
	if name := dns.RcodeToString[rcode]; name != "" {
		return name
	}
	return "OTHER"
}

func upstreamResult(resp *dns.Msg, err error) string {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "canceled"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		return "error"
	}
	if resp == nil {
		return "empty"
	}
	if resp.Truncated {
		return "truncated"
	}
	return metricRcode(resp.Rcode)
}

func resolutionErrorReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrReferralLimitExceeded):
		return "referral_limit"
	case errors.Is(err, ErrResolveDepthExceeded):
		return "depth_limit"
	case errors.Is(err, ErrServerNotReachable), errors.Is(err, serverNoRespErr):
		return "upstream_unreachable"
	case errors.Is(err, notFoundErr):
		return "not_found"
	default:
		return "other"
	}
}
