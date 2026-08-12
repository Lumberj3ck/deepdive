package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"database/sql"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite"
)

const policyAPIPath = "/api/v1/policies/domains"

var errPolicyRevisionConflict = errors.New("policy revision conflict")

type policyDocument struct {
	Revision       uint64          `json:"revision"`
	BlockedDomains []BlockedDomain `json:"blocked_domains"`
}

type DomainPolicy struct {
	mu       sync.RWMutex
	revision uint64
	blocked  map[string]int64
	db       *sql.DB
}

func NewDomainPolicy() (*DomainPolicy, error) {
	policy := &DomainPolicy{blocked: make(map[string]int64)}
	conn, err := sql.Open("sqlite", "policy.db")

	if err != nil {
		return nil, err
	}
	policy.db = conn

	_, err = conn.Exec("create table if not exists policies (id integer not null, primary key (id));")

	if err != nil {
		conn.Close()
		return nil, err
	}
	_, err = conn.Exec("create table if not exists blocked_domains (id integer not null, domain string not null, policy integer not null, block_since integer not null, foreign key (policy) references  policies(id), primary key (id), unique (policy, domain));")
	if err != nil {
		conn.Close()
		return nil, err
	}

	var id uint64
	err = conn.QueryRow("select coalesce(max(id), 0) from policies;").Scan(&id)
	if err != nil {
		conn.Close()
		return nil, err
	}
	policy.revision = id
	rows, err := conn.Query("select b.domain, b.block_since from policies p join blocked_domains b on (p.id = b.policy) where policy = ?", policy.revision)

	if err != nil {
		return nil, fmt.Errorf("Failed to load blocked domains: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		var block_since int64
		if err := rows.Scan(&domain, &block_since); err != nil {
			conn.Close()
			return nil, fmt.Errorf("Failed to load blocked domains: %w", err)
		}
		policy.blocked[domain] = block_since
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("Failed to load blocked domains: %w", rows.Err())
	}
	return policy, nil
}

func (p *DomainPolicy) IsAllowed(domain string) bool {
	if p == nil {
		return true
	}
	domain, err := normalizeDomain(domain)
	if err != nil {
		return false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	for blocked, block_since := range p.blocked {
		if block_since > time.Now().Unix() {
			continue
		}
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return false
		}
	}
	return true
}

func (p *DomainPolicy) Snapshot() policyDocument {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domains := make([]BlockedDomain, 0, len(p.blocked))
	for domain, block_since := range p.blocked {
		domains = append(domains, BlockedDomain{domain, block_since})
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })
	return policyDocument{Revision: p.revision, BlockedDomains: domains}
}

type InvalidDomain struct {
	Err error
}

func (e *InvalidDomain) Error() string {
	return e.Err.Error()
}

func (e *InvalidDomain) Unwrap() error {
	return e.Err
}

var errDbOperation = fmt.Errorf("Failed to perform db operation")

func parseTimestamps(domains []BlockedDomain) error {
	for _, domain := range domains {
		t := time.Unix(domain.Block_since, 0)
		delta := time.Since(t)

		if delta < time.Hour*24*-1 {
			return fmt.Errorf("Maximum future domain block is 24 hours")
		}
	}
	return nil
}

func (p *DomainPolicy) Replace(domains []BlockedDomain, expectedRevision uint64) (policyDocument, error) {
	normalized, err := normalizedDomains(domains)
	if err != nil {
		return policyDocument{}, &InvalidDomain{err}
	}
	err = parseTimestamps(domains)
	if err != nil {
		return policyDocument{}, &InvalidDomain{err}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revision != expectedRevision {
		return policyDocument{}, errPolicyRevisionConflict
	}

	tx, err := p.db.BeginTx(context.Background(), nil)
	if err != nil {
		return policyDocument{}, errDbOperation
	}
	defer tx.Rollback()

	next := policyDocument{Revision: p.revision + 1, BlockedDomains: normalized}
	_, err = tx.Exec("insert into policies default values;")
	if err != nil {
		return policyDocument{}, errDbOperation
	}

	for _, domain := range normalized {
		_, err := tx.Exec("insert into blocked_domains (domain, block_since, policy) values (?, ?, ?);", domain.Domain, domain.Block_since, next.Revision)

		if err != nil {
			return policyDocument{}, errDbOperation
		}
	}

	err = tx.Commit()
	if err != nil {
		return policyDocument{}, errDbOperation
	}

	p.blocked = make(map[string]int64, len(normalized))
	for _, domain := range normalized {
		p.blocked[domain.Domain] = domain.Block_since
	}
	p.revision = next.Revision

	return next, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if _, ok := dns.IsDomainName(domain); !ok {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return domain, nil
}

func normalizedDomains(domains []BlockedDomain) ([]BlockedDomain, error) {
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]BlockedDomain, len(domains))
	for i, domain := range domains {
		domain_str, err := normalizeDomain(domain.Domain)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[domain_str]; exists {
			return nil, fmt.Errorf("duplicate domain %q", domain_str)
		}
		seen[domain_str] = struct{}{}
		normalized[i].Domain = domain_str
		normalized[i].Block_since = domain.Block_since
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Domain < normalized[j].Domain })
	return normalized, nil
}

type BlockedDomain struct {
	Domain      string `json:"domain"`
	Block_since int64  `json:"block_since"`
}

func newPolicyHandler(policy *DomainPolicy, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(policyAPIPath, func(w http.ResponseWriter, req *http.Request) {
		authorization := req.Header.Get("Authorization")
		providedToken, found := strings.CutPrefix(authorization, "Bearer ")
		if !found || providedToken == "" || subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
			writePolicyError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		switch req.Method {
		case http.MethodGet:
			writePolicyJSON(w, http.StatusOK, policy.Snapshot())
		case http.MethodPut:
			req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
			decoder := json.NewDecoder(req.Body)
			decoder.DisallowUnknownFields()
			var update struct {
				Revision       *uint64         `json:"revision"`
				BlockedDomains []BlockedDomain `json:"blocked_domains"`
			}
			if err := decoder.Decode(&update); err != nil {
				writePolicyError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				writePolicyError(w, http.StatusBadRequest, "body must contain one JSON object")
				return
			}
			if update.Revision == nil {
				writePolicyError(w, http.StatusBadRequest, "revision is required")
				return
			}
			if update.BlockedDomains == nil {
				writePolicyError(w, http.StatusBadRequest, "blocked domains is required")
				return
			}
			document, err := policy.Replace(update.BlockedDomains, *update.Revision)
			if errors.Is(err, errPolicyRevisionConflict) {
				writePolicyError(w, http.StatusConflict, err.Error())
				return
			}
			var inErr *InvalidDomain
			if errors.As(err, &inErr) {
				writePolicyError(w, http.StatusBadRequest, inErr.Error())
				return
			}
			if err != nil {
				writePolicyError(w, http.StatusInternalServerError, "failed to save policies")
				return
			}
			writePolicyJSON(w, http.StatusOK, document)
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
			writePolicyError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	return mux
}

func newPolicyServer(address string, policy *DomainPolicy, token string) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           newPolicyHandler(policy, token),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func writePolicyJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writePolicyError(w http.ResponseWriter, status int, message string) {
	writePolicyJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}
