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
	Revision       uint64   `json:"revision"`
	BlockedDomains []string `json:"blocked_domains"`
}

type DomainPolicy struct {
	mu       sync.RWMutex
	revision uint64
	blocked  map[string]struct{}
	db 		 *sql.DB
}

func NewDomainPolicy() (*DomainPolicy, error) {
	policy := &DomainPolicy{blocked: make(map[string]struct{})}
	conn, err := sql.Open("sqlite", "policy.db")

	if err != nil{
		return nil, err
	}
	policy.db = conn

	_, err = conn.Exec("create table if not exists policies (id integer not null, primary key (id));")

	if err != nil{
		conn.Close()
		return nil, err
	}
	_, err = conn.Exec("create table if not exists blocked_domains (id integer not null, domain string not null, policy integer not null, foreign key (policy) references  policies(id), primary key (id), unique (policy, domain));")
	if err != nil{
		conn.Close()
		return nil, err
	}

	var id uint64
	err = conn.QueryRow("select coalesce(max(id), 0) from policies;").Scan(&id)
	if err != nil{
		conn.Close()
		return nil, err
	}
	policy.revision = id
	rows, err := conn.Query("select b.domain from policies p join blocked_domains b on (p.id = b.policy) where policy = ?", policy.revision);

	for rows.Next(){
		var domain string
		if err := rows.Scan(&domain); err != nil{
			conn.Close()
			return nil, fmt.Errorf("Failed to load blocked domains: %w", err)
		}
		policy.blocked[domain] = struct{}{}
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
	for blocked := range p.blocked {
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return false
		}
	}
	return true
}

func (p *DomainPolicy) Snapshot() policyDocument {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domains := make([]string, 0, len(p.blocked))
	for domain := range p.blocked {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return policyDocument{Revision: p.revision, BlockedDomains: domains}
}

type InvalidDomain struct{ 
	Err error
}

func (e *InvalidDomain) Error() string {
	return e.Err.Error()
}

func (e *InvalidDomain) Unwrap() error {
	return e.Err
}

var errDbOperation = fmt.Errorf("Failed to perform db operation")

func (p *DomainPolicy) Replace(domains []string, expectedRevision uint64) (policyDocument, error) {
	normalized, err := normalizedDomains(domains)
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
	if err != nil{

		return policyDocument{}, errDbOperation
	}

	for _, domain := range normalized{
		_, err := tx.Exec("insert into blocked_domains (domain, policy) values (?, ?);", domain, next.Revision)
		
		if err != nil{
			fmt.Println("HERE", err)
			return policyDocument{}, errDbOperation
		}
	}

	p.blocked = make(map[string]struct{}, len(normalized))
	for _, domain := range normalized {
		p.blocked[domain] = struct{}{}
	}
	p.revision = next.Revision

	err = tx.Commit()
	if err != nil{
		return policyDocument{}, errDbOperation
	}

	return next, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if _, ok := dns.IsDomainName(domain); !ok {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return domain, nil
}

func normalizedDomains(domains []string) ([]string, error) {
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain, err := normalizeDomain(domain)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	sort.Strings(normalized)
	return normalized, nil
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
				Revision       *uint64  `json:"revision"`
				BlockedDomains []string `json:"blocked_domains"`
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
			document, err := policy.Replace(update.BlockedDomains, *update.Revision)
			if errors.Is(err, errPolicyRevisionConflict) {
				writePolicyError(w, http.StatusConflict, err.Error())
				return
			}
			var inErr *InvalidDomain
			if errors.As(err, &inErr){
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
