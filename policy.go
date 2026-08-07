package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const policyAPIPath = "/api/v1/policies/domains"

type policyDocument struct {
	Revision       uint64   `json:"revision"`
	BlockedDomains []string `json:"blocked_domains"`
}

type DomainPolicy struct {
	mu       sync.RWMutex
	filePath string
	revision uint64
	blocked  map[string]struct{}
}

func NewDomainPolicy(filePath string) (*DomainPolicy, error) {
	policy := &DomainPolicy{filePath: filePath, blocked: make(map[string]struct{})}
	if filePath == "" {
		return policy, nil
	}

	data, err := os.ReadFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return policy, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var document policyDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode policy file: %w", err)
	}
	blocked, err := normalizedDomains(document.BlockedDomains)
	if err != nil {
		return nil, fmt.Errorf("decode policy file: %w", err)
	}
	policy.revision = document.Revision
	for _, domain := range blocked {
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

func (p *DomainPolicy) Replace(domains []string) (policyDocument, error) {
	normalized, err := normalizedDomains(domains)
	if err != nil {
		return policyDocument{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	next := policyDocument{Revision: p.revision + 1, BlockedDomains: normalized}
	if p.filePath != "" {
		if err := writePolicyFile(p.filePath, next); err != nil {
			return policyDocument{}, err
		}
	}
	p.blocked = make(map[string]struct{}, len(normalized))
	for _, domain := range normalized {
		p.blocked[domain] = struct{}{}
	}
	p.revision = next.Revision
	return next, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", errors.New("domain cannot be empty")
	}
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

func writePolicyFile(path string, document policyDocument) error {
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	data = append(data, '\n')

	temporary, err := os.CreateTemp(filepath.Dir(path), ".resolvy-policy-*")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set policy file permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write policy file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync policy file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close policy file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	return nil
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
			if _, err := normalizedDomains(update.BlockedDomains); err != nil {
				writePolicyError(w, http.StatusBadRequest, err.Error())
				return
			}
			document, err := policy.Replace(update.BlockedDomains)
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
