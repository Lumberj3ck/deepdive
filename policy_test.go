package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDomainPolicyBlocksDomainAndSubdomains(t *testing.T) {
	policy, err := NewDomainPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Replace([]string{"Example.COM.", "example.com"}); err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{"example.com", "example.com.", "api.example.com."} {
		if policy.IsAllowed(domain) {
			t.Errorf("%q is allowed, want blocked", domain)
		}
	}
	if !policy.IsAllowed("notexample.com.") {
		t.Fatal("suffix match blocked an unrelated domain")
	}

	snapshot := policy.Snapshot()
	if snapshot.Revision != 1 {
		t.Fatalf("revision = %d, want 1", snapshot.Revision)
	}
	if len(snapshot.BlockedDomains) != 1 || snapshot.BlockedDomains[0] != "example.com" {
		t.Fatalf("blocked domains = %#v, want [example.com]", snapshot.BlockedDomains)
	}
}

func TestDomainPolicyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	policy, err := NewDomainPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Replace([]string{"blocked.example"}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewDomainPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.IsAllowed("sub.blocked.example.") {
		t.Fatal("persisted policy was not loaded")
	}
	if reloaded.Snapshot().Revision != 1 {
		t.Fatalf("reloaded revision = %d, want 1", reloaded.Snapshot().Revision)
	}
}

func TestPolicyHandlerRequiresBearerToken(t *testing.T) {
	policy, _ := NewDomainPolicy("")
	handler := newPolicyHandler(policy, "secret")

	for _, authorization := range []string{"", "secret", "Basic secret", "Bearer wrong"} {
		req := httptest.NewRequest(http.MethodGet, policyAPIPath, nil)
		req.Header.Set("Authorization", authorization)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Errorf("authorization %q: status = %d, want %d", authorization, resp.Code, http.StatusUnauthorized)
		}
	}
}

func TestPolicyHandlerReplacesAndReadsBlocklist(t *testing.T) {
	policy, _ := NewDomainPolicy("")
	handler := newPolicyHandler(policy, "secret")

	put := httptest.NewRequest(http.MethodPut, policyAPIPath, strings.NewReader(`{"blocked_domains":["B.example.","a.example"]}`))
	put.Header.Set("Authorization", "Bearer secret")
	putResponse := httptest.NewRecorder()
	handler.ServeHTTP(putResponse, put)
	if putResponse.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d: %s", putResponse.Code, http.StatusOK, putResponse.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, policyAPIPath, nil)
	get.Header.Set("Authorization", "Bearer secret")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", getResponse.Code, http.StatusOK)
	}
	var document policyDocument
	if err := json.NewDecoder(getResponse.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Revision != 1 || strings.Join(document.BlockedDomains, ",") != "a.example,b.example" {
		t.Fatalf("unexpected policy document: %#v", document)
	}
}

func TestResolverRefusesBlockedDomain(t *testing.T) {
	policy, _ := NewDomainPolicy("")
	if _, err := policy.Replace([]string{"blocked.example"}); err != nil {
		t.Fatal(err)
	}
	resolver := &Resolver{History: NewRequestHistory(10), DomainPolicy: policy}
	request := new(dns.Msg)
	request.SetQuestion("blocked.example.", dns.TypeA)
	writer := &recordingDNSWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5356},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}

	resolver.handleAll(writer, request)
	if writer.message == nil {
		t.Fatal("resolver did not write a DNS response")
	}
	if writer.message.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[writer.message.Rcode])
	}
	if events := resolver.History.Snapshot(); len(events) != 1 || events[0].Result != "REFUSED" {
		t.Fatalf("unexpected request history: %#v", events)
	}
}

type recordingDNSWriter struct {
	local   net.Addr
	remote  net.Addr
	message *dns.Msg
}

func (w *recordingDNSWriter) LocalAddr() net.Addr             { return w.local }
func (w *recordingDNSWriter) RemoteAddr() net.Addr            { return w.remote }
func (w *recordingDNSWriter) WriteMsg(message *dns.Msg) error { w.message = message.Copy(); return nil }
func (w *recordingDNSWriter) Write([]byte) (int, error)       { return 0, nil }
func (w *recordingDNSWriter) Close() error                    { return nil }
func (w *recordingDNSWriter) TsigStatus() error               { return nil }
func (w *recordingDNSWriter) TsigTimersOnly(bool)             {}
func (w *recordingDNSWriter) Hijack()                         {}
