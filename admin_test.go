package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestHistoryIsBoundedAndNewestFirst(t *testing.T) {
	history := NewRequestHistory(2)
	history.Add(RequestEvent{Name: "first.example."})
	history.Add(RequestEvent{Name: "second.example."})
	history.Add(RequestEvent{Name: "third.example."})

	events := history.Snapshot()
	if len(events) != 2 {
		t.Fatalf("history length = %d, want 2", len(events))
	}
	if events[0].Name != "third.example." || events[1].Name != "second.example." {
		t.Fatalf("unexpected history order: %#v", events)
	}
}

func TestAdminHandlerRequiresBasicAuth(t *testing.T) {
	handler := newAdminHandler(NewRequestHistory(10), "admin", "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
	if resp.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

func TestAdminHandlerRendersHistory(t *testing.T) {
	history := NewRequestHistory(10)
	history.Add(RequestEvent{
		At:        time.Date(2026, time.August, 6, 12, 30, 0, 0, time.UTC),
		Direction: "upstream",
		Network:   "udp",
		Peer:      "192.0.2.1",
		Name:      "example.org.",
		QType:     "A",
		Result:    "NOERROR",
		Duration:  10 * time.Millisecond,
	})
	handler := newAdminHandler(history, "admin", "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "example.org.") {
		t.Fatal("dashboard does not contain request history")
	}
}
