package main

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"sync"
	"time"
)

type RequestEvent struct {
	At        time.Time
	Direction string
	Network   string
	Peer      string
	Name      string
	QType     string
	Result    string
	Duration  time.Duration
}

type RequestHistory struct {
	mu     sync.RWMutex
	limit  int
	events []RequestEvent
}

func NewRequestHistory(limit int) *RequestHistory {
	return &RequestHistory{limit: limit}
}

func (h *RequestHistory) Add(event RequestEvent) {
	if h == nil || h.limit <= 0 {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.events) == h.limit {
		copy(h.events, h.events[1:])
		h.events[len(h.events)-1] = event
		return
	}
	h.events = append(h.events, event)
}

func (h *RequestHistory) Snapshot() []RequestEvent {
	if h == nil {
		return nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	events := make([]RequestEvent, len(h.events))
	for i := range h.events {
		events[len(h.events)-1-i] = h.events[i]
	}
	return events
}

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Resolvy requests</title>
<style>
body { font: 14px sans-serif; margin: 2rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: .4rem; text-align: left; }
</style>
</head>
<body>
<h1>Recent DNS requests</h1>
<p>Newest first. Refresh the page to update.</p>
<table>
<thead><tr><th>Time</th><th>Direction</th><th>Network</th><th>Peer</th><th>Name</th><th>Type</th><th>Result</th><th>Duration</th></tr></thead>
<tbody>
{{range .}}
<tr><td>{{.At.Format "2006-01-02 15:04:05.000"}}</td><td>{{.Direction}}</td><td>{{.Network}}</td><td>{{.Peer}}</td><td>{{.Name}}</td><td>{{.QType}}</td><td>{{.Result}}</td><td>{{.Duration}}</td></tr>
{{else}}
<tr><td colspan="8">No requests recorded.</td></tr>
{{end}}
</tbody>
</table>
</body>
</html>`))

func newAdminHandler(history *RequestHistory, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		providedUser, providedPassword, ok := req.BasicAuth()
		userMatches := subtle.ConstantTimeCompare([]byte(providedUser), []byte(username)) == 1
		passwordMatches := subtle.ConstantTimeCompare([]byte(providedPassword), []byte(password)) == 1
		if !ok || !userMatches || !passwordMatches {
			w.Header().Set("WWW-Authenticate", `Basic realm="resolvy admin", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := adminTemplate.Execute(w, history.Snapshot()); err != nil {
			http.Error(w, "Failed to render dashboard", http.StatusInternalServerError)
		}
	})
}
