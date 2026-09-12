package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)


func main() {
	certFile := flag.String("cert", "/etc/fullchain.pem", "TLS certificate chain")
	privKeyFile := flag.String("privkey", "/etc/privkey.pem", "TLS private key")
	host := flag.String("bind", "127.0.0.1:5356", "DNS server bind address")
	adminUser := flag.String("admin-user", "admin", "Admin dashboard username")
	adminPassword := flag.String("admin-password", "", "Admin dashboard password; empty disables the dashboard")
	adminHost := flag.String("admin-bind", "127.0.0.1:8080", "Admin dashboard bind address")
	policyToken := flag.String("policy-token", "", "Policy API token; empty disables the API")
	policyHost := flag.String("policy-bind", "127.0.0.1:8081", "Policy API bind address")

	startMetrics := flag.Bool("metrics", false, "Start prometheus metrics client.")
	flag.Parse()

	udpServer := dns.Server{Addr: *host, Net: "udp"}
	history := NewRequestHistory(500)
	policy, err := NewDomainPolicy()
	if err != nil {
		slog.Error("Failed to load domain policies", "err", err)
		os.Exit(1)
	}
	resolver := NewResolver()
	resolver.History = history
	resolver.DomainPolicy = policy
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

	if *startMetrics{
		reg := prometheus.NewRegistry()
		reg.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)

		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

		metricsServer := http.Server{
			Addr: ":9091",
			Handler: mux,
		}

		go func() {

			slog.Info("Started prometheus client at ", "addr", metricsServer.Addr)
			err := metricsServer.ListenAndServe()

			if err != nil {
				slog.Error(err.Error())
			}

			wg <- struct{}{}
		}()
	}


	<-wg
}
