// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A real short-lived server certificate makes elapsed-time renewal observable;
// neither the host clock nor the client's chain/hostname verification changes.
func TestAgentServerListenersRemainUsableAfterCertificateExpiry(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	const name = "server-renewal-proof"
	identity := bootstrapAgentIdentityForHTTPRenewal(t, h, name)
	t.Cleanup(identity.Destroy)
	csr := newAgentCSR(t, name)
	body, err := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csr)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listeners := make([]net.Listener, 2)
	for i := range listeners {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = ln
	}
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		h.srv.serveAgentChannelWithLifetime(ctx, listeners[0], 6*time.Second)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		h.srv.serveAgentHTTPRenewalWithLifetime(ctx, listeners[1], 6*time.Second)
	}()
	t.Cleanup(func() { cancel(); <-done; <-done })
	heartbeat := func() error {
		creds, err := mtls.AgentClientCredentials(identity, h.srv.AgentCACertPEM(), "localhost", nil)
		if err != nil {
			return err
		}
		conn, err := transport.Dial(listeners[0].Addr().String(), creds)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		callCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		_, err = transport.NewAgentClient(conn).Heartbeat(callCtx, &transport.HeartbeatRequest{AgentID: name, Version: "test", Status: "active"})
		return err
	}
	renewal := func() error {
		client := agentHTTPRenewalClient(t, h, identity)
		defer client.CloseIdleConnections()
		code, data, err := postHTTPRenewal(client, "https://"+listeners[1].Addr().String(), body)
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("renewal status %d: %s", code, data)
		}
		return nil
	}
	for label, call := range map[string]func() error{"grpc": heartbeat, "https": renewal} {
		if err := call(); err != nil {
			t.Fatalf("initial %s: %v", label, err)
		}
	}
	// The observed expiry must really be short: a mistakenly long-lived fixture
	// would make successful requests after seven seconds a vacuous renewal proof.
	assertTelemetry := func(minimumIssuances int) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.srv.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		value := func(series string) float64 {
			t.Helper()
			for _, line := range strings.Split(rec.Body.String(), "\n") {
				if raw, ok := strings.CutPrefix(line, series+" "); ok {
					n, err := strconv.ParseFloat(raw, 64)
					if err != nil {
						t.Fatalf("invalid %s: %v", series, err)
					}
					return n
				}
			}
			t.Fatalf("missing listener telemetry: %s", series)
			return 0
		}
		for _, listener := range []string{"grpc", "https"} {
			expiry := value(`trstctl_agent_server_certificate_expiry_timestamp_seconds{listener="` + listener + `"}`)
			remaining := time.Until(time.Unix(int64(expiry), 0))
			if remaining <= 0 || remaining > 7*time.Second {
				t.Fatalf("%s reports an invalid short-lived server expiry: %s", listener, remaining)
			}
			succeeded := value(`trstctl_agent_server_certificate_issuances_total{listener="` + listener + `",result="success"}`)
			if succeeded < float64(minimumIssuances) {
				t.Fatalf("%s reports only %v successful issuances after renewal", listener, succeeded)
			}
			if failed := value(`trstctl_agent_server_certificate_issuances_total{listener="` + listener + `",result="failed"}`); failed != 0 {
				t.Fatalf("%s reports unexpected failed issuance: %v", listener, failed)
			}
		}
	}
	assertTelemetry(1)
	for cycle := 1; cycle <= 2; cycle++ {
		time.Sleep(7 * time.Second)
		for label, call := range map[string]func() error{"grpc": heartbeat, "https": renewal} {
			if err := call(); err != nil {
				t.Errorf("fresh %s application request after %d certificate lifetimes: %v", label, cycle, err)
			}
		}
		assertTelemetry(cycle + 1)
	}
	// Mutual authentication remains mandatory after repeated server renewals.
	noCertificate := agentHTTPRenewalClient(t, h, nil)
	defer noCertificate.CloseIdleConnections()
	if _, _, err := postHTTPRenewal(noCertificate, "https://"+listeners[1].Addr().String(), body); err == nil {
		t.Fatal("renewed listener accepted missing client certificate")
	}
	rogueCA, err := mtls.NewCA("untrusted-renewal-client")
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := rogueCA.IssueClientCertificate(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rogueClient := agentHTTPRenewalClient(t, h, mtls.StaticSource(rogue))
	defer rogueClient.CloseIdleConnections()
	if _, _, err := postHTTPRenewal(rogueClient, "https://"+listeners[1].Addr().String(), body); err == nil {
		t.Fatal("renewed listener accepted untrusted client certificate")
	}
}
