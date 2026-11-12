// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// P5-L2: a syslog receiver that requires RFC 5425 mutual TLS receives a
// feed that presents the client certificate its client_cert_ref names. A
// feed without one is refused at the handshake and delivers nothing; the
// reference is syslog's alone and must be an operator-approved env: name.
func TestServedSyslogAuditFeedPresentsAClientCertificateP5L2(t *testing.T) {
	restore := syslogFeedTimeout
	syslogFeedTimeout = 2 * time.Second
	t.Cleanup(func() { syslogFeedTimeout = restore })
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L2_CA", "env:TRSTCTL_P5L2_CLIENT"}
	})
	receiver := newP5L2MutualSyslog(t, h)
	const clientName = "trstctl-audit-feed.p5l2.test"
	key, err := crypto.GenerateHostSubjectKey(clientName, []string{clientName})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	certPEM, err := h.srv.IssueLeaf(t.Context(), key.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_P5L2_CA", string(h.caPEM))
	t.Setenv("TRSTCTL_P5L2_CLIENT", string(certPEM)+string(keyPEM))
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l2-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	const withCert, withoutCert = "50505050-5050-4505-8505-505050505501", "50505050-5050-4505-8505-505050505502"
	feed := func(name, clientRef string) map[string]any {
		body := map[string]any{
			"name": name, "provider": "syslog", "endpoint_url": "syslog+tls://localhost:" + receiver.port,
			"token_ref": "env:TRSTCTL_P5L2_CA", "interval_seconds": 300, "batch_size": 100, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
		}
		if clientRef != "" {
			body["client_cert_ref"] = clientRef
		}
		return body
	}
	putAuditFeedAUD52(t, h, token, withCert, feed("P5-L2 mutual TLS", "env:TRSTCTL_P5L2_CLIENT"))
	putAuditFeedAUD52(t, h, token, withoutCert, feed("P5-L2 no client certificate", ""))

	// The reference is syslog's alone, an env: name, and operator-approved.
	elastic := feed("P5-L2 elastic", "env:TRSTCTL_P5L2_CLIENT")
	elastic["provider"], elastic["endpoint_url"] = "elastic", "http://127.0.0.1:9/audit/_bulk"
	for name, body := range map[string]map[string]any{
		"elastic":     elastic,
		"file":        feed("P5-L2 file", "file:/etc/trstctl/client.pem"),
		"not allowed": feed("P5-L2 unlisted", "env:TRSTCTL_P5L2_UNLISTED"),
	} {
		if status, response := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/50505050-5050-4505-8505-505050505509", token, "p5l2-refused-"+name, body); status/100 != 4 {
			t.Fatalf("%s: HTTP %d %s, want a refusal", name, status, response)
		}
	}

	ownerName := "P5-L2 team " + strconv.FormatInt(time.Now().UnixNano(), 10)
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l2-owner", map[string]any{
		"kind": "team", "name": ownerName, "email": "p5l2@example.test",
	}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed an audit record: HTTP %d %s", status, body)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	list := getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, list, withCert, "delivered", 1)
	assertAuditFeedStatusAUD52(t, list, withoutCert, "retrying", 0)
	names, refused := receiver.clients()
	if len(names) == 0 || refused == 0 {
		t.Fatalf("verified clients %v, refused handshakes %d: want the feed's certificate and one refusal", names, refused)
	}
	for _, name := range names {
		if name != clientName {
			t.Fatalf("the receiver verified client %q, want %q", name, clientName)
		}
	}
	if len(receiver.sequences()) == 0 {
		t.Fatal("the mutual-TLS receiver received no records")
	}
}

// p5L2MutualSyslog is a syslog receiver that requires a client certificate
// issued by the harness CA, reading frames as P5's receiver does.
type p5L2MutualSyslog struct {
	*p5Syslog
	port     string
	cmu      sync.Mutex
	verified []string
	refused  int
}

func newP5L2MutualSyslog(t *testing.T, h *servedHarness) *p5L2MutualSyslog {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey("localhost", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	certPEM, err := h.srv.IssueLeaf(t.Context(), key.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "syslog.crt"), filepath.Join(dir, "syslog.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := mtls.ServerCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := cert.ListenerRequiringClientCert(raw, h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &p5L2MutualSyslog{p5Syslog: &p5Syslog{seen: map[uint64]bool{}}}
	_, r.port, _ = net.SplitHostPort(raw.Addr().String())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				name, err := mtls.VerifiedClientCommonName(conn)
				r.cmu.Lock()
				if err != nil {
					r.refused++
				} else {
					r.verified = append(r.verified, name)
				}
				r.cmu.Unlock()
				if err != nil {
					_ = conn.Close()
					return
				}
				r.read(conn)
			}()
		}
	}()
	return r
}

func (r *p5L2MutualSyslog) clients() ([]string, int) {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return append([]string(nil), r.verified...), r.refused
}
