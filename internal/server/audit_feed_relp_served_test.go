// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/relp"
	"trstctl.com/trstctl/internal/relp/relptest"
)

// P5-L3: a syslog feed whose endpoint is relp+tls:// delivers over RELP, and
// the receiver acknowledges every message. A receiver that refuses one
// message leaves the batch retrying, not delivered; once it takes the batch,
// the feed is delivered with every message acknowledged in sequence order,
// ending in the chain trailer, the retry repeating what was taken before.
func TestServedSyslogAuditFeedOverRELPIsAcknowledgedP5L3(t *testing.T) {
	restore := syslogFeedTimeout
	syslogFeedTimeout = 5 * time.Second
	t.Cleanup(func() { syslogFeedTimeout = restore })
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L3_CA"}
	})
	t.Setenv("TRSTCTL_P5L3_CA", string(h.caPEM))
	receiver := &relptest.Receiver{Answer: func(session, n int, _ []byte) int {
		if session == 1 && n == 2 {
			return 500
		}
		return 200
	}}
	port := serveP5L3RELP(t, h, receiver)
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l3-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	const feedID = "50505050-5050-4505-8505-505050505531"
	putAuditFeedAUD52(t, h, token, feedID, map[string]any{
		"name": "P5-L3 RELP", "provider": "syslog", "endpoint_url": "relp+tls://localhost:" + port,
		"token_ref": "env:TRSTCTL_P5L3_CA", "interval_seconds": 300, "batch_size": 50, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
	})
	if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/50505050-5050-4505-8505-505050505532", token, "p5l3-no-port", map[string]any{
		"name": "P5-L3 RELP without a port", "provider": "syslog", "endpoint_url": "relp+tls://localhost",
		"interval_seconds": 300, "batch_size": 50, "enabled": true,
	}); status != http.StatusBadRequest {
		t.Fatalf("a relp+tls endpoint without a port: HTTP %d %s, want 400", status, body)
	}
	for i := 0; i < 2; i++ {
		name := "P5-L3 team " + strconv.FormatInt(time.Now().UnixNano(), 10)
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l3-"+name, map[string]any{
			"kind": "team", "name": name, "email": "p5l3@example.test",
		}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed an audit record: HTTP %d %s", status, body)
		}
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
	assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), feedID, "retrying", 0)
	// The feed sends ahead of the answers (its window), so the receiver may
	// have taken messages after the refused one too; never the refused one.
	first := receiver.Messages()
	if len(first) < 1 {
		t.Fatal("the receiver acknowledged nothing before the refusal")
	}

	// The receiver takes the retried batch whole.
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), feedID, "delivered", 1)
	batch := receiver.Messages()[len(first):]
	if len(batch) < 3 || string(batch[0]) != string(first[0]) {
		t.Fatalf("the retry delivered %d messages; want the whole batch, starting with the repeat", len(batch))
	}
	for _, msg := range first {
		if string(msg) == string(batch[1]) {
			t.Fatal("the receiver took the message it refused")
		}
	}
	var last uint64
	for i, msg := range batch {
		_, body, ok := strings.Cut(string(msg), " trstctl-audit - ")
		var rec struct {
			Sequence uint64 `json:"sequence"`
			Type     string `json:"type"`
		}
		if !ok || !strings.HasPrefix(string(msg), "<110>1 ") || json.Unmarshal([]byte(body), &rec) != nil {
			t.Fatalf("message %d is not the feed's RFC 5424 record: %q", i+1, msg)
		}
		if i == len(batch)-1 {
			if rec.Type != "trstctl.audit.chain_trailer" {
				t.Fatalf("the batch ends with %q, want the chain trailer", rec.Type)
			}
			break
		}
		if rec.Sequence <= last {
			t.Fatalf("message %d has sequence %d after %d", i+1, rec.Sequence, last)
		}
		last = rec.Sequence
	}
	if v := receiver.Violations(); len(v) != 0 {
		t.Fatalf("the feed broke RELP: %v", v)
	}
	t.Logf("P5L3_RELP_OK sessions=%d refused_session_acks=%d batch=%d window=%d", receiver.Sessions(), len(first), len(batch), relp.Window)
}

// serveP5L3RELP runs receiver behind TLS with a certificate the harness CA
// issued for localhost and returns its port.
func serveP5L3RELP(t *testing.T, h *servedHarness, receiver *relptest.Receiver) string {
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
	certFile, keyFile := filepath.Join(dir, "relp.crt"), filepath.Join(dir, "relp.key")
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
	ln := cert.Listener(raw)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go receiver.Serve(conn)
		}
	}()
	_, port, _ := net.SplitHostPort(raw.Addr().String())
	return port
}
