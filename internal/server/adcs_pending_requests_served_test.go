// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedPendingADCSRequestsListedFromTheRelayReadN1L2 is N1-L2: an AD CS
// issuer's pending requests are listed from the relay's latest read of its
// CA database, newest first, with each one's template, requested name and
// requester, and marked when a trstctl issuance is held on it (N1-L1); an
// issued row's name and requester stay on the relay. A later read with
// nothing pending replaces the list. Before any read the list is empty.
func TestServedPendingADCSRequestsListedFromTheRelayReadN1L2(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	standIn, certsrv := newADCSCertsrvStandIn(t)
	standIn.mu.Lock()
	standIn.hold = true
	standIn.seq = 4300 // request ids of its own; served tests share a tenant
	standIn.mu.Unlock()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSDatabase}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
	})
	startServedOutboxPump(t, h.srv)
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue", "discovery:read", "discovery:write")
	type pendingList struct {
		CAConfig  string  `json:"ca_config"`
		ReadAt    *string `json:"read_at"`
		Truncated bool    `json:"truncated"`
		Items     []struct {
			RequestID    int    `json:"request_id"`
			Template     string `json:"template"`
			CommonName   string `json:"common_name"`
			Requester    string `json:"requester"`
			HeldIssuance bool   `json:"held_issuance"`
		} `json:"items"`
	}
	list := func() (pendingList, string) {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/external-cas/corp-adcs-web/adcs-requests", token, nil)
		var out pendingList
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("pending requests = %d %s", code, body)
		}
		return out, string(body)
	}
	if got, body := list(); got.ReadAt != nil || len(got.Items) != 0 || got.CAConfig != adcsRevocationCA {
		t.Fatalf("before any read = %s; want an empty list and no read time", body)
	}

	// A trstctl issuance the CA holds (request 4301).
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "held-n1l2.served.test", DNSNames: []string{"held-n1l2.served.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/issue", token, "n1l2-issue", map[string]any{
		"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "dns_names": []string{"held-n1l2.served.test"}, "ttl_seconds": 86400,
	}); code == http.StatusCreated {
		t.Fatalf("an issuance the CA holds completed: %s", body)
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/external-cas/corp-adcs-web/held-issues", token, nil)
		if code == http.StatusOK && strings.Contains(string(body), `"ca_request_id":4301`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the held issuance was not recorded: %d %s", code, body)
		}
	}

	// The relay reads the CA database: two pending requests, one issued row.
	view := func(rows string) string {
		dir := t.TempDir()
		data := filepath.Join(dir, "view.csv")
		header := `"Issued Request ID","Request Disposition","Serial Number","Certificate Effective Date","Certificate Expiration Date","Issued Common Name","Certificate Template","Requester Name","Revocation Date"` + "\n"
		if err := os.WriteFile(data, []byte(header+rows), 0o600); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(dir, "certutil")
		body := "#!/bin/sh\n[ \"$1\" = -config ] && [ \"$2\" = '" + adcsRevocationCA + "' ] && [ \"$3\" = -view ] || exit 2\ncat '" + data + "'\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
			t.Fatal(err)
		}
		return script
	}
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "n1l2", Status: "active",
		Executors: &transport.ExecutorReport{Version: "n1l2", Kinds: []transport.ExecutorKind{{Kind: relay.KindADCSDatabase}}}}); err != nil {
		t.Fatal(err)
	}
	read := func(key, rows string) string {
		t.Helper()
		relay.CertutilPath = view(rows)
		if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, key,
			map[string]any{"ca_config": adcsRevocationCA, "relay_agent_id": agentRowID(h.tenant, h.agent)}); code != http.StatusAccepted {
			t.Fatalf("collect %s = %d %s", key, code, body)
		}
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 || len(channel.reports) != 1 {
			t.Fatalf("production relay = %d %v reports %d", count, err, len(channel.reports))
		}
		return channel.reports[0].Detail
	}
	report := read("n1l2-read-1", `"20","20 -- Issued","1a00000020","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web20.corp.example","WebServer","CORP\svc-web20","EMPTY"
"4301","9 -- Taken Under Submission","EMPTY","EMPTY","EMPTY","held-n1l2.served.test","WebServer","CORP\svc-trstctl","EMPTY"
"4302","9 -- Taken Under Submission","EMPTY","EMPTY","EMPTY","app-b.corp.example","WebServer","CORP\carol","EMPTY"
`)
	for _, leaked := range []string{"web20", "svc-web20", "1a00000020"} {
		if strings.Contains(report, leaked) {
			t.Fatalf("the relay report carries %q from an issued row: %s", leaked, report)
		}
	}
	got, body := list()
	if got.ReadAt == nil || got.Truncated || len(got.Items) != 2 {
		t.Fatalf("after the read = %s", body)
	}
	newest, held := got.Items[0], got.Items[1]
	if newest.RequestID != 4302 || newest.Template != "WebServer" || newest.CommonName != "app-b.corp.example" || newest.Requester != `CORP\carol` || newest.HeldIssuance {
		t.Fatalf("request 4302 = %+v", newest)
	}
	if held.RequestID != 4301 || held.CommonName != "held-n1l2.served.test" || !held.HeldIssuance {
		t.Fatalf("request 4301 = %+v; want it marked held by the trstctl issuance", held)
	}

	// A later read with nothing pending replaces the list.
	read("n1l2-read-2", `"20","20 -- Issued","1a00000020","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web20.corp.example","WebServer","CORP\svc-web20","EMPTY"
`)
	if got, body := list(); got.ReadAt == nil || len(got.Items) != 0 {
		t.Fatalf("after a read with nothing pending = %s", body)
	}
}
