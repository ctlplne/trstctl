// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// eMudhra, Part 4 Done-when (served): two moduli sharing a prime are found.
// Agents report RSA certificates' public keys; the leader's batch-GCD audit
// runs over the tenant's distinct RSA keys and records a weak-key finding at
// each place a factorable key appears, as one audit run. A key reported under
// another certificate's key hash is not used.
func TestServedWeakKeyAuditFindsKeysThatShareAPrime(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a, err := enrollAgent(t, h, "edge-agent-batch-gcd", "agent.trstctl.local").Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	registerInventoryAgent(t, client)

	shareA, shareB, err := weakkeytest.SharedPrimeRSASPKIs(1024)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, _, err := weakkeytest.SharedPrimeRSASPKIs(1024)
	if err != nil {
		t.Fatal(err)
	}
	certFinding := func(path string, spki []byte, fingerprint string) transport.InventoryFinding {
		return transport.InventoryFinding{
			Kind: "x509_certificate", Ref: path, Provenance: "filesystem:" + path, Fingerprint: fingerprint, RiskScore: 10,
			Metadata: map[string]string{"subject": "CN=" + path, "spki_sha256": crypto.SHA256Hex(spki),
				"rsa_spki": base64.StdEncoding.EncodeToString(spki)},
		}
	}
	pinned := certFinding("/etc/ssl/pinned.pem", shareA, strings.Repeat("d", 64))
	pinned.Metadata["spki_sha256"] = crypto.SHA256Hex(unrelated) // claims shareA's key under another key's hash
	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem", Findings: []transport.InventoryFinding{
		certFinding("/etc/ssl/a.pem", shareA, strings.Repeat("a", 64)),
		certFinding("/etc/ssl/b.pem", shareB, strings.Repeat("b", 64)),
		certFinding("/etc/ssl/unrelated.pem", unrelated, strings.Repeat("c", 64)),
		pinned,
	}})
	if err != nil || inv.Recorded != 4 {
		t.Fatalf("report inventory: %+v %v", inv, err)
	}

	rep, err := h.srv.AuditTenantSharedFactors(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Distinct != 3 || len(rep.Shared) != 2 {
		t.Fatalf("audit report = %+v; want three distinct keys, two sharing a prime", rep)
	}
	findings, err := h.store.ListDiscoveryFindingsPage(ctx, h.tenant, "", store.ZeroUUID, 500)
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]map[string]any{}
	pinnedKept := true
	for _, f := range findings {
		meta := map[string]any{}
		_ = json.Unmarshal(f.Metadata, &meta)
		if f.Kind == orchestrator.WeakKeyFindingKind {
			flagged[f.Fingerprint] = meta
		}
		if f.Ref == "/etc/ssl/pinned.pem" {
			_, pinnedKept = meta["rsa_spki"]
		}
	}
	if len(flagged) != 2 || flagged[strings.Repeat("a", 64)] == nil || flagged[strings.Repeat("b", 64)] == nil {
		t.Fatalf("weak-key findings = %v; want the two keys sharing a prime", flagged)
	}
	for fp, meta := range flagged {
		reason, _ := meta["key_weak_reason"].(string)
		if meta["key_strength"] != "weak" || !strings.Contains(reason, "shares a prime with 1 other key") {
			t.Fatalf("finding %s metadata = %v", fp, meta)
		}
	}
	if pinnedKept {
		t.Fatal("a key reported under another key's hash was kept for the audit")
	}
	runs, err := h.store.ListDiscoveryRunsPage(ctx, h.tenant, store.ZeroUUID, 500)
	if err != nil {
		t.Fatal(err)
	}
	audited := false
	for _, run := range runs {
		if run.RequestedBy == "system:weak-key-audit" && run.Status == "succeeded" && run.Targets == 3 && run.Discovered == 2 {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("no succeeded audit run over three keys with two findings: %+v", runs)
	}
}

// TestServedWeakKeyAuditRunsNowWhenAnOperatorAsksAUDO1 is AUD-O1: an operator
// runs the weak-key audit now instead of waiting for the six-hourly sweep.
// The request queues one run on the audit's own source, a second request
// while it is queued answers with that same run, and the control plane runs
// the audit as that run: the keys that share a prime become findings on it,
// under the operator's name. Once it has finished, another request queues a
// new run.
func TestServedWeakKeyAuditRunsNowWhenAnOperatorAsksAUDO1(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a, err := enrollAgent(t, h, "edge-agent-audit-now", "agent.trstctl.local").Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	registerInventoryAgent(t, client)
	shareA, shareB, err := weakkeytest.SharedPrimeRSASPKIs(1024)
	if err != nil {
		t.Fatal(err)
	}
	finding := func(path string, spki []byte, fingerprint string) transport.InventoryFinding {
		return transport.InventoryFinding{Kind: "x509_certificate", Ref: path, Provenance: "filesystem:" + path, Fingerprint: fingerprint, RiskScore: 10,
			Metadata: map[string]string{"subject": "CN=" + path, "spki_sha256": crypto.SHA256Hex(spki), "rsa_spki": base64.StdEncoding.EncodeToString(spki)}}
	}
	if inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem", Findings: []transport.InventoryFinding{
		finding("/etc/ssl/now-a.pem", shareA, strings.Repeat("e", 64)), finding("/etc/ssl/now-b.pem", shareB, strings.Repeat("f", 64)),
	}}); err != nil || inv.Recorded != 2 {
		t.Fatalf("report inventory: %+v %v", inv, err)
	}
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "aud-o1-operator", "discovery:read", "discovery:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "aud-o1-reader", "discovery:read")
	runNow := func(token, key string) (int, map[string]any) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/weak-key-audit/runs", token, key, nil)
		var run map[string]any
		_ = json.Unmarshal(body, &run)
		return status, run
	}
	if status, _ := runNow(reader, "aud-o1-reader"); status != http.StatusForbidden {
		t.Fatalf("a reader ran the audit: %d", status)
	}
	status, first := runNow(operator, "aud-o1-first")
	if status != http.StatusAccepted || first["status"] != "queued" {
		t.Fatalf("run the audit now = %d %v", status, first)
	}
	sourceID, _ := first["source_id"].(string)
	if source, err := h.store.GetDiscoverySource(ctx, h.tenant, sourceID); err != nil || source.Kind != "weak_key_audit" || source.Name != "weak-key-audit:batch-gcd" {
		t.Fatalf("the run's source = %+v, %v; want the weak-key audit's own", source, err)
	}
	if status, again := runNow(operator, "aud-o1-again"); status != http.StatusAccepted || again["id"] != first["id"] {
		t.Fatalf("a second request while the audit is queued = %d %v, want the queued run %v", status, again, first["id"])
	}
	drainCtx, drainCancel := context.WithTimeout(ctx, time.Minute)
	defer drainCancel()
	if err := h.srv.Drain(drainCtx); err != nil {
		t.Fatal(err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, first["id"].(string))
	if err != nil || run.Status != "succeeded" || run.Targets != 2 || run.Discovered != 2 || run.RequestedBy != "aud-o1-operator" {
		t.Fatalf("the audit run = %+v, %v; want succeeded over two keys with two findings, requested by the operator", run, err)
	}
	findings, err := h.store.ListDiscoveryFindingsPage(ctx, h.tenant, "", store.ZeroUUID, 500)
	if err != nil {
		t.Fatal(err)
	}
	onRun := 0
	for _, f := range findings {
		if f.Kind == orchestrator.WeakKeyFindingKind && f.RunID == run.ID {
			onRun++
		}
	}
	if onRun != 2 {
		t.Fatalf("%d weak-key findings on the operator's run, want 2", onRun)
	}
	if status, next := runNow(operator, "aud-o1-next"); status != http.StatusAccepted || next["id"] == first["id"] || next["status"] != "queued" {
		t.Fatalf("a request after the audit finished = %d %v", status, next)
	}
}
