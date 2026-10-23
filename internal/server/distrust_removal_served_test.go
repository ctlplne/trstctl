// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// eMudhra, Part 4 Done-when: a host trust store holding emSign ECC Root CA -
// G3 shows a finding, and the operator can remove the root through trust
// distribution where the host profile allows it. The control plane queues the
// exact removal for the agent that found it; the agent's executor reads the
// file, matches its own distrust list and removes exactly those bytes; the
// signed result lands on the receipt. A bundle is refused and left alone.
func TestServedDistrustedRootIsRemovedFromTheHostTrustStore(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, relay.KindTrustDistribute)
	registerInventoryAgent(t, h.client)
	writer := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read")

	emsign, err := os.ReadFile(filepath.Join("..", "keyposture", "testdata", "emsign-ecc-root-ca-g3.pem")) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := os.ReadFile(filepath.Join("..", "keyposture", "testdata", "ecdsa-p256-ordinary.pem")) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(emsign)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := certinfo.Inspect(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	single := filepath.Join(store, "emSign_ECC_Root_CA_-_G3.crt")
	bundle := filepath.Join(store, "ca-certificates.crt")
	cleanPath := filepath.Join(store, "internal-root.crt")
	for path, data := range map[string][]byte{single: emsign, bundle: append(append([]byte{}, ordinary...), emsign...), cleanPath: ordinary} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	anchor := func(path string, cert certinfo.Info) transport.InventoryFinding {
		return transport.InventoryFinding{
			Kind: "trust-store", Ref: "os/" + path, Provenance: "trust-store:os/" + path,
			Fingerprint: cert.SHA256Fingerprint, RiskScore: 20,
			Metadata: map[string]string{"subject": cert.Subject, "spki_sha256": cert.SPKISHA256,
				"trust_store_kind": "os", "private_key_present": "false"},
		}
	}
	inv, err := h.client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "trust-store",
		Findings: []transport.InventoryFinding{anchor(single, info), anchor(bundle, info), anchor(cleanPath, clean)}})
	if err != nil || inv.Recorded != 3 {
		t.Fatalf("report trust store: %+v %v", inv, err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, reader, nil)
	if status != http.StatusOK {
		t.Fatalf("list findings: %d %s", status, body)
	}
	var listed struct {
		Items []struct {
			ID  string `json:"id"`
			Ref string `json:"ref"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	findingFor := map[string]string{}
	for _, item := range listed.Items {
		findingFor[item.Ref] = item.ID
	}

	remove := func(path, fingerprint, key string) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h.servedHarness, http.MethodPost,
			"/api/v1/discovery/findings/"+findingFor["os/"+path]+"/remove-distrusted-root", writer, key,
			map[string]any{"fingerprint": fingerprint, "anchor_path": path, "reason": "emSign ECC Root CA - G3 distrusted"})
	}
	// A root the distrust list does not name, and a request whose reviewed path
	// differs from the finding, are refused before anything is queued.
	if status, body := remove(cleanPath, clean.SHA256Fingerprint, "remove-clean"); status != http.StatusUnprocessableEntity ||
		!strings.Contains(string(body), "distrust list must name this certificate itself") {
		t.Fatalf("undistrusted root = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/discovery/findings/"+findingFor["os/"+single]+"/remove-distrusted-root", writer, "remove-wrong-path",
		map[string]any{"fingerprint": info.SHA256Fingerprint, "anchor_path": cleanPath}); status != http.StatusConflict {
		t.Fatalf("mismatched path = %d %s", status, body)
	}

	status, body = remove(single, info.SHA256Fingerprint, "remove-emsign")
	var receipt struct {
		ID          string `json:"id"`
		OutboxID    int64  `json:"outbox_id"`
		Destination string `json:"destination"`
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.Status != "trust_anchor_removal_queued" ||
		receipt.Destination != relay.KindTrustDistribute || receipt.OutboxID == 0 || receipt.Fingerprint != info.SHA256Fingerprint {
		t.Fatalf("queue removal = %d %s", status, body)
	}
	if status, again := remove(single, info.SHA256Fingerprint, "remove-emsign"); status != http.StatusAccepted || string(again) != string(body) {
		t.Fatalf("replay = %d %s", status, again)
	}

	// Only the agent that found the root claims it, and the intent carries no
	// certificate bytes: the host reads its own file.
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindTrustDistribute}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != receipt.OutboxID {
		t.Fatalf("claim = %+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	var intent relay.TrustDistributionIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Operation != relay.TrustRemoveDistrusted ||
		intent.FindingID != findingFor["os/"+single] || intent.AnchorPath != single || len(intent.AnchorPEM) != 0 ||
		intent.RequiredAgentID != agentRowID(h.tenant, h.agent) {
		t.Fatalf("intent = %+v err=%v", intent, err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{store}}
	result, err := relay.ExecuteDistrustedRootRemoval(profile, intent)
	if err != nil || result.State != relay.DistrustRemovalRemoved {
		t.Fatalf("host removal = %+v err=%v", result, err)
	}
	if _, err := os.Stat(single); !os.IsNotExist(err) {
		t.Fatalf("the root file remains: %v", err)
	}
	detail, _ := json.Marshal(result)
	if res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(detail), result.Digest())); err != nil || !res.Accepted {
		t.Fatalf("report = %+v err=%v", res, err)
	}
	final, err := h.store.GetConnectorDeliveryReceiptForOutbox(ctx, h.tenant, receipt.OutboxID)
	if err != nil || final.Status != "trust_anchor_removed" || !strings.Contains(final.Reason, "emSign ECC Root CA - G3") ||
		!strings.Contains(final.Detail, `"state":"removed"`) {
		t.Fatalf("final receipt = %+v err=%v", final, err)
	}

	// The bundle's copy of the same root is refused and the bundle left whole.
	status, body = remove(bundle, info.SHA256Fingerprint, "remove-bundle")
	var queued struct {
		OutboxID int64 `json:"outbox_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("queue bundle removal = %d %s", status, body)
	}
	claimed, err = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindTrustDistribute}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != queued.OutboxID {
		t.Fatalf("claim bundle = %+v err=%v", claimed, err)
	}
	if err := json.Unmarshal(claimed.Jobs[0].Payload, &intent); err != nil {
		t.Fatal(err)
	}
	result, err = relay.ExecuteDistrustedRootRemoval(profile, intent)
	if err != nil || result.State != relay.DistrustRemovalBundle {
		t.Fatalf("bundle removal = %+v err=%v", result, err)
	}
	detail, _ = json.Marshal(result)
	if res, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, claimed.Jobs[0].JobID, claimed.Jobs[0].Attempt,
		transport.JobOutcomeExecuted, string(detail), result.Digest())); err != nil || !res.Accepted {
		t.Fatalf("report bundle = %+v err=%v", res, err)
	}
	refused, err := h.store.GetConnectorDeliveryReceiptForOutbox(ctx, h.tenant, queued.OutboxID)
	if err != nil || refused.Status != "trust_anchor_removal_refused" || !strings.Contains(refused.Reason, "trust tool") {
		t.Fatalf("bundle receipt = %+v err=%v", refused, err)
	}
	if data, err := os.ReadFile(bundle); err != nil || !strings.Contains(string(data), "BEGIN CERTIFICATE") { // #nosec G304 -- the test's own temporary file (CWE-22)
		t.Fatalf("the bundle was touched: %v", err)
	}
}
