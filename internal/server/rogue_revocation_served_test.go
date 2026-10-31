// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/ca/venafi/venafifake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// seedRogueCTFinding records what the CT monitor records for an unexpected
// certificate: its serial, names and log position, never its bytes.
func seedRogueCTFinding(t *testing.T, h *servedHarness, info certinfo.Info) string {
	t.Helper()
	ctx, now := t.Context(), time.Now().UTC()
	sourceID, runID, findingID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	meta, err := json.Marshal(map[string]any{
		"log_url": "https://ct.example.test/log", "index": 42, "subject": info.Subject, "issuer": info.Issuer,
		"serial": info.SerialNumber, "sans": info.DNSNames, "not_after": info.NotAfter, "matched_domain": "corp.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{ID: sourceID, TenantID: h.tenant,
			Kind: "ct_log", Name: "ct-" + sourceID[:8], Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "queued", CreatedAt: now}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: findingID, TenantID: h.tenant, RunID: runID,
			SourceID: sourceID, Kind: "ct_unexpected_issuance", Ref: info.DNSNames[0], Provenance: "ct:https://ct.example.test/log",
			Fingerprint: info.SHA256Fingerprint, RiskScore: 90, Metadata: meta, DiscoveredAt: now})
	}); err != nil {
		t.Fatalf("seed the CT finding: %v", err)
	}
	return findingID
}

type rogueIssuerState struct {
	Status    string `json:"status"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason"`
}

func rogueIssuerRevocationOf(t *testing.T, h *servedHarness, token, findingID string) *rogueIssuerState {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/revocation/rogue-certificates", token, nil)
	var posture struct {
		Findings []struct {
			DiscoveryID      string            `json:"discovery_id"`
			IssuerRevocation *rogueIssuerState `json:"issuer_revocation"`
		} `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("rogue listing = %d %s", status, body)
	}
	for _, f := range posture.Findings {
		if f.DiscoveryID == findingID {
			return f.IssuerRevocation
		}
	}
	t.Fatalf("finding %s is not in the rogue listing", findingID)
	return nil
}

// A163 Done-when: a rogue certificate found in Certificate Transparency —
// issued in the tenant's own vendor account outside trstctl — is revoked at the
// CA that issued it through trstctl. The vendor confirms before the finding
// reads revoked at the issuer, a redelivery calls the vendor no second time, an
// authority that cannot revoke by serial is refused, and a serial the authority
// never issued is not reported revoked.
func TestServedRogueCertificateIsRevokedAtItsIssuer(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	vn, err := venafifake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vn.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	digi := digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(client))
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{
			{ID: "corp-digicert", Type: "digicert", Name: "Corp DigiCert", CA: digi},
			{ID: "corp-venafi", Type: "venafi", Name: "Corp Venafi", CA: venafi.New(venafi.Config{Name: "venafi", BaseURL: vn.URL(),
				AccessToken: []byte(vn.Token()), PolicyDN: vn.PolicyDN()}, venafi.WithHTTPClient(client))},
		}
	})
	registerServedTenant(t, h, "Rogue revocation tenant")
	ctx := t.Context()
	shadow, err := digi.Issue(ctx, ca.IssueRequest{TenantID: h.tenant, CSR: serverTestCSR(t, "shadow.corp.example", nil),
		DNSNames: []string{"shadow.corp.example"}, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(shadow.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	findingID := seedRogueCTFinding(t, h, info)
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	if got := rogueIssuerRevocationOf(t, h, token, findingID); got != nil {
		t.Fatalf("a fresh CT finding already reads %+v", got)
	}
	const route = "/api/v1/revocation/rogue-certificates/revoke"
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"venafi needs the certificate": {map[string]any{"discovery_id": findingID, "authority_id": "corp-venafi", "reason": "keyCompromise"}, http.StatusConflict},
		"unknown authority":            {map[string]any{"discovery_id": findingID, "authority_id": "corp-nowhere", "reason": "keyCompromise"}, http.StatusNotFound},
		"not a reason":                 {map[string]any{"discovery_id": findingID, "authority_id": "corp-digicert", "reason": "because"}, http.StatusBadRequest},
		"no such finding":              {map[string]any{"discovery_id": uuid.NewString(), "authority_id": "corp-digicert", "reason": "keyCompromise"}, http.StatusNotFound},
	} {
		if status, body := secretsReq(t, h, http.MethodPost, route, token, tc.body); status != tc.want {
			t.Errorf("%s = %d %s; want %d", name, status, body, tc.want)
		}
	}
	readOnly := seedScopedToken(t, h.store, h.tenant, "certs:read", "identities:write")
	if status, body := secretsReq(t, h, http.MethodPost, route, readOnly, map[string]any{"discovery_id": findingID, "authority_id": "corp-digicert", "reason": "keyCompromise"}); status != http.StatusForbidden {
		t.Fatalf("revoking without certs:issue = %d %s; want 403", status, body)
	}

	request := map[string]any{"discovery_id": findingID, "authority_id": "corp-digicert", "reason": "keyCompromise"}
	status, body := secretsReqKey(t, h, http.MethodPost, route, token, "a163-rogue", request)
	if status != http.StatusAccepted || !strings.Contains(string(body), `"status":"queued"`) {
		t.Fatalf("revoke the rogue certificate at its issuer = %d %s", status, body)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, route, token, "a163-rogue", request); status != http.StatusAccepted || string(replay) != string(body) {
		t.Fatalf("replayed request = %d %s; want the same queued revocation", status, replay)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, route, token, "a163-rogue-again", request); status != http.StatusConflict {
		t.Fatalf("a second revocation while one is queued = %d %s; want 409", status, body)
	}
	if got := rogueIssuerRevocationOf(t, h, token, findingID); got == nil || got.Status != "queued" || len(dc.Revocations()) != 0 {
		t.Fatalf("before delivery the finding reads %+v and DigiCert revoked %v; want queued and nothing revoked yet", got, dc.Revocations())
	}

	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	for round := 1; round <= 2; round++ {
		if err := dispatcher.Deliver(ctx, message); err != nil {
			t.Fatalf("delivery round %d: %v", round, err)
		}
		revoked := dc.Revocations()
		if len(revoked) != 1 {
			t.Fatalf("after round %d DigiCert revoked %v; want exactly the shadow certificate", round, revoked)
		}
		for _, reason := range revoked {
			if reason != "key_compromise" {
				t.Fatalf("DigiCert recorded %q; want key_compromise", reason)
			}
		}
	}
	got := rogueIssuerRevocationOf(t, h, token, findingID)
	if got == nil || got.Status != "revoked" || got.RevokedAt == "" || got.Reason != "keyCompromise" {
		t.Fatalf("after the vendor confirmed, the finding reads %+v; want revoked at the issuer", got)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, route, token, "a163-rogue-after", request); status != http.StatusConflict {
		t.Fatalf("revoking a finding already revoked at the issuer = %d %s; want 409", status, body)
	}

	// A finding whose serial this authority never issued is not reported revoked.
	stranger := info
	stranger.SerialNumber = "0badc0de0badc0de"
	strangerID := seedRogueCTFinding(t, h, stranger)
	if status, body := secretsReqKey(t, h, http.MethodPost, route, token, "a163-stranger", map[string]any{
		"discovery_id": strangerID, "authority_id": "corp-digicert", "reason": "superseded"}); status != http.StatusAccepted {
		t.Fatalf("queue the stranger = %d %s", status, body)
	}
	pending, err := h.srv.outbox.Pending(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var strangerMessage *orchestrator.Message
	for _, r := range pending {
		if r.Destination == "revocation.publish" && strings.Contains(string(r.Payload), strangerID) {
			strangerMessage = &orchestrator.Message{ID: r.ID, TenantID: h.tenant, Destination: r.Destination, Payload: r.Payload, IdempotencyKey: r.IdempotencyKey}
		}
	}
	if strangerMessage == nil {
		t.Fatal("no delivery queued for the stranger")
	}
	if err := dispatcher.Deliver(ctx, *strangerMessage); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Fatalf("delivering a serial DigiCert never issued = %v; want the authority's refusal", err)
	}
	if got := rogueIssuerRevocationOf(t, h, token, strangerID); got == nil || got.Status != "queued" || len(dc.Revocations()) != 1 {
		t.Fatalf("the stranger reads %+v with DigiCert revocations %v; want still queued and nothing new revoked", got, dc.Revocations())
	}
}
