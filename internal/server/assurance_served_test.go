// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/store"
)

// TestServedCredentialAssuranceRecordA179 is A179's served contract: a renewed,
// verified certificate's record carries every stage with evidence IDs, verifies
// offline against the audit JWK set, and a tampered copy fails.
func TestServedCredentialAssuranceRecordA179(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = time.Hour
		d.AuditSigningKey = auditKey
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read",
	)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "assurance-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	const name = "assurance.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": name, "owner_id": owner.ID,
		"attributes": map[string]any{"connector": "nginx", "target": "edge-assurance"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: %d %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &ident)
	for _, to := range []string{"issued", "deployed"} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{"to": to, "reason": "assurance fixture"})
		alreadyDeployed := to == "deployed" && status == http.StatusConflict && strings.Contains(string(body), "deployed")
		if status != http.StatusOK && !alreadyDeployed {
			t.Fatalf("transition %s: %d %s", to, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, name)
	if err != nil || len(certs) != 1 {
		t.Fatalf("issued certificates = %d, %v", len(certs), err)
	}
	predecessor := certs[0]
	window := ari.SuggestWindow(*predecessor.NotBefore, *predecessor.NotAfter, time.Now().UTC(), false)
	if queued, err := h.srv.runLifecycleOnceAt(ctx, window.Start.Add(time.Second)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d, %v", queued, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 || runs.Items[0].Status != "succeeded" {
		t.Fatalf("rotation runs = %s", runs.Raw)
	}
	run := runs.Items[0]
	successor, err := certificateByFingerprint(t, h, run.SuccessorFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	// The successor's delivery and its verification, and a scan that found it.
	for _, receipt := range []store.ConnectorDeliveryReceipt{
		{IdentityID: &ident.ID, Destination: "connector.deploy", Connector: "nginx", Target: "edge-assurance",
			Fingerprint: successor.Fingerprint, Status: "delivered", IdempotencyKey: "assurance-served"},
		{IdentityID: &ident.ID, Destination: "connector.deploy", Connector: "nginx", Target: "edge-assurance",
			Fingerprint: successor.Fingerprint, Status: "verified", IdempotencyKey: "assurance-served:verified"},
	} {
		if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, receipt); err != nil {
			t.Fatal(err)
		}
	}
	const sourceID, runID = "17900000-0000-4000-8000-0000000000d1", "17900000-0000-4000-8000-0000000000d2"
	now := time.Now().UTC()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_sources (id, tenant_id, kind, name, created_at, updated_at) VALUES ($1, $2, 'network', 'edge scan', $3, $3)`, sourceID, h.tenant, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_runs (id, tenant_id, source_id, status, created_at) VALUES ($1, $2, $3, 'succeeded', $4)`, runID, h.tenant, sourceID, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO discovery_findings (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, discovered_at)
			VALUES ('17900000-0000-4000-8000-0000000000d3', $1, $2, $3, 'certificate', 'edge-assurance:443', 'tls-handshake', $4, $5)`,
			h.tenant, runID, sourceID, successor.Fingerprint, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+successor.ID+"/assurance-record", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("assurance record: %d %s", status, body)
	}
	var signed assurance.Signed
	if err := json.Unmarshal(body, &signed); err != nil {
		t.Fatal(err)
	}
	// The verifier pins the deployment's audit JWK set, not the response's copy.
	pinnedJWKS, err := auditKey.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, pinnedJWKS, signed.PublicJWKS) {
		t.Fatalf("the response's public_jwks differs from the audit key's: %s", signed.PublicJWKS)
	}
	keys, err := jose.ParseJWKSet(pinnedJWKS)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := assurance.Verify(body, keys)
	if err != nil {
		t.Fatalf("the served record does not verify offline: %v", err)
	}
	r := verified.Record
	if r.Credential.CertificateID != successor.ID || !slices.Contains(r.Credential.IdentityIDs, ident.ID) || r.TenantID != h.tenant {
		t.Fatalf("credential = %+v", r.Credential)
	}
	if len(r.Discovery) != 1 || !strings.HasPrefix(r.Discovery[0].EvidenceID, "discovery-finding:") {
		t.Fatalf("discovery = %+v", r.Discovery)
	}
	if r.Owner == nil || r.Owner.OwnerID != owner.ID {
		t.Fatalf("owner = %+v", r.Owner)
	}
	// A scheduler renewal names the transition that decided it.
	if !r.Issuance.IssuedByTrstctl || !strings.HasPrefix(r.Issuance.EvidenceID, "event:") || r.Issuance.CA == "" {
		t.Fatalf("issuance = %+v", r.Issuance)
	}
	if len(r.Deployments) == 0 || len(r.Verifications) == 0 {
		t.Fatalf("deployments %+v verifications %+v", r.Deployments, r.Verifications)
	}
	for _, d := range r.Deployments {
		if !strings.HasPrefix(d.EvidenceID, "connector-receipt:") {
			t.Fatalf("deployment without evidence id: %+v", d)
		}
	}
	if len(r.Renewals.Runs) != 1 || r.Renewals.Runs[0].EvidenceID != "rotation-run:"+run.ID || r.Renewals.Runs[0].Role != "successor" {
		t.Fatalf("renewals = %+v", r.Renewals)
	}
	if len(r.Audit) == 0 {
		t.Fatal("no audit entry names the renewed certificate")
	}
	for _, stage := range []string{"discovery", "deployment", "verification"} {
		if !slices.Contains(r.IndependentlyObserved, stage) {
			t.Fatalf("%s not independently observed: %v / recorded %v / absent %v", stage, r.IndependentlyObserved, r.RecordedOnly, r.Absent)
		}
	}
	if !slices.Equal(r.Absent, []string{"revocation"}) {
		t.Fatalf("a renewed, verified certificate lacks stages: absent %v", r.Absent)
	}
	if !strings.Contains(signed.Rendering, "rotation-run:"+run.ID) {
		t.Fatalf("rendering lacks the renewal evidence:\n%s", signed.Rendering)
	}

	var tampered map[string]any
	_ = json.Unmarshal(body, &tampered)
	tampered["record"].(map[string]any)["issuance"].(map[string]any)["ca"] = "CN=Someone Else"
	raw, _ := json.Marshal(tampered)
	if _, err := assurance.Verify(raw, keys); err == nil {
		t.Fatal("a tampered record verified")
	}
	other := seedScopedToken(t, h.store, h.tenant, "lifecycle:read")
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+successor.ID+"/assurance-record", other, nil); status != http.StatusForbidden {
		t.Fatalf("a token without certs:read read the record: %d", status)
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/17900000-0000-4000-8000-0000000000ff/assurance-record", tok, nil); status != http.StatusNotFound {
		t.Fatalf("an unknown certificate: %d", status)
	}
}

func certificateByFingerprint(t *testing.T, h *servedHarness, fingerprint string) (store.Certificate, error) {
	t.Helper()
	var id string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT id::text FROM certificates WHERE tenant_id = $1 AND fingerprint = $2`, h.tenant, fingerprint).Scan(&id)
	}); err != nil {
		return store.Certificate{}, err
	}
	return h.store.GetCertificate(t.Context(), h.tenant, id)
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(a, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &right); err != nil {
		t.Fatal(err)
	}
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}
