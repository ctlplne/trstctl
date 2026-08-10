// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

const (
	servedTenantA = "11111111-1111-1111-1111-111111111111"
	servedTenantB = "22222222-2222-2222-2222-222222222222"
)

// TestEvidencePackServedTenantScopedExactClaimsAUD76 proves the production
// route, authz guard, audit query, control evaluator, signed envelope, and
// verifier together. Tenant B owns the exact three event types needed by CC7;
// tenant A owns only an unrelated event. A request authenticated as A also sends
// a forged B tenant header, which must have no effect on either the manifest or
// its control verdicts.
func TestEvidencePackServedTenantScopedExactClaimsAUD76(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	through := time.Date(2026, 8, 9, 18, 0, 0, 0, time.UTC)
	appendEvent := func(tenantID, typ, data string, offset time.Duration) string {
		t.Helper()
		event, appendErr := log.Append(ctx, events.Event{
			TenantID: tenantID,
			Type:     typ,
			Time:     through.Add(offset),
			Data:     []byte(data),
		})
		if appendErr != nil {
			t.Fatalf("append %s for %s: %v", typ, tenantID, appendErr)
		}
		return event.ID
	}
	unrelatedID := appendEvent(servedTenantA, "tenant.member.upserted", `{"subject":"auditor-a"}`, -time.Hour)
	bPolicyID := appendEvent(servedTenantB, "policy.decision", `{}`, -3*time.Minute)
	bLifecycleID := appendEvent(servedTenantB, "certificate.recorded", `{}`, -2*time.Minute)
	bMonitoringID := appendEvent(servedTenantB, "discovery.finding.recorded", `{}`, -time.Minute)

	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate evidence signer: %v", err)
	}
	t.Cleanup(signer.Destroy)
	service := &evidenceService{
		audit:  audit.NewService(log, nil),
		signer: signer,
		now:    func() time.Time { return through },
		buildGraph: func(_ context.Context, _ *store.Store, _ string) (*graph.Graph, error) {
			g := graph.New()
			g.AddNode(graph.Node{ID: "asset:rsa", Kind: graph.KindCryptoAsset, Attrs: map[string]string{"algorithm": string(crypto.RSA2048)}})
			g.AddNode(graph.Node{ID: "workload:api", Kind: graph.KindWorkload})
			g.AddNode(graph.Node{ID: "credential:api", Kind: graph.KindCredential})
			g.AddEdge(graph.Edge{From: "workload:api", To: "credential:api", Type: graph.EdgeOwns})
			return g, nil
		},
	}

	handler := api.New(nil, nil, nil,
		api.WithComplianceEvidence(service),
		api.WithPrincipalResolver(func(r *http.Request) (authz.Principal, error) {
			tenantID := r.Header.Get("X-Test-Principal-Tenant")
			return authz.Principal{
				TenantID: tenantID,
				Subject:  "auditor@example.test",
				Grants: []authz.Grant{{
					Role:  authz.BuiltinRoles()["auditor"],
					Scope: authz.Scope{TenantID: tenantID},
				}},
			}, nil
		}),
	)

	packA, reportA := serveEvidencePack(t, handler, signer, servedTenantA, servedTenantB)
	if packA.Format != api.ComplianceEvidencePackFormat || reportA.TenantID != servedTenantA {
		t.Fatalf("tenant A served pack = format=%q tenant=%q", packA.Format, reportA.TenantID)
	}
	if reportA.EvidenceWindow != (EvidenceWindow{From: through.Add(-DefaultEvidenceWindow), Through: through}) {
		t.Fatalf("tenant A evidence window = %+v", reportA.EvidenceWindow)
	}
	for _, id := range []string{"soc2-key-management", "soc2-cc6-access-control", "soc2-cc7-monitoring-audit-evidence", "soc2-cc8-change-management-evidence"} {
		mustHaveControl(t, reportA.Controls, id, "gap")
	}
	assertReportExcludesEventIDs(t, reportA, bPolicyID, bLifecycleID, bMonitoringID)
	assertReportIncludesEventID(t, reportA, unrelatedID, false)

	_, reportB := serveEvidencePack(t, handler, signer, servedTenantB, servedTenantA)
	if reportB.TenantID != servedTenantB {
		t.Fatalf("tenant B signed manifest tenant = %q", reportB.TenantID)
	}
	mustHaveControl(t, reportB.Controls, "soc2-cc7-monitoring-audit-evidence", "evidenced")
	for _, id := range []string{"soc2-key-management", "soc2-cc6-access-control", "soc2-cc8-change-management-evidence"} {
		mustHaveControl(t, reportB.Controls, id, "gap")
	}
	for _, eventID := range []string{bPolicyID, bLifecycleID, bMonitoringID} {
		assertReportIncludesEventID(t, reportB, eventID, true)
	}
	assertReportExcludesEventIDs(t, reportB, unrelatedID)
}

func serveEvidencePack(t *testing.T, handler http.Handler, signer crypto.DigestSigner, principalTenant, forgedHeaderTenant string) (api.ComplianceEvidencePack, Report) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", nil)
	req.Header.Set("X-Test-Principal-Tenant", principalTenant)
	req.Header.Set("X-Tenant-ID", forgedHeaderTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("served evidence pack status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var pack api.ComplianceEvidencePack
	if err := json.Unmarshal(rec.Body.Bytes(), &pack); err != nil {
		t.Fatalf("decode served evidence pack: %v", err)
	}
	if string(pack.PublicKeyDER) != string(signer.Public().DER) {
		t.Fatal("served verifier key does not match the signing boundary public key")
	}
	manifest, err := Verify(pack.SignedExport, pack.PublicKeyDER)
	if err != nil {
		t.Fatalf("verify served evidence pack: %v", err)
	}
	var report Report
	if err := json.Unmarshal(manifest, &report); err != nil {
		t.Fatalf("decode signed manifest: %v", err)
	}
	return pack, report
}

func assertReportIncludesEventID(t *testing.T, report Report, eventID string, want bool) {
	t.Helper()
	found := false
	for _, control := range report.Controls {
		for _, ref := range control.EvidenceRefs {
			if ref.Ref == "event:"+eventID {
				found = true
				if ref.Source != "audit_event" || ref.Sequence == 0 || ref.Digest == "" || ref.ObservedAt.IsZero() {
					t.Fatalf("event %s has incomplete immutable reference: %+v", eventID, ref)
				}
			}
		}
	}
	if found != want {
		t.Fatalf("signed report event %s presence = %v, want %v", eventID, found, want)
	}
}

func assertReportExcludesEventIDs(t *testing.T, report Report, eventIDs ...string) {
	t.Helper()
	for _, eventID := range eventIDs {
		assertReportIncludesEventID(t, report, eventID, false)
	}
}
