// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
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
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	servedTenantA = "11111111-1111-1111-1111-111111111111"
	servedTenantB = "22222222-2222-2222-2222-222222222222"
)

// TestEvidencePackServedTenantScopedExactClaimsAUD76 proves the production
// route, authz guard, audit query, control evaluator, signed envelope, and
// verifier together. Tenant B owns the exact three event types needed by CC7;
// tenant A owns only an unrelated event. A request authenticated as A first sends
// a forged B tenant header, which must be rejected. A second request with matching
// principal and tenant headers must return only A's evidence.
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
	adcsObservation := func(tenantID, domain string) (string, adcsdiscovery.InventoryObserved) {
		inv := adcsdiscovery.Inventory{
			Templates: []adcsdiscovery.Template{{
				Name: "UserAuth", EnrolleeSuppliesSubject: true, EKUs: []string{adcsdiscovery.EKUClientAuth},
				EnrollmentPrincipals: []string{"S-1-5-11"}, PublishedBy: []string{"CORP-CA"},
			}},
			EnrollmentServices: []adcsdiscovery.EnrollmentService{{
				Name: "CORP-CA", AgentRestrictions: adcsdiscovery.EnrollmentAgentRestrictions{State: adcsdiscovery.EvidenceUnobserved, Source: "requires_windows_relay"},
				Endpoints: []adcsdiscovery.EnrollmentEndpoint{{
					Kind: adcsdiscovery.EndpointNDESAdmin, URL: "http://ca.example/certsrv/mscep_admin/",
					State: adcsdiscovery.EndpointAnonymousAccess, HTTPStatus: 200, ExtendedProtection: adcsdiscovery.EvidenceUnobserved,
				}},
			}},
		}
		observed := adcsdiscovery.InventoryObserved{
			RunID: "run-" + domain, SourceID: "source-" + domain, Domain: domain,
			AgentID: "agent-" + domain, AgentName: "relay-" + domain, DirectoryVerified: true,
			Templates: inv.Templates, EnrollmentServices: inv.EnrollmentServices, Findings: adcsdiscovery.Findings(inv),
		}
		data, marshalErr := json.Marshal(observed)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return appendEvent(tenantID, projections.EventADCSInventoryObserved, string(data), -50*time.Minute), observed
	}
	adcsAID, observedA := adcsObservation(servedTenantA, "CORP-A")
	adcsBID, _ := adcsObservation(servedTenantB, "CORP-B")
	driftPayload := projections.ADCSTemplateDriftObserved{
		RunID: "run-drift-a", SourceID: "source-CORP-A", Domain: "CORP-A",
		AgentID: "agent-CORP-A", ObservedBy: "relay-CORP-A",
		Direction: adcsdiscovery.DriftWorse, Worsened: true,
		Lifecycle: []adcsdiscovery.LifecycleChange{{Template: "UserAuth", Lifecycle: adcsdiscovery.TemplateAdded, NowDangerous: true}},
	}
	driftData, err := json.Marshal(driftPayload)
	if err != nil {
		t.Fatal(err)
	}
	adcsDriftAID := appendEvent(servedTenantA, projections.EventADCSTemplateDriftWorsened, string(driftData), -49*time.Minute)
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
		buildGraph: func(_ context.Context, _ *store.Store, tenantID string) (*graph.Graph, error) {
			g := graph.New()
			g.AddNode(graph.Node{ID: "asset:rsa", Kind: graph.KindCryptoAsset, Attrs: map[string]string{"algorithm": string(crypto.RSA2048)}})
			g.AddNode(graph.Node{ID: "workload:api", Kind: graph.KindWorkload})
			g.AddNode(graph.Node{ID: "credential:api", Kind: graph.KindCredential})
			g.AddEdge(graph.Edge{From: "workload:api", To: "credential:api", Type: graph.EdgeOwns})
			if tenantID == servedTenantA {
				g.AddNode(graph.Node{ID: "cert:a", Kind: graph.KindCredential, Name: "a.example.test", Attrs: map[string]string{
					"credential_kind": "certificate", "certificate_id": "cert-a", "fingerprint": "sha256:a",
					"subject": "a.example.test", "key_origin": "host_agent",
				}})
			} else {
				g.AddNode(graph.Node{ID: "cert:b", Kind: graph.KindCredential, Name: "b.example.test", Attrs: map[string]string{
					"credential_kind": "certificate", "certificate_id": "cert-b", "fingerprint": "sha256:b",
					"subject": "b.example.test", "key_origin": "host_agent", "key_storage": "file",
					"key_exportable": "exportable", "key_generated_by": "agent-b",
				}})
			}
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
	if reportA.Custody.Total != 1 || reportA.Custody.Unrecorded != 1 ||
		len(reportA.Custody.UnrecordedCertificates) != 1 ||
		reportA.Custody.UnrecordedCertificates[0].ID != "cert-a" || packA.Custody.Unrecorded != 1 {
		t.Fatalf("tenant A custody evidence = report=%+v outer=%+v", reportA.Custody, packA.Custody)
	}
	for _, id := range []string{"soc2-key-management", "soc2-cc6-access-control", "soc2-cc7-monitoring-audit-evidence", "soc2-cc8-change-management-evidence"} {
		mustHaveControl(t, reportA.Controls, id, "gap")
	}
	assertReportExcludesEventIDs(t, reportA, bPolicyID, bLifecycleID, bMonitoringID)
	assertReportIncludesEventID(t, reportA, unrelatedID, false)
	if len(reportA.ADCS.Observations) != 1 || reportA.ADCS.Observations[0].Domain != "CORP-A" ||
		reportA.ADCS.Observations[0].Reference.EventID != adcsAID ||
		len(reportA.ADCS.Observations[0].Findings) != len(observedA.Findings) ||
		len(reportA.ADCS.Drift) != 1 || reportA.ADCS.Drift[0].Reference.EventID != adcsDriftAID {
		t.Fatalf("tenant A signed AD CS evidence = %+v", reportA.ADCS)
	}
	if got, want := mustJSON(t, packA.ADCS), mustJSON(t, reportA.ADCS); string(got) != string(want) {
		t.Fatalf("outer AD CS convenience copy differs from signed manifest\nouter=%s\nsigned=%s", got, want)
	}
	if bytes.Contains(mustJSON(t, reportA.ADCS), []byte(adcsBID)) || bytes.Contains(mustJSON(t, reportA.ADCS), []byte("CORP-B")) {
		t.Fatal("tenant A signed AD CS evidence contains tenant B facts")
	}

	_, reportB := serveEvidencePack(t, handler, signer, servedTenantB, servedTenantA)
	if reportB.TenantID != servedTenantB {
		t.Fatalf("tenant B signed manifest tenant = %q", reportB.TenantID)
	}
	if reportB.Custody.Total != 1 || reportB.Custody.Recorded != 1 || reportB.Custody.Unrecorded != 0 {
		t.Fatalf("tenant B custody evidence = %+v", reportB.Custody)
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

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func serveEvidencePack(t *testing.T, handler http.Handler, signer crypto.DigestSigner, principalTenant, forgedHeaderTenant string) (api.ComplianceEvidencePack, Report) {
	t.Helper()
	forged := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", nil)
	forged.Header.Set("X-Test-Principal-Tenant", principalTenant)
	forged.Header.Set("X-Tenant-ID", forgedHeaderTenant)
	forgedRec := httptest.NewRecorder()
	handler.ServeHTTP(forgedRec, forged)
	if forgedRec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant evidence request status = %d, want 403; body=%s", forgedRec.Code, forgedRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", nil)
	req.Header.Set("X-Test-Principal-Tenant", principalTenant)
	req.Header.Set("X-Tenant-ID", principalTenant)
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
