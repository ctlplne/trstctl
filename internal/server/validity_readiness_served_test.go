// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tlsvalidity"
)

// TestServedValidityReadinessA178 is A178's served contract: a public TLS
// profile requesting 397 days is flagged for the 2026 and 2027 steps, every
// active certificate has a verdict under every step from the scheduler's own
// view of it, and the export names its Baseline Requirements version. The
// report is a read: it appends nothing to the event log.
func TestServedValidityReadinessA178(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 30 * 24 * time.Hour
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "profiles:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{
		"name": "web-public",
		"spec": map[string]any{"public_tls": true, "allowed_ekus": []string{"serverAuth"}, "max_validity": "9528h"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create public TLS profile: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/profiles", tok, map[string]any{
		"name": "clients-only", "spec": map[string]any{"public_tls": true, "allowed_ekus": []string{"clientAuth"}},
	})
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		t.Fatalf("a clientAuth-only public TLS profile was accepted: status %d body %s", status, body)
	}

	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "Checkout team", "")
	if err != nil {
		t.Fatal(err)
	}
	deployed := func(name string) (store.Identity, store.Certificate) {
		t.Helper()
		identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, state := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed} {
			if err := h.srv.orch.Transition(ctx, h.tenant, identity.ID, state, "validity readiness fixture"); err != nil {
				t.Fatalf("transition %s to %s: %v", name, state, err)
			}
			if err := h.srv.Drain(ctx); err != nil {
				t.Fatal(err)
			}
		}
		certs, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, name)
		if err != nil || len(certs) != 1 {
			t.Fatalf("%s certificates = %d, %v", name, len(certs), err)
		}
		return identity, certs[0]
	}
	verifiedIdentity, verifiedCert := deployed("checkout.example.test")
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &verifiedIdentity.ID, Destination: "connector.deploy", Connector: "apache", Target: "checkout-edge",
		Fingerprint: verifiedCert.Fingerprint, Status: "verified", IdempotencyKey: "validity-readiness-verified",
	}); err != nil {
		t.Fatal(err)
	}
	_, unverifiedCert := deployed("billing.example.test")

	now := time.Now().UTC()
	publicDER, err := certtest.TLSLeaf("www.example.test", now.Add(-time.Hour), now.Add(90*24*time.Hour), "2.23.140.1.2.1")
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/certificates", tok, map[string]any{
		"pem": string(crypto.EncodeCertificatePEM(publicDER)), "deployment_location": "edge-lb",
	})
	if status != http.StatusCreated {
		t.Fatalf("ingest public certificate: status %d body %s", status, body)
	}
	var ingested struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ingested); err != nil {
		t.Fatal(err)
	}

	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/validity-readiness", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("validity readiness: status %d body %s", status, body)
	}
	var report tlsvalidity.Report
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode report: %v (%s)", err, body)
	}
	if report.Requirements.Version != "2.3.1" || report.Requirements.Section != "6.3.2" {
		t.Fatalf("requirements = %+v", report.Requirements)
	}
	if !report.Scheduler.Enabled || report.Scheduler.RenewBeforeSeconds != int64(30*24*time.Hour/time.Second) {
		t.Fatalf("scheduler = %+v", report.Scheduler)
	}
	var effective []string
	for _, step := range report.Steps {
		effective = append(effective, step.Effective)
	}
	if !slices.Equal(effective, []string{"2026-03-15", "2027-03-15", "2029-03-15"}) {
		t.Fatalf("steps = %v", effective)
	}

	var profile *tlsvalidity.ProfileReadiness
	for i := range report.Profiles {
		if report.Profiles[i].Name == "web-public" {
			profile = &report.Profiles[i]
		}
	}
	if profile == nil || !profile.PublicTLS || profile.RequestedDays != 398 || len(profile.Steps) != 3 {
		t.Fatalf("web-public profile row = %+v (all %+v)", profile, report.Profiles)
	}
	if !profile.Steps[0].Flagged || !profile.Steps[1].Flagged || profile.Steps[0].Reason != tlsvalidity.ReasonRequestedValidityExceeds {
		t.Fatalf("a 397-day public TLS profile must be flagged for the 2026 and 2027 steps: %+v", profile.Steps)
	}

	byID := map[string]tlsvalidity.CertificateReadiness{}
	for _, row := range report.Certificates {
		if len(row.Steps) != 3 {
			t.Fatalf("%s has %d verdicts, want one per step", row.CertificateID, len(row.Steps))
		}
		byID[row.CertificateID] = row
	}
	if len(byID) != 3 {
		t.Fatalf("report covers %d certificates, want the 3 active ones: %+v", len(byID), report.Certificates)
	}
	verdicts := func(row tlsvalidity.CertificateReadiness) []tlsvalidity.Verdict {
		var out []tlsvalidity.Verdict
		for _, step := range row.Steps {
			out = append(out, step.Verdict)
		}
		return out
	}
	verified := byID[verifiedCert.ID]
	if verified.Automation != tlsvalidity.AutomationScheduled || verified.Deployment != tlsvalidity.DeploymentVerified ||
		verified.IdentityID != verifiedIdentity.ID || verified.Scope != tlsvalidity.ScopePrivateTLS ||
		!slices.Equal(verdicts(verified), []tlsvalidity.Verdict{"renews", "renews", "renews"}) {
		t.Fatalf("verified scheduled certificate = %+v", verified)
	}
	if verified.RenewalLifetimeDays != 30 || verified.RenewalLeadDays != 10 {
		t.Fatalf("a 30-day renewal with a 30-day lead renews at the ARI window, 10 days out: %+v", verified)
	}
	// The harness's deploy transition tries a connector delivery that fails;
	// with no later success on record, the scheduler holds that identity.
	unverified := byID[unverifiedCert.ID]
	if unverified.Automation != tlsvalidity.AutomationScheduled || unverified.Deployment != tlsvalidity.DeploymentFailed ||
		!slices.Equal(verdicts(unverified), []tlsvalidity.Verdict{"at_risk", "at_risk", "at_risk"}) ||
		!slices.Equal(unverified.Steps[0].Reasons, []string{tlsvalidity.ReasonDeliveryFailed}) {
		t.Fatalf("a scheduled certificate whose delivery failed = %+v", unverified)
	}
	public := byID[ingested.ID]
	if public.Scope != tlsvalidity.ScopePublicTLS || public.Automation != tlsvalidity.AutomationNone ||
		!slices.Equal(verdicts(public), []tlsvalidity.Verdict{"manual", "manual", "manual"}) {
		t.Fatalf("an ingested public TLS certificate = %+v", public)
	}
	for i, perYear := range []int{2, 4, 8} {
		if got := report.Steps[i].ManualRenewalsPerYear; got != perYear {
			t.Errorf("step %s manual renewals a year = %d, want %d", report.Steps[i].Effective, got, perYear)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/validity-readiness/export", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("export: status %d body %s", status, body)
	}
	var export struct {
		Filename     string             `json:"filename"`
		ContentType  string             `json:"content_type"`
		Requirements tlsvalidity.Source `json:"requirements"`
		CSV          string             `json:"csv"`
	}
	if err := json.Unmarshal(body, &export); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(export.Filename, "validity-readiness-br-2.3.1-") || export.ContentType != "text/csv" || export.Requirements.Version != "2.3.1" {
		t.Fatalf("export = %+v", export)
	}
	records, err := csv.NewReader(strings.NewReader(export.CSV)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < 1+3*3+3 {
		t.Fatalf("export has %d rows", len(records))
	}
	for _, record := range records[1:] {
		if !strings.Contains(record[len(record)-1], "Baseline Requirements 2.3.1") {
			t.Fatalf("export row does not name its BR version: %v", record)
		}
	}

	after, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the report appended events %d..%d", before, after)
	}
	unauthorized := seedScopedToken(t, h.store, h.tenant, "lifecycle:read")
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/validity-readiness", unauthorized, nil); status != http.StatusForbidden {
		t.Fatalf("a token without certs:read read the report: %d", status)
	}
}
