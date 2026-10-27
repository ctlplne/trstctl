// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/cryptorisk"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedCryptoRiskReportA185 proves the cryptographic risk report end to
// end: a scheduled run signs and archives a report that lists each weak,
// distrusted or quantum-vulnerable key with its dependents, the NIST IR 8547
// deadline that applies and its migration plan; the next period's report says
// what was added and resolved since the archived one; and the on-demand report
// and its CSV agree with it.
func TestServedCryptoRiskReportA185(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := &reportWorkerSigner{key: key}
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	ctx := t.Context()
	projector := projections.New(h.store)
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	apply := func(sequence uint64, eventType string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, events.Event{
			ID: fmt.Sprintf("18500000-0000-4000-8000-%012d", sequence), Type: eventType,
			TenantID: h.tenant, Sequence: sequence, Time: base.Add(time.Duration(sequence) * time.Second), Data: data, // #nosec G115 -- fixture sequences are single-digit seconds (CWE-190).
		}); err != nil {
			t.Fatalf("apply %s: %v", eventType, err)
		}
	}
	const (
		ownerID    = "18500000-0000-4000-8000-000000000001"
		identityID = "18500000-0000-4000-8000-000000000002"
		targetID   = "18500000-0000-4000-8000-000000000003"
		assetID    = "18500000-0000-4000-8000-000000000004"
		campaignID = "18500000-0000-4000-8000-000000000005"
		scheduleID = "18500000-0000-4000-8000-000000000006"
	)
	// An RSA-2048 key on the edge load balancer, which a payments certificate
	// identity is deployed to: a quantum-vulnerable key with a dependent and an owner.
	apply(1, projections.EventOwnerCreated, projections.OwnerCreated{ID: ownerID, Kind: "service", Name: "payments-team"})
	apply(2, projections.EventDeploymentTargetUpserted, projections.DeploymentTargetUpserted{
		ID: targetID, Name: "lb-edge", Connector: "f5", Config: json.RawMessage(`{"address_ref":"lb-edge"}`),
	})
	apply(3, projections.EventIdentityCreated, projections.IdentityCreated{
		ID: identityID, Kind: "x509_certificate", Name: "lb-tls", OwnerID: ownerID,
		Attributes: json.RawMessage(`{"deployment_target":"lb-edge"}`),
	})
	apply(4, projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{
		ID: assetID, Kind: "public-key", Location: "lb-edge", Algorithm: "RSA", KeyBits: 2048,
		Strength: "acceptable", QuantumVulnerable: true,
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "crypto-operator", "graph:read", "risk:read", "discovery:write", "audit:read", "certs:read")
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/graph/crypto-readiness/actions", operator, "a185-action", map[string]any{
		"id": campaignID, "name": "RSA-2048 edge migration", "owner": "payments-team",
		"deadline": base.Add(90 * 24 * time.Hour), "wave": "wave-1",
		"readiness_criteria": []string{"owner approved"}, "finding_ids": []string{assetID},
	})
	if status != http.StatusCreated {
		t.Fatalf("start readiness action = %d %s", status, body)
	}
	// Inventory certificates: one with a weak RSA-1024 key, one issued under the
	// distrusted emSign root (known by its issuer name).
	expiry := base.Add(200 * 24 * time.Hour)
	record := func(serial, issuer, alg string) store.Certificate {
		t.Helper()
		cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
			Subject: "CN=" + serial + ".risk.example.test", Serial: serial, Issuer: issuer, KeyAlgorithm: alg,
			Fingerprint: crypto.SHA256Hex([]byte("a185-" + serial)), Source: "discovered", NotAfter: &expiry,
		})
		if err != nil {
			t.Fatalf("record %s: %v", serial, err)
		}
		return cert
	}
	weak := record("weak1024", "CN=Acme Issuing CA", "RSA-1024")
	distrusted := record("emsigned", "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN", "ECDSA P-256")

	// A crypto_risk schedule due two hours ago.
	due := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	scheduleEvent, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted, Time: due.Add(-time.Hour), SchemaVersion: 1,
		Data: []byte(`{"id":"` + scheduleID + `","framework":"cnsa-2.0","name":"weekly crypto risk","report_type":"crypto_risk","interval_seconds":3600,"enabled":true,"delivery":"audit_export"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, scheduleEvent); err != nil {
		t.Fatal(err)
	}
	runReport := func(label string) cryptorisk.Report {
		t.Helper()
		schedule, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
		if err != nil {
			t.Fatal(err)
		}
		if processed, err := h.srv.runComplianceReportDue(ctx, schedule, time.Now().UTC().Add(2*time.Hour)); err != nil || !processed {
			t.Fatalf("%s: due edge processed %v, %v", label, processed, err)
		}
		run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, schedule.NextRunAt)
		if err != nil || run.Status != "completed" {
			t.Fatalf("%s: run = %+v, %v", label, run, err)
		}
		artifact, err := h.srv.reportArchive.Read(ctx, run.ArtifactRef, h.tenant, run.ID, run.ArtifactDigest)
		if err != nil || h.srv.api.VerifyScheduledComplianceArtifact(artifact, run) != nil {
			t.Fatalf("%s: archived signed artifact unreadable: %v", label, err)
		}
		var envelope struct {
			Manifest api.ScheduledComplianceManifest `json:"manifest"`
		}
		var report cryptorisk.Report
		if json.Unmarshal(artifact, &envelope) != nil || envelope.Manifest.ReportType != "crypto_risk" || json.Unmarshal(envelope.Manifest.Payload, &report) != nil {
			t.Fatalf("%s: artifact is not a crypto-risk report: %s", label, artifact)
		}
		return report
	}

	first := runReport("first period")
	items := map[string]cryptorisk.Item{}
	for _, it := range first.Items {
		items[it.Key] = it
	}
	asset := items["crypto:"+assetID]
	if asset.Dependents.Count == 0 || !slices.Contains(asset.Owners, "payments-team") ||
		asset.Deadline.DeprecatedAfter != 2030 || asset.Deadline.DisallowedAfter != 2035 || asset.Deadline.SecurityBits != 112 ||
		!strings.Contains(asset.Deadline.Source, "initial public draft") ||
		len(asset.Plan.Actions) != 1 || asset.Plan.Actions[0].CampaignID != campaignID {
		t.Fatalf("the RSA-2048 key must carry its dependents, owner, IR 8547 deadline and campaign: %+v", asset)
	}
	weakItem := items["certificate:"+weak.ID]
	if weakItem.Deadline.Status != cryptorisk.DeadlineReplaceNow || !slices.Contains(weakItem.Exposures, cryptorisk.ExposureWeak) ||
		weakItem.Plan.Recommended == "" {
		t.Fatalf("the weak certificate must be replaced now with a recommended plan: %+v", weakItem)
	}
	distrustedItem := items["certificate:"+distrusted.ID]
	if distrustedItem.Distrust == nil || distrustedItem.Distrust.Entry != "emSign ECC Root CA - G3" || distrustedItem.Priority != 1 {
		t.Fatalf("the distrusted certificate must come first: %+v", distrustedItem)
	}
	if first.Changes.Comparable || first.Changes.Note == "" || first.CNSA20 == "" {
		t.Fatalf("a first report has nothing to compare: %+v", first.Changes)
	}

	// Next period: the distrusted certificate was revoked and another weak key appeared.
	if err := h.srv.orch.RevokeCertificate(ctx, h.tenant, distrusted.Fingerprint, distrusted.Serial, "superseded", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	added := record("weak1024b", "CN=Acme Issuing CA", "RSA-1024")
	second := runReport("second period")
	c := second.Changes
	if !c.Comparable || c.PreviousGeneratedAt == nil || !c.PreviousGeneratedAt.Equal(first.GeneratedAt) ||
		!slices.Equal(c.Added, []string{"certificate:" + added.ID}) || !slices.Equal(c.Resolved, []string{"certificate:" + distrusted.ID}) {
		t.Fatalf("period-over-period change = %+v", c)
	}

	// On demand: the same report, compared with the newest archived one.
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/crypto-risk", operator, "", nil)
	var onDemand cryptorisk.Report
	if status != http.StatusOK || json.Unmarshal(body, &onDemand) != nil {
		t.Fatalf("on-demand report = %d %s", status, body)
	}
	if onDemand.Summary.Items != second.Summary.Items || !onDemand.Changes.Comparable || len(onDemand.Changes.Added) != 0 || len(onDemand.Changes.Resolved) != 0 {
		t.Fatalf("on-demand report vs the newest archived one: summary %+v vs %+v, changes %+v", onDemand.Summary, second.Summary, onDemand.Changes)
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/crypto-risk/export", operator, "", nil)
	var export struct {
		ContentType string `json:"content_type"`
		CSV         string `json:"csv"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &export) != nil || export.ContentType != "text/csv" {
		t.Fatalf("export = %d %s", status, body)
	}
	rows, err := csv.NewReader(strings.NewReader(export.CSV)).ReadAll()
	if err != nil || len(rows) != len(onDemand.Items)+1 || rows[0][0] != "priority" {
		t.Fatalf("csv = %d rows (%v) for %d items", len(rows), err, len(onDemand.Items))
	}

	// A token that may read risk but not certificates sees no certificate, and is told.
	riskOnly := seedScopedToken(t, h.store, h.tenant, "risk:read")
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/crypto-risk", riskOnly, "", nil)
	var limited cryptorisk.Report
	if status != http.StatusOK || json.Unmarshal(body, &limited) != nil || !strings.Contains(limited.Coverage, "may not read certificates") {
		t.Fatalf("risk-only report = %d %s", status, body)
	}
	for _, it := range limited.Items {
		if it.Kind == "certificate" {
			t.Fatalf("a token without certs:read saw a certificate: %+v", it)
		}
	}
	if status, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/crypto-risk?limit=0", operator, "", nil); status != http.StatusBadRequest {
		t.Fatalf("limit=0 = %d, want 400", status)
	}
}
