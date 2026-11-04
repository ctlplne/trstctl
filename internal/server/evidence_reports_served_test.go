// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A252 Done when: each evidence template renders from real data, verifies
// offline, and states what it couldn't observe. Real product flows make the
// events — a recorded certificate, a member and API tokens, a secret rotated,
// a decoy planted and used, a rehearsal previewed — then one hourly schedule
// per template signs a report, and a verifier holding only the published key
// checks each archived run.
func TestServedEvidenceReportTemplatesA252(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(&reportWorkerSigner{key: key}))
	})
	ctx := t.Context()
	start := time.Now().UTC().Add(-time.Minute)
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "evidence-admin", "*")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		code, out := doBearer(t, h.ts, method, path, admin, key, body)
		if code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, out)
		}
		return out
	}

	// Lifecycle: a certificate recorded from outside trstctl.
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	if _, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{Subject: "CN=a252.example.test", Serial: "a252",
		Issuer: "CN=Outside CA", KeyAlgorithm: "ECDSA-P256", Fingerprint: crypto.SHA256Hex([]byte("a252-leaf")), Source: "discovered",
		NotAfter: &notAfter}); err != nil {
		t.Fatal(err)
	}
	// Access: a member, and an API token minted then revoked.
	const member = "auditor@a252.example"
	call(http.MethodPut, "/api/v1/access/members/"+url.PathEscape(member), "a252-member",
		map[string]any{"display_name": "A252 auditor", "roles": []string{"viewer"}, "source": "manual"}, http.StatusOK)
	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/access/api-tokens", "a252-token",
		map[string]any{"subject": "ci:a252", "scopes": []string{"certs:read"}}, http.StatusCreated), &minted); err != nil {
		t.Fatal(err)
	}
	call(http.MethodDelete, "/api/v1/access/api-tokens/"+minted.ID, "a252-token-revoke", nil, http.StatusNoContent)
	// Rotation: a stored secret rotated.
	call(http.MethodPost, "/api/v1/secrets/store", "a252-secret", map[string]any{"name": "a252/db/password", "value": "a252-secret-v1"}, http.StatusCreated)
	call(http.MethodPut, "/api/v1/secrets/store/a252/db/password", "a252-rotate", map[string]any{"value": "a252-secret-v2"}, http.StatusOK)
	// Incident response: a decoy planted, then used by a thief.
	var decoy struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/secrets/honeytokens", "a252-decoy",
		map[string]any{"name": "a252-decoy", "placement": "payments/ci"}, http.StatusCreated), &decoy); err != nil || decoy.Token == "" {
		t.Fatalf("plant decoy: %v", err)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/certificates", decoy.Token, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("decoy use = %d, want 401", code)
	}
	// Qualification: a target-outage rehearsal saved and previewed.
	var target struct {
		ID string `json:"id"`
	}
	code, out := doBearer(t, h.ts, http.MethodPost, "/api/v1/connectors/targets", admin, "a252-target", map[string]any{
		"name": "a252/staging-lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a252.internal", "partition": "Common", "environment": "staging"},
	})
	if (code != http.StatusCreated && code != http.StatusOK) || json.Unmarshal(out, &target) != nil || target.ID == "" {
		t.Fatalf("create target = %d %s", code, out)
	}
	var scenario struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(http.MethodPost, "/api/v1/rehearsals/scenarios", "a252-scenario", map[string]any{
		"name": "A252 load balancer outage", "kind": "target_outage",
		"candidate": map[string]any{"kind": "target", "ref": target.ID},
		"data_set":  map[string]any{"kind": "scrubbed_failure", "failure": map[string]any{"source": "outbox_dead_letter", "ref": "dl-a252", "code": "connect_timeout"}},
		"steps": []map[string]any{
			{"action": "deliver_to_unreachable_target", "target": target.ID, "expect": "retried_with_backoff"},
			{"action": "exhaust_retries", "target": target.ID, "expect": "dead_lettered_and_alerted"},
		},
	}, http.StatusCreated), &scenario); err != nil || scenario.ID == "" {
		t.Fatalf("save scenario: %v", err)
	}
	call(http.MethodPost, "/api/v1/rehearsals/scenarios/"+scenario.ID+"/runs", "a252-preview", map[string]any{"mode": "static_preview"}, http.StatusCreated)

	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/report-signing-key", admin, "", nil)
	var signingKey api.ReportSigningKey
	if status != http.StatusOK || json.Unmarshal(body, &signingKey) != nil {
		t.Fatalf("report signing key = %d %s", status, body)
	}
	pinned, err := compliance.ParsePublicKey([]byte(signingKey.PublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}

	projector := projections.New(h.store)
	due := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	want := map[string]string{ // kind -> a section the flows above must have filled
		"lifecycle_evidence":         "recorded from outside trstctl",
		"access_evidence":            "API tokens",
		"rotation_evidence":          "secrets",
		"incident_response_evidence": "decoys",
		"qualification_evidence":     "rehearsals",
	}
	for i, kind := range []string{"lifecycle_evidence", "access_evidence", "rotation_evidence", "incident_response_evidence", "qualification_evidence"} {
		scheduleID := "a2520000-0000-4000-8000-00000000000" + string(rune('1'+i))
		scheduleEvent, err := h.log.Append(ctx, events.Event{
			TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted, Time: due.Add(-time.Hour), SchemaVersion: 1,
			Data: []byte(`{"id":"` + scheduleID + `","framework":"soc2","name":"hourly ` + kind + `","report_type":"` + kind +
				`","interval_seconds":3600,"enabled":true,"delivery":"audit_export"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, scheduleEvent); err != nil {
			t.Fatal(err)
		}
		schedule, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
		if err != nil {
			t.Fatal(err)
		}
		if processed, err := h.srv.runComplianceReportDue(ctx, schedule, time.Now().UTC().Add(2*time.Hour)); err != nil || !processed {
			t.Fatalf("%s: due edge processed %v, %v", kind, processed, err)
		}
		run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, schedule.NextRunAt)
		if err != nil || run.Status != "completed" {
			t.Fatalf("%s: run = %+v, %v", kind, run, err)
		}
		artifact, err := h.srv.reportArchive.Read(ctx, run.ArtifactRef, h.tenant, run.ID, run.ArtifactDigest)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := compliance.VerifyScheduledReport(artifact, pinned)
		if err != nil || verified.ReportType != kind || verified.RunID != run.ID {
			t.Fatalf("%s: offline verification = %+v, %v", kind, verified, err)
		}
		var report api.EvidenceReport
		if err := json.Unmarshal(verified.Payload, &report); err != nil {
			t.Fatal(err)
		}
		if report.Kind != kind || report.Format != "trstctl.report."+kind+".v1" || !report.WindowThrough.Equal(schedule.NextRunAt) ||
			report.SourceHeadSequence == 0 || len(report.Scope) == 0 || len(report.CurrentState) == 0 || len(report.Unobserved) < 2 {
			t.Fatalf("%s: report header = %+v", kind, report)
		}
		filled := false
		for _, s := range report.Sections {
			if s.Name == want[kind] {
				filled = s.Events > 0 && len(s.ByType) > 0
			}
			for _, id := range s.SubjectIDs {
				if len(id) != 36 {
					t.Fatalf("%s: section %q names a non-ID subject %q", kind, s.Name, id)
				}
			}
		}
		if !filled {
			t.Fatalf("%s: section %q is empty: %+v (window %s to %s, events from %s)", kind, want[kind], report.Sections,
				report.WindowFrom, report.WindowThrough, start)
		}
		for _, forbidden := range []string{auth.TokenPrefix, minted.Token, decoy.Token, "a252-secret-v", "BEGIN", member} {
			if forbidden != "" && bytes.Contains(artifact, []byte(forbidden)) {
				t.Fatalf("%s: the signed report carries %q", kind, forbidden[:min(len(forbidden), 10)])
			}
		}
	}

	// On demand, unsigned, the same template over a chosen window.
	var onDemand api.EvidenceReport
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/reports/evidence/access_evidence?from="+url.QueryEscape(start.Format(time.RFC3339))+
		"&through="+url.QueryEscape(time.Now().UTC().Add(time.Minute).Format(time.RFC3339)), "", nil, http.StatusOK), &onDemand); err != nil {
		t.Fatal(err)
	}
	if onDemand.CurrentState["api_tokens_active"] < 1 || !slices.ContainsFunc(onDemand.Unobserved, func(s string) bool {
		return strings.Contains(s, "per client network and hour")
	}) {
		t.Fatalf("on-demand access report = %+v", onDemand)
	}
	call(http.MethodGet, "/api/v1/reports/evidence/nonsense", "", nil, http.StatusNotFound)
	call(http.MethodGet, "/api/v1/reports/evidence/access_evidence?from=2026-01-01T00:00:00Z&through=2026-06-01T00:00:00Z", "", nil, http.StatusBadRequest)
}
