// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// JOURNEY-003 acceptance: a compromised issuer response is a served fleet
// reissuance workflow, not a static plan. The API enumerates affected identities
// by issuer, reissues and deploys replacements in batches, revokes the old
// identities, records rollback evidence, supports pause/resume/rollback state
// snapshots, exports evidence, and persists the whole run through AN-2 events.
func TestServedFleetReissuanceForCompromisedIssuerReissuesRevokesAndExportsEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "fleet-incident-commander", []string{
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.IssuersRead), string(authz.IssuersWrite),
		string(authz.IncidentsRead), string(authz.IncidentsWrite),
		string(authz.CertsIssue), string(authz.GraphRead),
		string(authz.ConnectorsRead), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("journey-003-audit")
	if err != nil {
		_ = log.Close()
		t.Fatalf("generate audit key: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey, EnableRemediation: true,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	issuerID := createX509IssuerWithToken(t, ts, adminToken)
	firstID := createIdentityWithIssuerWithToken(t, ts, adminToken, owner.ID, issuerID, "payments-api", "fleet-identity-1")
	secondID := createIdentityWithIssuerWithToken(t, ts, adminToken, owner.ID, issuerID, "payments-worker", "fleet-identity-2")
	for _, id := range []string{firstID, secondID} {
		if code, body := transitionIdentityWithToken(t, ts, adminToken, id, "issued", "fleet-issued-"+id); code != http.StatusOK {
			t.Fatalf("issue identity %s = %d, want 200; body=%s", id, code, body)
		}
		if code, body := transitionIdentityWithToken(t, ts, adminToken, id, "deployed", "fleet-deployed-"+id); code != http.StatusOK {
			t.Fatalf("deploy identity %s = %d, want 200; body=%s", id, code, body)
		}
	}

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs", adminToken, "fleet-run-1", map[string]any{
		"issuer_id":     issuerID,
		"reason":        "intermediate CA private key exposure",
		"batch_size":    1,
		"connector":     "nginx",
		"target":        "edge/prod",
		"rollback_ref":  "restore previous fullchain on every edge target",
		"health_gates":  []map[string]string{{"name": "replacement deployed", "status": "passed"}, {"name": "revocation published", "status": "passed"}},
		"evidence_hint": "ca-compromise-drill-42",
	})
	if code != http.StatusCreated {
		t.Fatalf("start fleet reissuance = %d, want 201; body=%s", code, body)
	}
	var run struct {
		ID                     string   `json:"id"`
		IssuerID               string   `json:"issuer_id"`
		Status                 string   `json:"status"`
		Phase                  string   `json:"phase"`
		Reason                 string   `json:"reason"`
		BatchSize              int      `json:"batch_size"`
		AffectedIdentityIDs    []string `json:"affected_identity_ids"`
		ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
		RevokedIdentityIDs     []string `json:"revoked_identity_ids"`
		ConnectorDeliveryIDs   []string `json:"connector_delivery_ids"`
		ConnectorDeliveries    []struct {
			Status   string `json:"status"`
			Attempts int    `json:"attempts"`
		} `json:"connector_deliveries"`
		BatchCount int `json:"batch_count"`
		Batches    []struct {
			Index                  int      `json:"index"`
			Status                 string   `json:"status"`
			IdentityIDs            []string `json:"identity_ids"`
			ReplacementIdentityIDs []string `json:"replacement_identity_ids"`
			HealthGate             string   `json:"health_gate"`
		} `json:"batches"`
		HealthGates          []struct{ Name, Status string } `json:"health_gates"`
		GraphImpact          json.RawMessage                 `json:"graph_impact"`
		FailedTargets        []string                        `json:"failed_targets"`
		RollbackRefs         []string                        `json:"rollback_refs"`
		EvidenceBundleFormat string                          `json:"evidence_bundle_format"`
		EvidenceBundle       string                          `json:"evidence_bundle"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode fleet run: %v body=%s", err, body)
	}
	if run.ID == "" || run.IssuerID != issuerID {
		t.Fatalf("fleet run ids = %+v", run)
	}
	if run.Status != "executed" || run.Phase != "fleet_reissued_and_compromised_revoked" {
		t.Fatalf("fleet run status/phase = %s/%s", run.Status, run.Phase)
	}
	if run.BatchSize != 1 || run.BatchCount != 2 || len(run.Batches) != 2 {
		t.Fatalf("fleet batches = size %d count %d items %#v", run.BatchSize, run.BatchCount, run.Batches)
	}
	if !sameMembers(run.AffectedIdentityIDs, []string{firstID, secondID}) || !sameMembers(run.RevokedIdentityIDs, []string{firstID, secondID}) {
		t.Fatalf("affected/revoked ids = affected %#v revoked %#v", run.AffectedIdentityIDs, run.RevokedIdentityIDs)
	}
	if len(run.ReplacementIdentityIDs) != 2 || len(run.ConnectorDeliveryIDs) != 2 {
		t.Fatalf("replacement/delivery ids = replacements %#v deliveries %#v", run.ReplacementIdentityIDs, run.ConnectorDeliveryIDs)
	}
	if len(run.ConnectorDeliveries) != 2 {
		t.Fatalf("connector delivery evidence = %#v, want two queued intents", run.ConnectorDeliveries)
	}
	for _, delivery := range run.ConnectorDeliveries {
		if delivery.Status != "queued" || delivery.Attempts != 0 || delivery.Status == "delivered" {
			t.Fatalf("pre-worker fleet delivery evidence = %+v, want queued/0 and never delivered", delivery)
		}
	}
	if !bytes.Contains(run.GraphImpact, []byte(`"id":"iss:`+issuerID+`"`)) {
		t.Fatalf("graph impact does not anchor the compromised issuer: %s", run.GraphImpact)
	}
	if len(run.HealthGates) != 2 || run.HealthGates[0].Status != "passed" {
		t.Fatalf("health gates = %#v", run.HealthGates)
	}
	if len(run.FailedTargets) != 0 {
		t.Fatalf("queued fleet connector intents were presented as failed targets: %#v", run.FailedTargets)
	}
	if len(run.RollbackRefs) < 7 || !strings.Contains(strings.Join(run.RollbackRefs, " "), "previous fullchain") {
		t.Fatalf("rollback refs = %#v", run.RollbackRefs)
	}
	if run.EvidenceBundleFormat != "jws" || strings.Count(run.EvidenceBundle, ".") != 2 {
		t.Fatalf("evidence bundle = format %q bundle %q; want compact JWS", run.EvidenceBundleFormat, run.EvidenceBundle)
	}

	for _, id := range []string{firstID, secondID} {
		code, identityBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+id, adminToken, "", nil)
		if code != http.StatusOK || !bytes.Contains(identityBody, []byte(`"status":"revoked"`)) {
			t.Fatalf("compromised identity %s after fleet run = %d body=%s; want revoked", id, code, identityBody)
		}
	}
	for _, id := range run.ReplacementIdentityIDs {
		code, identityBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+id, adminToken, "", nil)
		if code != http.StatusOK || !bytes.Contains(identityBody, []byte(`"status":"deployed"`)) {
			t.Fatalf("replacement identity %s after fleet run = %d body=%s; want deployed", id, code, identityBody)
		}
	}

	code, listBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/fleet-reissuance-runs?issuer_id="+issuerID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(listBody, []byte(run.ID)) {
		t.Fatalf("list fleet runs = %d body=%s; want run id", code, listBody)
	}
	code, getBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/fleet-reissuance-runs/"+run.ID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(getBody, []byte(run.ConnectorDeliveryIDs[0])) {
		t.Fatalf("get fleet run = %d body=%s; want connector delivery evidence", code, getBody)
	}
	code, pauseBody := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+run.ID+"/pause", adminToken, "fleet-pause-1", map[string]string{"reason": "freeze while edge health is inspected"})
	if code != http.StatusOK || !bytes.Contains(pauseBody, []byte(`"status":"paused"`)) {
		t.Fatalf("pause fleet run = %d body=%s; want paused", code, pauseBody)
	}
	code, resumeBody := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+run.ID+"/resume", adminToken, "fleet-resume-1", map[string]string{"reason": "edge health clear"})
	if code != http.StatusOK || !bytes.Contains(resumeBody, []byte(`"phase":"resume_recorded"`)) {
		t.Fatalf("resume fleet run = %d body=%s; want resume phase", code, resumeBody)
	}
	code, rollbackBody := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/fleet-reissuance-runs/"+run.ID+"/rollback", adminToken, "fleet-rollback-1", map[string]string{
		"reason":       "operator rollback drill",
		"rollback_ref": "restore old edge bindings from signed runbook",
	})
	if code != http.StatusOK || !bytes.Contains(rollbackBody, []byte(`"status":"rollback_recorded"`)) || !bytes.Contains(rollbackBody, []byte("signed runbook")) {
		t.Fatalf("rollback fleet run = %d body=%s; want rollback evidence", code, rollbackBody)
	}
	code, evidenceBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/fleet-reissuance-runs/"+run.ID+"/evidence", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(evidenceBody, []byte(run.EvidenceBundle)) || !bytes.Contains(evidenceBody, []byte("signed runbook")) {
		t.Fatalf("fleet evidence export = %d body=%s; want signed bundle and rollback refs", code, evidenceBody)
	}

	var sawRecords int
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == projections.EventIncidentFleetReissuanceRecorded && ev.TenantID == tenantID && bytes.Contains(ev.Data, []byte(run.ID)) {
			sawRecords++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if sawRecords < 4 {
		t.Fatalf("incident.fleet_reissuance.recorded events = %d, want start+pause+resume+rollback", sawRecords)
	}
}

func createX509IssuerWithToken(t *testing.T, ts *httptest.Server, token string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/issuers", token, "fleet-issuer", map[string]any{
		"kind":     "x509_ca",
		"name":     "compromised intermediate",
		"chain":    []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		"internal": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create issuer = %d, want 201; body=%s", code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode issuer id: %v body=%s", err, body)
	}
	return got.ID
}

func createIdentityWithIssuerWithToken(t *testing.T, ts *httptest.Server, token, ownerID, issuerID, name, idem string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/identities", token, idem, map[string]any{
		"kind":      "x509_certificate",
		"name":      name,
		"owner_id":  ownerID,
		"issuer_id": issuerID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create identity %s = %d, want 201; body=%s", name, code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id: %v body=%s", err, body)
	}
	return got.ID
}

func sameMembers(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, v := range got {
		seen[v]++
	}
	for _, v := range want {
		if seen[v] == 0 {
			return false
		}
		seen[v]--
	}
	return true
}
