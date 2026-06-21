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

// JOURNEY-004 acceptance: the incident path is not a plan-only page. A served
// operator request executes replacement-before-revocation over HTTP, records
// connector delivery evidence, seals an audit bundle, persists an
// incident.execution.recorded event, and exposes list/get evidence.
func TestServedIncidentExecutionIssuesReplacementRevokesAndSealsEvidence(t *testing.T) {
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
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "incident-commander", []string{
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.IncidentsRead), string(authz.IncidentsWrite),
		string(authz.CertsIssue), string(authz.GraphRead),
		string(authz.ConnectorsRead), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("journey-004-audit")
	if err != nil {
		_ = log.Close()
		t.Fatalf("generate audit key: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	compromisedID := createIdentityWithToken(t, ts, adminToken, owner.ID)
	if code, body := transitionIdentityWithToken(t, ts, adminToken, compromisedID, "issued", "incident-compromised-issued"); code != http.StatusOK {
		t.Fatalf("issue compromised identity = %d, want 200; body=%s", code, body)
	}

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/incidents/executions", adminToken, "incident-execute-1", map[string]any{
		"identity_id":           compromisedID,
		"reason":                "private key export detected",
		"replacement_name":      "svc.example.test-incident-replacement",
		"connector":             "nginx",
		"target":                "edge/prod/payments",
		"delivery_rollback_ref": "restore edge/prod/payments previous fullchain",
	})
	if code != http.StatusCreated {
		t.Fatalf("execute incident = %d, want 201; body=%s", code, body)
	}
	var execResp struct {
		ID                    string          `json:"id"`
		CompromisedIdentityID string          `json:"compromised_identity_id"`
		ReplacementIdentityID string          `json:"replacement_identity_id"`
		ConnectorDeliveryID   string          `json:"connector_delivery_id"`
		Status                string          `json:"status"`
		Phase                 string          `json:"phase"`
		BlastRadius           json.RawMessage `json:"blast_radius"`
		RevocationStatus      string          `json:"revocation_status"`
		EvidenceBundleFormat  string          `json:"evidence_bundle_format"`
		EvidenceBundle        string          `json:"evidence_bundle"`
		FailedTargets         []string        `json:"failed_targets"`
		RollbackRefs          []string        `json:"rollback_refs"`
		ConnectorDelivery     struct {
			Status      string `json:"status"`
			Connector   string `json:"connector"`
			Target      string `json:"target"`
			RollbackRef string `json:"rollback_ref"`
		} `json:"connector_delivery"`
		ReplacementIdentity struct {
			Status string `json:"status"`
			Name   string `json:"name"`
		} `json:"replacement_identity"`
	}
	if err := json.Unmarshal(body, &execResp); err != nil {
		t.Fatalf("decode incident response: %v body=%s", err, body)
	}
	if execResp.ID == "" || execResp.CompromisedIdentityID != compromisedID || execResp.ReplacementIdentityID == "" || execResp.ConnectorDeliveryID == "" {
		t.Fatalf("incident response missing ids: %+v", execResp)
	}
	if execResp.Status != "executed" || execResp.Phase != "replacement_deployed_and_compromised_revoked" {
		t.Fatalf("incident status/phase = %s/%s", execResp.Status, execResp.Phase)
	}
	if !bytes.Contains(execResp.BlastRadius, []byte(`"id":"id:`+compromisedID+`"`)) {
		t.Fatalf("blast-radius snapshot does not name compromised graph node: %s", execResp.BlastRadius)
	}
	if execResp.RevocationStatus != "revocation_publish_queued" {
		t.Fatalf("revocation status = %q", execResp.RevocationStatus)
	}
	if execResp.EvidenceBundleFormat != "jws" || strings.Count(execResp.EvidenceBundle, ".") != 2 {
		t.Fatalf("evidence bundle = format %q bundle %q; want compact JWS", execResp.EvidenceBundleFormat, execResp.EvidenceBundle)
	}
	if execResp.ConnectorDelivery.Status != "unrouted" || execResp.ConnectorDelivery.Connector != "nginx" || execResp.ConnectorDelivery.Target != "edge/prod/payments" {
		t.Fatalf("connector delivery evidence = %+v", execResp.ConnectorDelivery)
	}
	if len(execResp.FailedTargets) != 1 || !strings.Contains(execResp.FailedTargets[0], "edge/prod/payments") {
		t.Fatalf("failed targets = %#v", execResp.FailedTargets)
	}
	if len(execResp.RollbackRefs) < 3 || !strings.Contains(strings.Join(execResp.RollbackRefs, " "), "previous fullchain") {
		t.Fatalf("rollback refs = %#v", execResp.RollbackRefs)
	}
	if execResp.ReplacementIdentity.Status != "deployed" || execResp.ReplacementIdentity.Name != "svc.example.test-incident-replacement" {
		t.Fatalf("replacement identity evidence = %+v", execResp.ReplacementIdentity)
	}

	code, compromisedBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+compromisedID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(compromisedBody, []byte(`"status":"revoked"`)) {
		t.Fatalf("compromised identity after incident = %d body=%s; want revoked", code, compromisedBody)
	}
	code, replacementBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+execResp.ReplacementIdentityID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(replacementBody, []byte(`"status":"deployed"`)) {
		t.Fatalf("replacement identity after incident = %d body=%s; want deployed", code, replacementBody)
	}
	code, listBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/executions?identity_id="+compromisedID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(listBody, []byte(execResp.ID)) {
		t.Fatalf("list incident executions = %d body=%s; want execution id", code, listBody)
	}
	code, getBody := doBearer(t, ts, http.MethodGet, "/api/v1/incidents/executions/"+execResp.ID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(getBody, []byte(execResp.ConnectorDeliveryID)) {
		t.Fatalf("get incident execution = %d body=%s; want connector delivery id", code, getBody)
	}

	var sawIncidentEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == projections.EventIncidentExecutionRecorded && ev.TenantID == tenantID && bytes.Contains(ev.Data, []byte(execResp.ID)) {
			sawIncidentEvent = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawIncidentEvent {
		t.Fatal("incident.execution.recorded event was not recorded")
	}
}
