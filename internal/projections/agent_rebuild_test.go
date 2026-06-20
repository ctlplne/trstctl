package projections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const replayAgentID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

func appendJSONEvent(t *testing.T, log *events.Log, typ, tenantID string, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", typ, err)
	}
	ev, err := log.Append(context.Background(), events.Event{Type: typ, TenantID: tenantID, Data: data})
	if err != nil {
		t.Fatalf("append %s: %v", typ, err)
	}
	return ev
}

// TestAgentHeartbeatRebuildFeedsAgentsAPI pins ARCH-002: agent liveness is not
// independent PostgreSQL state. A rebuild from the event log alone reconstructs
// agents, and the served GET /api/v1/agents surface reads that rebuilt projection.
func TestAgentHeartbeatRebuildFeedsAgentsAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)

	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
	appendJSONEvent(t, log, projections.EventAgentHeartbeat, tenantA, projections.AgentHeartbeat{
		ID: replayAgentID, Agent: "edge-replay-1", Version: "1.2.3", Status: "active", CertSerial: "01",
	})
	appendJSONEvent(t, log, projections.EventAgentHeartbeat, tenantA, projections.AgentHeartbeat{
		ID: replayAgentID, Agent: "edge-replay-1", Version: "1.2.4", Status: "degraded", CertSerial: "02",
	})
	appendJSONEvent(t, log, projections.EventAgentCertRenewed, tenantA, projections.AgentCertRenewed{
		ID: replayAgentID, Agent: "edge-replay-1", OldSerial: "02", NewSerial: "03",
	})

	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	handler := api.New(s,
		orchestrator.NewIdempotency(s),
		orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)),
	)
	token := mintToken(t, s, "agents:read")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/agents = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	var body struct {
		Agents []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Status  string `json:"status"`
			Version string `json:"version"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode agents response: %v", err)
	}
	if len(body.Agents) != 1 {
		t.Fatalf("agents = %+v, want exactly one rebuilt agent", body.Agents)
	}
	got := body.Agents[0]
	if got.ID != replayAgentID || got.Name != "edge-replay-1" || got.Status != "degraded" || got.Version != "1.2.4" {
		t.Fatalf("rebuilt agent = %+v, want id/name/status/version from heartbeat projection", got)
	}

	agents, err := s.ListAgentsPage(ctx, tenantA, nil, store.ZeroUUID, 20)
	if err != nil {
		t.Fatalf("ListAgentsPage: %v", err)
	}
	if len(agents) != 1 || agents[0].LastSeenAt == nil {
		t.Fatalf("store agents after rebuild = %+v, want one liveness-projected row", agents)
	}
}

func TestReadModelTablesClassifyLogRebuiltTables(t *testing.T) {
	if !containsTable(store.ReadModelTables, "agents") {
		t.Fatal("agents must be in store.ReadModelTables so rebuild/snapshot/backup classification matches ARCH-002")
	}
	if !containsTable(store.ReadModelTables, "certificate_profiles") {
		t.Fatal("certificate_profiles must be in store.ReadModelTables so profile state rebuilds from the event log")
	}
	if !containsTable(store.ReadModelTables, "ca_issued_certs") {
		t.Fatal("ca_issued_certs must be in store.ReadModelTables so OCSP/CRL state rebuilds from the event log")
	}
	if !containsTable(store.ReadModelTables, "ca_crls") {
		t.Fatal("ca_crls must be in store.ReadModelTables so CRL publication rebuilds from the event log")
	}
}

// TestRevocationResponderStateRebuildsFromLog pins CORRECT-002 / RED-002: the
// OCSP and CRL serving tables are projections, not sidecar PostgreSQL state. A
// rebuild from the event log alone must recreate the issued serial, its revocation
// status, and the latest CRL bytes.
func TestRevocationResponderStateRebuildsFromLog(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: embedded PostgreSQL + NATS")
	}
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	caID := "00000000-0000-0000-0000-00000000ca02"
	serial := "red-002-serial"
	fingerprint := "RED:002:FP"
	now := time.Now().UTC().Truncate(time.Second)

	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
	appendJSONEvent(t, log, projections.EventCertificateRecorded, tenantA, projections.CertificateRecorded{
		ID: "00000000-0000-0000-0000-00000000c201", CAID: caID,
		Subject: "CN=red-002.test", Serial: serial, Fingerprint: fingerprint,
		Issuer: "trstctl Issuing CA", KeyAlgorithm: "ECDSA-P256", Source: "issued",
	})
	appendJSONEvent(t, log, projections.EventCertificateRevoked, tenantA, projections.CertificateRevoked{
		CAID: caID, Serial: serial, Fingerprint: fingerprint, Reason: "keyCompromise", ReasonCode: 1, RevokedAt: now,
	})
	payload, err := json.Marshal(projections.CRLPublished{
		CAID: caID, Number: 7, DER: []byte{0x30, 0x03, 0x02, 0x01, 0x07},
		ThisUpdate: now, NextUpdate: now.Add(24 * time.Hour), RevokedCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventCRLPublished, TenantID: tenantA,
		SchemaVersion: projections.CRLPublishedEventSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatalf("append CRL event: %v", err)
	}

	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	issued, found, err := s.LookupIssuedCert(ctx, tenantA, caID, serial)
	if err != nil {
		t.Fatalf("LookupIssuedCert: %v", err)
	}
	if !found || !issued.Revoked() || issued.ReasonCode != 1 {
		t.Fatalf("rebuilt issued cert = %+v found=%v, want revoked reason 1", issued, found)
	}
	crl, found, err := s.LatestCRL(ctx, tenantA, caID)
	if err != nil {
		t.Fatalf("LatestCRL: %v", err)
	}
	if !found || crl.Number != 7 || string(crl.DER) != string([]byte{0x30, 0x03, 0x02, 0x01, 0x07}) {
		t.Fatalf("rebuilt CRL = %+v found=%v, want number 7 with DER from event", crl, found)
	}
}

func containsTable(tables []string, table string) bool {
	for _, got := range tables {
		if got == table {
			return true
		}
	}
	return false
}
