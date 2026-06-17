package projections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

	agents, err := s.ListAgents(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].LastSeenAt == nil {
		t.Fatalf("store agents after rebuild = %+v, want one liveness-projected row", agents)
	}
}

func TestReadModelTablesClassifyAgentsAsLogRebuild(t *testing.T) {
	if !containsTable(store.ReadModelTables, "agents") {
		t.Fatal("agents must be in store.ReadModelTables so rebuild/snapshot/backup classification matches ARCH-002")
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
