package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

const (
	connectorTenantA = "11111111-1111-1111-1111-111111111111"
	connectorTenantB = "22222222-2222-2222-2222-222222222222"
)

func TestOutboxCircuitStatusIsTenantFiltered(t *testing.T) {
	now := time.Date(2026, 6, 21, 14, 0, 0, 0, time.UTC)
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithOutboxCircuitStatus(func() []orchestrator.CircuitSnapshot {
			return []orchestrator.CircuitSnapshot{
				{
					TenantID: connectorTenantA, Destination: "connector.deploy", State: orchestrator.CircuitOpen,
					Failures: 3, OpenUntil: now.Add(time.Minute), UpdatedAt: now, LastError: "upstream unavailable",
				},
				{
					TenantID: connectorTenantB, Destination: "webhook.audit", State: orchestrator.CircuitOpen,
					Failures: 5, OpenUntil: now.Add(2 * time.Minute), UpdatedAt: now, LastError: "other tenant",
				},
			}
		}),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/outbox-circuits", nil)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []struct {
			TenantID    string `json:"tenant_id"`
			Destination string `json:"destination"`
			State       string `json:"state"`
			Failures    int    `json:"failures"`
			LastError   string `json:"last_error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %+v, want exactly the caller tenant circuit", body.Items)
	}
	got := body.Items[0]
	if got.TenantID != connectorTenantA || got.Destination != "connector.deploy" || got.State != "open" || got.Failures != 3 {
		t.Fatalf("circuit = %+v, want tenant A connector.deploy/open/3", got)
	}
	if got.LastError != "upstream unavailable" {
		t.Fatalf("last_error = %q", got.LastError)
	}
}
