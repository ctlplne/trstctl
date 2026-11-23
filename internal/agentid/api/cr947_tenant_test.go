// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The intake rejects an obviously foreign signed tenant before creating a
// durable issuance job. The signer still checks the signature and tenant again.
func TestCR947IssuanceIntakeRejectsForeignRecordTenant(t *testing.T) {
	chain, err := json.Marshal(delegation.PreconditionsBody{Chain: []delegation.RecordEnvelope{
		{Record: delegation.Record{TenantID: "tenant-A"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	svc := agidapi.NewService(nil, nil, nil)
	if _, err := svc.IssueChainBound(context.Background(), "tenant-B", agidapi.IssueChainBoundRequest{AgentID: "agent", Chain: chain}); err == nil {
		t.Fatal("foreign-tenant delegation chain was accepted for an issuance job")
	}
	if _, err := svc.IssueChainBound(context.Background(), "tenant-A", agidapi.IssueChainBoundRequest{AgentID: "agent", Chain: chain}); err != nil {
		t.Fatalf("matching-tenant chain was rejected before signer verification: %v", err)
	}
}

func TestCR947ServedIssuanceRefusesForeignTenantBeforeQueue(t *testing.T) {
	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"
	chain, err := json.Marshal(delegation.PreconditionsBody{Chain: []delegation.RecordEnvelope{
		{Record: delegation.Record{TenantID: tenantA}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(agidapi.IssueChainBoundRequest{AgentID: "agent", Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	served := coreapi.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		coreapi.WithInsecureHeaderResolver(),
		coreapi.WithLicensedRoutes(agidapi.Routes(agidapi.NewService(nil, nil, nil))...))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent-delegation/issuances", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", t.Name())
	request.Header.Set("X-Tenant-ID", tenantB)
	request.Header.Set("X-Subject", "cr947-fleet")
	request.Header.Set("X-Roles", "cli")
	response := httptest.NewRecorder()
	served.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "another tenant") {
		t.Fatalf("foreign-tenant issuance = %d %s, want actionable 400", response.Code, response.Body.String())
	}
}
