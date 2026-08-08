// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/usage"
)

// L2's quota gate at the served issuance surface.
//
// The checker itself is Provider-tier (ee/billing) and proves its refusal
// against real PostgreSQL in its own package; this test cuts at the CORE seam
// it plugs into — usage.AllowCreate — and proves the served route consults the
// gate, classifies the refusal as a structured 429, and never reaches the
// orchestrator for an over-cap tenant. Community builds install no checker, so
// the same route with the default allow-all is also asserted to keep working.

type cappedQuota struct {
	refuse   bool
	consults int
}

func (c *cappedQuota) AllowCreate(_ context.Context, tenantID, resource string) error {
	c.consults++
	if c.refuse {
		return fmt.Errorf("quota exhausted: tenant %s has 2 of 2 %s: %w", tenantID, resource, usage.ErrQuotaExhausted)
	}
	return nil
}

func TestServedIssuanceConsultsTheQuotaGateAndRefuses429(t *testing.T) {
	checker := &cappedQuota{}
	usage.SetQuotaChecker(checker)
	t.Cleanup(func() { usage.SetQuotaChecker(nil) })

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:issue")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "quota-owner", "email": "q@example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d: %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "quota.example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatal(err)
	}

	// Over the cap: the served transition must refuse 429 BEFORE the
	// orchestrator accepts anything — a quota discovered in the outbox worker
	// is an opaque retry loop, not an answer.
	checker.refuse = true
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "over cap",
	})
	if status != http.StatusTooManyRequests {
		t.Fatalf("over-cap issuance = %d, want 429.\n\n"+
			"The quota gate existed for a full epic with ZERO callers: the checker was installed, "+
			"consulted nothing, and every cap was decorative. This test is the caller.\nbody: %s",
			status, body)
	}
	if checker.consults == 0 {
		t.Fatal("the route refused without consulting the checker; whatever refused, it was not the quota")
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("429 body is not problem+json: %v (%s)", err, body)
	}
	if problem.Detail == "" {
		t.Fatal("the 429 carries no detail; a caller cannot see which cap they hit")
	}

	// Identity must still be pending: nothing was accepted.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+ident.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read identity = %d", status)
	}
	var got struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status == "issued" {
		t.Fatal("an over-cap tenant's identity reached issued; the 429 was cosmetic")
	}

	// Under the cap the same transition proceeds.
	checker.refuse = false
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "under cap",
	})
	if status != http.StatusOK {
		t.Fatalf("under-cap issuance = %d: %s", status, body)
	}
}
