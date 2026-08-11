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
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// IAM-05 acceptance: ABAC is a deny overlay on top of served RBAC + the OPA
// policy gate. RBAC gives the operator certs:issue, and the base policy allows
// because a profile is bound; the ABAC module still denies prod certificate
// issuance outside the configured change window. A staging certificate proves the
// overlay narrows access rather than replacing RBAC.
func TestServedABACDenyOverlayEnforcesChangeWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	storeServerTestProfile(t, st, tenantID, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"},
		MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store:            st,
		Log:              log,
		DefaultProfile:   "tls-server",
		EnablePolicyGate: true,
		EnableABAC:       true,
		ABACModule:       servedABACChangeWindowPolicy,
		ABACEnvironment:  map[string]string{"change_window": "false"},
		APIOptions:       []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build control plane: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	prodID := createABACIdentityServed(t, ts, tenantID, owner.ID, "prod-api", map[string]any{
		"env": "prod",
		"tags": map[string]any{
			"service": "payments",
		},
	})
	if code, body := transitionABACIdentity(t, ts, tenantID, prodID, "issue-prod"); code != http.StatusForbidden || !bytes.Contains(bytes.ToLower(body), []byte("change window")) {
		t.Fatalf("prod issue outside change window = %d body=%s; want 403 ABAC change-window denial", code, body)
	}
	prod, err := st.GetIdentity(ctx, tenantID, prodID)
	if err != nil {
		t.Fatalf("load prod identity: %v", err)
	}
	if prod.Status != "requested" {
		t.Fatalf("ABAC-denied prod identity status = %q, want requested", prod.Status)
	}

	stagingID := createABACIdentityServed(t, ts, tenantID, owner.ID, "staging-api", map[string]any{
		"env": "staging",
	})
	if code, body := transitionABACIdentity(t, ts, tenantID, stagingID, "issue-staging"); code != http.StatusOK {
		t.Fatalf("staging issue with RBAC+policy allow = %d body=%s; want 200", code, body)
	}
	staging, err := st.GetIdentity(ctx, tenantID, stagingID)
	if err != nil {
		t.Fatalf("load staging identity: %v", err)
	}
	if staging.Status != "issued" {
		t.Fatalf("staging identity status = %q, want issued", staging.Status)
	}
}

const servedABACChangeWindowPolicy = `package trstctl.abac

default deny := false
default reason := ""

deny if {
	input.permission == "certs:issue"
	input.resource.env == "prod"
	input.env.change_window != "true"
}

reason := "prod cert issuance requires an active change window" if {
	input.permission == "certs:issue"
	input.resource.env == "prod"
	input.env.change_window != "true"
}
`

func createABACIdentityServed(t *testing.T, ts *httptest.Server, tenant, ownerID, name string, attrs map[string]any) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"kind": "x509_certificate", "name": name, "owner_id": ownerID, "attributes": attrs,
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("X-Subject", "seed-bot")
	req.Header.Set("Idempotency-Key", "create-"+strings.ReplaceAll(name, " ", "-"))
	code, b := doReq(t, ts, req)
	if code != http.StatusCreated {
		t.Fatalf("create identity %s = %d, want 201; body=%s", name, code, b)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id for %s: %v; body=%s", name, err, b)
	}
	return got.ID
}

func transitionABACIdentity(t *testing.T, ts *httptest.Server, tenant, identityID, idem string) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"to": "issued", "reason": "abac acceptance"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities/"+identityID+"/transitions", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("X-Subject", "operator")
	req.Header.Set("Idempotency-Key", idem)
	return doReq(t, ts, req)
}
