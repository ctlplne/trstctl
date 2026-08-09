// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	succapi "trstctl.com/trstctl/ee/succession/api"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// TestFederationBridge_ImportThenListRoundTrip is the AUD-9 regression:
// pcas_federation_bridge was WRITE-ONLY state — POST persisted the foreign
// deployment id, trust root and base epoch under RLS, and the only SELECT in
// the tree was a test row count. This drives the SERVED routes end to end:
// import a bridge, then assert the served list returns it with the foreign
// deployment id and the trust-root digest. A store-level round trip would pass
// on the pre-fix tree and prove nothing about reachability.
func TestFederationBridge_ImportThenListRoundTrip(t *testing.T) {
	ctx := context.Background()
	base, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin open: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "DROP DATABASE IF EXISTS pcas_bridge_list"); err != nil {
		t.Fatalf("drop db: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "CREATE DATABASE pcas_bridge_list"); err != nil {
		t.Fatalf("create db: %v", err)
	}
	base.Close()
	cs, err := corestore.Open(ctx, strings.TrimSuffix(testDSN, "/postgres")+"/pcas_bridge_list")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	factory := succapi.NewAPIOptionsFactory()
	licensed, err := factory(editionseam.LicensedAPIOptionsDeps{Store: cs, Outbox: orchestrator.NewOutbox(cs)})
	if err != nil {
		t.Fatalf("api options factory: %v", err)
	}
	principal := authz.Principal{TenantID: tenantA, Subject: "op", Grants: []authz.Grant{{Role: pcasRole, Scope: authz.Scope{TenantID: tenantA}}}}
	served := api.New(cs, orchestrator.NewIdempotency(cs), nil, append([]api.Option{
		api.WithRoles(pcasRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	}, licensed...)...)

	trustRoot := []byte("foreign-root-der-bytes")
	body, err := json.Marshal(map[string]any{
		"foreign_deployment_id":  "deploy-west",
		"local_deployment_id":    "deploy-east",
		"local_authority_handle": "auth-1",
		"identity_id":            "spiffe://d/id",
		"foreign_trust_root_der": base64.StdEncoding.EncodeToString(trustRoot),
		"foreign_genesis":        base64.StdEncoding.EncodeToString([]byte("genesis-record")),
		"local_base_epoch":       7,
	})
	if err != nil {
		t.Fatalf("encode import request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/federation/imports", bytes.NewReader(body))
	req.Header.Set("Idempotency-Key", "bridge-import-1")
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST federation import = %d body=%s, want 202", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	served.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/pcas/federation/bridges", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET federation bridges = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var list succapi.FederationBridgeListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode bridge list: %v", err)
	}
	if list.Count != 1 || len(list.Bridges) != 1 {
		t.Fatalf("bridge list count=%d bridges=%d, want exactly the imported bridge (body=%s)", list.Count, len(list.Bridges), rr.Body.String())
	}
	got := list.Bridges[0]
	if got.ForeignDeploymentID != "deploy-west" || got.IdentityID != "spiffe://d/id" || got.LocalBaseEpoch != 7 {
		t.Fatalf("served bridge = %+v, want deploy-west/spiffe://d/id/epoch 7", got)
	}
	wantDigest := hex.EncodeToString(crypto.SHA256Sum(trustRoot))
	if got.TrustRootSHA256 != wantDigest {
		t.Fatalf("served trust-root digest = %q, want %q — the operator must be able to compare the imported root against the foreign deployment's published one", got.TrustRootSHA256, wantDigest)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("served bridge carries no updated_at timestamp")
	}
}
