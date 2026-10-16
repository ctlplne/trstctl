// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// Queuing an import is not proof that the foreign chain verified. Only the
// worker's signed bridge result may appear in the trusted bridge list.
func TestFederationBridge_UnverifiedImportNotServed(t *testing.T) {
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
	local, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "deploy-east", "deploy-east", tenantA)
	if err != nil {
		t.Fatalf("local federation genesis fixture: %v", err)
	}
	if err := pcasstore.New(cs).PutGenesis(ctx, tenantA, pcasstore.GenesisAnchor{
		Genesis: local.Genesis, TrustRootPublicDER: local.TrustRootPubDER,
		EventID: "test-local-federation-genesis", RequestID: "test-local-federation-genesis",
	}); err != nil {
		t.Fatalf("store local federation genesis fixture: %v", err)
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

	// A real PKIX public key, not a placeholder string. The old fixture was
	// literally []byte("foreign-root-der-bytes") and round-tripped fine, which is
	// the defect restating itself: nothing validated what was persisted as a
	// federation trust anchor.
	trustRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trustRootKey.Destroy)
	trustRoot := trustRootKey.Public().DER
	body, err := json.Marshal(map[string]any{
		"foreign_deployment_id":  "deploy-west",
		"local_deployment_id":    "deploy-east",
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
	if list.Count != 0 || len(list.Bridges) != 0 {
		t.Fatalf("queued unverified import is already trusted: count=%d bridges=%d body=%s", list.Count, len(list.Bridges), rr.Body.String())
	}
}
