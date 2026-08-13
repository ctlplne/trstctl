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

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// AUD-69 assembled proof: the browser-side request editor is backed by real
// tenant-scoped routes. This test deliberately uses the same short-lived token
// create/revoke flow and the exact pagination, object-path, mutation-body, and
// problem-response requests the Explorer sends.
func TestAUD69APIExplorerRequestAndTokenJourney(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and JetStream; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "69696969-6969-4696-8969-696969696969"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "aud69"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "explorer-owner"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	admin := seedServedAPIToken(t, ctx, st, tenantID, "platform-admin", []string{
		string(authz.AccessRead), string(authz.AccessWrite),
		string(authz.AccessRoleAssign),
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.CertsRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	openAPICode, openAPIBody := doBearer(t, ts, http.MethodGet, "/api/v1/openapi.json", admin, "", nil)
	if openAPICode != http.StatusOK || !bytes.Contains(openAPIBody, []byte(`"operationId":"listCertificates"`)) ||
		!bytes.Contains(openAPIBody, []byte(`"name":"limit"`)) || !bytes.Contains(openAPIBody, []byte(`"name":"Idempotency-Key"`)) {
		t.Fatalf("served Explorer contract = %d body=%s", openAPICode, openAPIBody)
	}

	upsertMember(t, ts, admin, "explorer-operator", []string{"operator"})
	writeToken := mintAUD69ExplorerToken(t, ts, admin, "explorer-write", []string{string(authz.IdentitiesWrite)}, time.Now().Add(15*time.Minute))
	createCode, createBody := doBearer(t, ts, http.MethodPost, "/api/v1/identities", writeToken.Token, "aud69-create-payments-api", map[string]any{
		"kind":     "x509_certificate",
		"name":     "payments-api",
		"owner_id": owner.ID,
	})
	if createCode != http.StatusCreated {
		t.Fatalf("edited identity mutation = %d body=%s", createCode, createBody)
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(createBody, &created); err != nil || created.ID == "" || created.Name != "payments-api" {
		t.Fatalf("edited mutation response = %#v err=%v body=%s", created, err, createBody)
	}

	readToken := mintAUD69ExplorerToken(t, ts, admin, "explorer-read", []string{string(authz.IdentitiesRead)}, time.Now().Add(15*time.Minute))
	readCode, readBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+created.ID, readToken.Token, "", nil)
	if readCode != http.StatusOK || !bytes.Contains(readBody, []byte(`"name":"payments-api"`)) {
		t.Fatalf("real selected-object path = %d body=%s", readCode, readBody)
	}
	missingCode, missingBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/00000000-0000-4000-8000-000000000099", readToken.Token, "", nil)
	if missingCode != http.StatusNotFound || !bytes.Contains(missingBody, []byte(`"status":404`)) {
		t.Fatalf("problem response = %d body=%s", missingCode, missingBody)
	}

	revokeCode, revokeBody := doBearer(t, ts, http.MethodDelete, "/api/v1/access/api-tokens/"+readToken.ID, admin, "aud69-revoke-read-key", nil)
	if revokeCode != http.StatusNoContent {
		t.Fatalf("revoke test key = %d body=%s", revokeCode, revokeBody)
	}
	revokedCode, revokedBody := doBearer(t, ts, http.MethodGet, "/api/v1/identities/"+created.ID, readToken.Token, "", nil)
	if revokedCode != http.StatusUnauthorized {
		t.Fatalf("revoked test key request = %d body=%s", revokedCode, revokedBody)
	}

	expiring := mintAUD69ExplorerToken(t, ts, admin, "explorer-pagination", []string{string(authz.CertsRead)}, time.Now().Add(2*time.Second))
	pageCode, pageBody := doBearer(t, ts, http.MethodGet, "/api/v1/certificates?limit=1", expiring.Token, "", nil)
	if pageCode != http.StatusOK || !bytes.Contains(pageBody, []byte(`"items"`)) {
		t.Fatalf("optional pagination request = %d body=%s", pageCode, pageBody)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		expiredCode, expiredBody := doBearer(t, ts, http.MethodGet, "/api/v1/certificates?limit=1", expiring.Token, "", nil)
		if expiredCode == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired test key remained usable: status=%d body=%s", expiredCode, expiredBody)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type aud69ExplorerToken struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func mintAUD69ExplorerToken(t *testing.T, ts *httptest.Server, admin, subject string, scopes []string, expiresAt time.Time) aud69ExplorerToken {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/api-tokens", admin, "aud69-token-"+subject, map[string]any{
		"subject": subject, "scopes": scopes, "expires_at": expiresAt.UTC().Format(time.RFC3339Nano),
	})
	if code != http.StatusCreated {
		t.Fatalf("mint Explorer token %s = %d body=%s", subject, code, body)
	}
	var token aud69ExplorerToken
	if err := json.Unmarshal(body, &token); err != nil || token.ID == "" || !strings.HasPrefix(token.Token, "trst_") {
		t.Fatalf("decode Explorer token %s = %#v err=%v body=%s", subject, token, err, body)
	}
	return token
}
