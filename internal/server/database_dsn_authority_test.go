// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/dynsecret"
)

func TestConfiguredDatabaseOpensRejectMalformedDSNBeforeDriverUse(t *testing.T) {
	ref := writeServedCredentialFile(t, "database-connection", "host=")
	provider := &configuredDynamicProvider{
		tenantID: servedTestTenant,
		cfg: config.DynamicSecretProviderConfig{
			Type: "postgresql", AdminDSNRef: ref, Database: "orders",
		},
	}
	opener := &configuredDynamicBackendOpener{ctx: t.Context(), provider: provider}
	_, closeBackend, err := openConfiguredDatabaseBackend(opener)
	defer closeBackend()
	if err == nil {
		t.Error("a malformed admin DSN reached backend construction")
	}
	if _, _, err := provider.DynamicSecretGatewayTLS(t.Context()); err == nil {
		t.Error("the gateway treated a malformed admin DSN as a session with no private trust")
	}
}

func TestConfiguredDatabaseDSNLoadsAreBounded(t *testing.T) {
	ref := writeServedCredentialFile(t, "database-connection", strings.Repeat("x", 64*1024+1))
	provider := &configuredDynamicProvider{
		tenantID:    servedTestTenant,
		cfg:         config.DynamicSecretProviderConfig{Type: "postgresql", AdminDSNRef: ref},
		credentials: integrationCredentialResolver{kek: serverTestPrincipalKEK()},
	}
	opener := &configuredDynamicBackendOpener{ctx: t.Context(), provider: provider}
	defer opener.destroyCredentials()
	if value, err := opener.resolve(ref); err == nil || value != nil {
		t.Error("the database opener retained a DSN above the size bound")
	}
	if _, _, err := provider.DynamicSecretGatewayTLS(t.Context()); err == nil {
		t.Error("gateway trust construction accepted an oversized admin DSN")
	}
	if _, err := provider.ResolveStaticRotationReceiverAuthority(t.Context()); err == nil {
		t.Error("static receiver binding accepted an oversized admin DSN")
	}
}

func TestServedTenantDatabaseDSNRechecksTrustAndEgressAfterStoreUpdate(t *testing.T) {
	const name = "review/database-admin"
	ca, _, _, err := certtest.PrivateCAServer("db.test")
	if err != nil {
		t.Fatal(err)
	}
	caRef := writeServedCredentialFile(t, "database-root.pem", string(ca))
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "database DSN custody")
	writer := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	storeValue := func(key, value string, create bool) {
		t.Helper()
		method, path := http.MethodPut, "/api/v1/secrets/store/"+name
		body := map[string]any{"value": value}
		if create {
			method, path = http.MethodPost, "/api/v1/secrets/store"
			body["name"] = name
		}
		status, _ := secretsReqKey(t, h, method, path, writer, key, body)
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("store database fixture version: %d", status)
		}
	}
	ctx := t.Context()
	provider := &configuredDynamicProvider{id: "review-database", tenantID: h.tenant,
		cfg: config.DynamicSecretProviderConfig{Type: "postgresql", AdminDSNRef: "secret://" + name,
			TLSCARef: caRef, TLSServerName: "db.test", Database: "orders"},
		credentials: integrationCredentialResolver{store: h.store, kek: h.kek}}
	storeValue("review-first-dsn", "postgres://review:plain@db.test/orders?sslmode=verify-full", true)
	trust, serverName, err := provider.DynamicSecretGatewayTLS(ctx)
	if err != nil || !bytes.Equal(trust, ca) || serverName != "db.test" {
		t.Fatal("the tenant-held DSN could not use the explicit operator CA")
	}
	storeValue("review-second-dsn", "postgres://review:plain@db.test/orders?sslmode=verify-full&sslrootcert=unused", false)
	if value, _, err := provider.DynamicSecretGatewayTLS(ctx); err == nil || len(value) != 0 {
		t.Fatal("the replacement tenant DSN selected a trust file")
	}
	storeValue("review-third-dsn", "postgres://review:plain@127.0.0.1:5432/orders?sslmode=verify-full", false)
	opener := &configuredDynamicBackendOpener{provider: provider, ctx: ctx}
	if _, cleanup, err := openConfiguredDatabaseBackend(opener); err == nil {
		cleanup()
		t.Fatal("the replacement tenant DSN used unapproved private egress")
	}
	provider.cfg.AllowPrivate = true
	provider.cfg.PrivateEgressCIDRs = []string{"127.0.0.1/32"}
	opener = &configuredDynamicBackendOpener{provider: provider, ctx: ctx}
	backend, cleanup, err := openConfiguredDatabaseBackend(opener)
	defer cleanup()
	if _, ok := backend.(*dynsecret.PostgresBackend); err != nil || !ok {
		t.Fatalf("the exact approved private TCP route was refused before use: %v", err)
	}
}
