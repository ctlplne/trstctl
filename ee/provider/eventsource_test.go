// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

type authorityAuthenticator struct{}

func (authorityAuthenticator) AuthenticateOperator(r *http.Request) (Operator, bool) {
	switch r.Header.Get("Authorization") {
	case "Bearer requester":
		return providerOperator("op-1"), true
	case "Bearer approver-a":
		return providerOperator("approver-a"), true
	case "Bearer approver-b":
		return providerOperator("approver-b"), true
	default:
		return Operator{}, false
	}
}

type authorityBrandCache struct{}

func (authorityBrandCache) Invalidate() {}

// AUD-62: provider authority is one immutable history, not five independently
// mutable tables plus a best-effort audit append. This real PostgreSQL/JetStream
// journey deliberately erases every provider read table, replays only the event
// log, and requires the exact customer, delegation, quota, brand, and break-glass
// state to return.
func TestProviderAuthorityRebuildsExactlyFromOneEventHistory(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	projection := NewAuthorityProjection(st)
	mutations := NewEventMutationSink(log, projection)
	tenantID := CustomerID("event-source-acme")
	now := time.Date(2026, 8, 9, 18, 0, 0, 0, time.UTC)
	limit := 37
	grant := BreakGlassGrant{
		ID: "bg-event-source", TenantID: tenantID, OperatorID: "operator-1",
		OperatorEmail: "operator@example.test", Reason: "customer-authorized incident",
		RequestedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
		ConsentedAt: now.Add(2 * time.Minute), ConsentedBy: "approver-1",
		SecondConsentedAt: now.Add(3 * time.Minute), SecondConsentedBy: "approver-2", UseCount: 1,
	}
	eventsToApply := []struct {
		key, typ string
		payload  AuthorityEvent
	}{
		{"provision-1", AuditTenantProvisioned, AuthorityEvent{Tenant: &Tenant{
			ID: tenantID, Slug: "event-source-acme", Name: "Event Source Acme", Status: TenantActive,
			CreatedAt: now, UpdatedAt: now,
		}, Audit: AuditEvent{Type: AuditTenantProvisioned, TenantID: tenantID, OperatorID: "operator-1", At: now}}},
		{"delegation-1", EventDelegationGranted, AuthorityEvent{Delegation: &DelegationMutation{
			OperatorID: "operator-1", CustomerID: tenantID, Operation: OpRead, GrantedBy: "provider-admin",
		}, Audit: AuditEvent{Type: EventDelegationGranted, TenantID: tenantID, OperatorID: "provider-admin", At: now}}},
		{"quota-1", EventTenantQuotaSet, AuthorityEvent{Quota: &billing.Quota{
			TenantID: tenantID, MaxCertificatesStored: &limit, UpdatedBy: "operator@example.test",
		}, Audit: AuditEvent{Type: EventTenantQuotaSet, TenantID: tenantID, OperatorID: "operator-1", At: now}}},
		{"brand-1", EventTenantBrandSet, AuthorityEvent{Brand: &TenantBrand{
			TenantID: tenantID, ProductName: "Acme Trust", CustomDomain: "pki.acme.test",
		}, Audit: AuditEvent{Type: EventTenantBrandSet, TenantID: tenantID, OperatorID: "operator-1", At: now}}},
		{"breakglass-1", AuditBreakGlassRequested, AuthorityEvent{Grant: &grant,
			Audit: AuditEvent{Type: AuditBreakGlassRequested, TenantID: tenantID, OperatorID: "operator-1", GrantID: grant.ID, At: now}}},
	}
	for _, item := range eventsToApply {
		if _, err := mutations.Append(ctx, item.key, item.typ, tenantID, item.payload); err != nil {
			t.Fatalf("Append(%s): %v", item.typ, err)
		}
	}

	want := providerAuthoritySnapshot(t, st, tenantID, grant.ID)
	if want.tenants != 1 || want.delegations != 1 || want.quotas != 1 || want.brands != 1 ||
		want.grants != 1 || want.quotaLimit != limit || want.productName != "Acme Trust" || want.useCount != 1 {
		t.Fatalf("projected authority = %+v, want one exact row in every view", want)
	}

	truncateProviderAuthority(t, st)
	if got := providerAuthoritySnapshot(t, st, tenantID, grant.ID); got.nonzero() {
		t.Fatalf("projection erase left state behind: %+v", got)
	}
	rebuilt := NewAuthorityProjection(st)
	if err := projections.New(st, projections.WithEventProjection(rebuilt)).Project(ctx, log); err != nil {
		t.Fatalf("Project(event history): %v", err)
	}
	if got := providerAuthoritySnapshot(t, st, tenantID, grant.ID); got != want {
		t.Fatalf("rebuilt authority = %+v, want exact pre-erase state %+v", got, want)
	}
}

// AUD-58 assembles the real seams in one journey: a signed IdP token is useful
// only while its SCIM identity is active; the projected grant reveals exactly
// one customer; a restart adds no bootstrap duplicates; and erasing PostgreSQL
// views followed by event replay restores the leaver and revoked authority.
func TestAUD58AssembledIdentityLifecycleScopeRestartAndRebuild(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	operator := OperatorIdentity{
		ID: "provider-op-1", ExternalID: "op-1", UserName: "dana@provider.example",
		Email: "dana@provider.example", DisplayName: "Dana", Role: OperatorAdmin,
		Active: true, Source: "scim:entra", CreatedAt: now, UpdatedAt: now,
	}
	alpha, beta := CustomerID("aud58-alpha"), CustomerID("aud58-beta")
	appendEvent := func(key, typ, tenantID string, payload AuthorityEvent) {
		t.Helper()
		payload.EffectiveAt = now
		if payload.Audit.Type == "" {
			payload.Audit.Type = typ
		}
		if payload.Audit.TenantID == "" {
			payload.Audit.TenantID = tenantID
		}
		payload.Audit.At = now
		if _, appendErr := runtime.Mutations.Append(ctx, key, typ, tenantID, payload); appendErr != nil {
			t.Fatalf("append %s: %v", typ, appendErr)
		}
	}
	appendEvent("aud58-operator", EventOperatorUpserted, providerAuthorityTenant,
		AuthorityEvent{Operator: &operator, Audit: AuditEvent{OperatorID: "scim:entra", Subject: operator.ID}})
	for _, tenant := range []Tenant{
		{ID: alpha, Slug: "aud58-alpha", Name: "AUD58 Alpha", Status: TenantActive, CreatedAt: now, UpdatedAt: now},
		{ID: beta, Slug: "aud58-beta", Name: "AUD58 Beta", Status: TenantActive, CreatedAt: now, UpdatedAt: now},
	} {
		copy := tenant
		appendEvent("aud58-tenant-"+tenant.Slug, AuditTenantProvisioned, tenant.ID,
			AuthorityEvent{Tenant: &copy, Audit: AuditEvent{OperatorID: "bootstrap-admin"}})
	}
	appendEvent("aud58-alpha-read", EventDelegationGranted, alpha, AuthorityEvent{
		Delegation: &DelegationMutation{OperatorID: operator.ID, CustomerID: alpha, Operation: OpRead,
			GrantedBy: "provider-admin", Source: "console"},
		Audit: AuditEvent{OperatorID: "provider-admin", Subject: operator.ID},
	})
	appendEvent("aud58-alpha-suspend", EventDelegationGranted, alpha, AuthorityEvent{
		Delegation: &DelegationMutation{OperatorID: operator.ID, CustomerID: alpha, Operation: OpSuspend,
			GrantedBy: "provider-admin", Source: "console"},
		Audit: AuditEvent{OperatorID: "provider-admin", Subject: operator.ID},
	})

	fixture := newOIDCFixture(t)
	access := NewPGAccessStore(st)
	authenticator := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer: "https://idp.provider.example", Audience: "trstctl-provider", JWKS: fixture.auth.cfg.JWKS,
		RoleClaim: "groups", AdminValues: []string{"trstctl-admins"}, MFAClaim: "amr", MFAValues: []string{"mfa"},
		Directory: access, RequireDirectory: true, Now: func() time.Time { return now },
	})
	handler := NewHandler(Config{
		License: providerLicense(t, 10), Store: NewPGStore(st), Access: access,
		Authenticator: authenticator, Delegations: NewPGDelegationSource(st),
		Mutations: runtime.Mutations,
	})
	request := fixture.request(t, fixture.signer, "idp-k1", fixture.baseClaims())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "AUD58 Alpha") || strings.Contains(response.Body.String(), "AUD58 Beta") {
		t.Fatalf("delegated customer list = %d %s; signed identity must see alpha and not beta", response.Code, response.Body.String())
	}
	alphaSuspend := fixture.request(t, fixture.signer, "idp-k1", fixture.baseClaims())
	alphaSuspend.Method, alphaSuspend.URL.Path = http.MethodPost, "/provider/v1/tenants/"+alpha+"/suspend"
	alphaSuspend.Header.Set("Idempotency-Key", "aud58-suspend-alpha")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, alphaSuspend)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delegated alpha suspend = %d body=%s", response.Code, response.Body.String())
	}
	rows, err := access.ListOperatorAccess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var recordedLastUse bool
	for _, row := range rows {
		for _, delegation := range row.Delegations {
			if delegation.CustomerID == alpha && delegation.Operation == OpSuspend && !delegation.LastUsedAt.IsZero() {
				recordedLastUse = true
			}
		}
	}
	if !recordedLastUse {
		t.Fatalf("successful delegated action did not project last-use evidence: %+v", rows)
	}
	betaSuspend := fixture.request(t, fixture.signer, "idp-k1", fixture.baseClaims())
	betaSuspend.Method, betaSuspend.URL.Path = http.MethodPost, "/provider/v1/tenants/"+beta+"/suspend"
	betaSuspend.Header.Set("Idempotency-Key", "aud58-suspend-beta")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, betaSuspend)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-customer beta suspend = %d body=%s, want 403", response.Code, response.Body.String())
	}

	leaver := operator
	leaver.Active, leaver.UpdatedAt, leaver.DeprovisionedAt = false, now.Add(time.Minute), now.Add(time.Minute)
	appendEvent("aud58-leaver", EventOperatorOffboarded, providerAuthorityTenant,
		AuthorityEvent{Operator: &leaver, Audit: AuditEvent{OperatorID: "scim:entra", Subject: "scim:entra"}})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t, fixture.signer, "idp-k1", fixture.baseClaims()))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("post-deprovision signed token = %d body=%s, want immediate 401", response.Code, response.Body.String())
	}

	headBeforeRestart, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewAuthorityRuntime(st, log)
	if err := restarted.Bootstrap(ctx); err != nil {
		t.Fatalf("restart bootstrap: %v", err)
	}
	headAfterRestart, err := log.LastSequence(ctx)
	if err != nil || headAfterRestart != headBeforeRestart {
		t.Fatalf("restart changed event head %d -> %d err=%v", headBeforeRestart, headAfterRestart, err)
	}

	truncateProviderAuthority(t, st)
	if err := projections.New(st, restarted.ProjectionOptions...).Project(ctx, log); err != nil {
		t.Fatalf("rebuild Provider authority: %v", err)
	}
	rebuiltIdentity, err := access.ResolveOperator(ctx, operator.ID)
	if err != nil || rebuiltIdentity.Active || rebuiltIdentity.DeprovisionedAt.IsZero() {
		t.Fatalf("rebuilt leaver = %+v err=%v", rebuiltIdentity, err)
	}
	delegations, err := NewPGDelegationSource(st).Delegations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actor := Operator{ID: operator.ID, Email: operator.Email, Role: operator.Role, MFA: true}
	if delegations.Authorize(actor, alpha, OpRead) == nil || delegations.Authorize(actor, beta, OpRead) == nil {
		t.Fatalf("rebuilt leaver retained customer authority: %+v", delegations)
	}
	rebuiltRows, err := access.ListOperatorAccess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var retainedLifecycle bool
	for _, row := range rebuiltRows {
		for _, delegation := range row.Delegations {
			if delegation.CustomerID == alpha && delegation.Operation == OpSuspend &&
				!delegation.LastUsedAt.IsZero() && !delegation.RevokedAt.IsZero() && delegation.RevokedBy == "scim:entra" {
				retainedLifecycle = true
			}
		}
	}
	if !retainedLifecycle {
		t.Fatalf("rebuild lost delegated use/revocation lifecycle: %+v", rebuiltRows)
	}
}

// A source-of-truth append can succeed while the synchronous projection fails.
// That is not permission to write the read table directly or append a second
// audit event: replay must finish the first event, and retrying its stable key
// must converge on the same one event and one row.
func TestProviderMutationConvergesAfterAppendProjectionFailure(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	tenantID := CustomerID("projection-failure")
	payload := AuthorityEvent{Tenant: &Tenant{
		ID: tenantID, Slug: "projection-failure", Name: "Projection Failure", Status: TenantActive,
		CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: time.Unix(100, 0).UTC(),
	}, Audit: AuditEvent{Type: AuditTenantProvisioned, TenantID: tenantID, OperatorID: "operator-1", At: time.Unix(100, 0).UTC()}}

	failing := NewAuthorityProjection(st)
	failing.applyHook = func(context.Context, events.Event) error { return errors.New("injected projection failure") }
	if _, err := NewEventMutationSink(log, failing).Append(ctx, "stable-create-key", AuditTenantProvisioned, tenantID, payload); err == nil {
		t.Fatal("append-plus-project returned success after its projection failed")
	}
	if _, err := NewPGStore(st).Tenant(ctx, tenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed projection mutated provider_tenants: %v", err)
	}

	healed := NewAuthorityProjection(st)
	if err := projections.New(st, projections.WithEventProjection(healed)).Project(ctx, log); err != nil {
		t.Fatalf("replay after projection failure: %v", err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, tenantID); err != nil {
		t.Fatalf("replay did not materialize appended tenant: %v", err)
	}
	if _, err := NewEventMutationSink(log, healed).Append(ctx, "stable-create-key", AuditTenantProvisioned, tenantID, payload); err != nil {
		t.Fatalf("identical retry did not converge: %v", err)
	}
	var count int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == AuditTenantProvisioned && event.TenantID == tenantID {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if count != 1 {
		t.Fatalf("stable retry produced %d provision events, want exactly one", count)
	}

	changed := payload
	changedTenant := *payload.Tenant
	changedTenant.Name = "Different Command"
	changed.Tenant = &changedTenant
	if _, err := NewEventMutationSink(log, healed).Append(ctx, "stable-create-key", AuditTenantProvisioned, tenantID, changed); !errors.Is(err, ErrMutationConflict) {
		t.Fatalf("same key with changed command = %v, want ErrMutationConflict", err)
	}
}

// Existing installations already have provider rows written by the pre-AUD-62
// direct stores. The first event-sourced boot must capture each uncovered row
// before the projection reset; a partial/repeated bootstrap must add no duplicate
// events and must never replace newer event history with a stale table snapshot.
func TestProviderAuthorityBootstrapPreservesPreEventRowsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	tenantID := CustomerID("upgrade-acme")
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	limit := 19
	grant := BreakGlassGrant{
		ID: "upgrade-grant", TenantID: tenantID, OperatorID: "upgrade-operator",
		Reason: "upgrade", RequestedAt: now, ExpiresAt: now.Add(time.Hour), UseCount: 2,
	}
	// These are intentionally direct fixtures: they model the five independent
	// pre-AUD-62 stores that an upgraded installation already has before an
	// authority event exists. Production packages expose no equivalent writer.
	for _, fixture := range []struct {
		statement string
		args      []any
	}{
		{`INSERT INTO provider_tenants (tenant_id, slug, name, status, created_at, updated_at)
			VALUES ($1, 'upgrade-acme', 'Upgrade Acme', 'suspended', $2, $3)`,
			[]any{tenantID, now.Add(-time.Hour), now}},
		{`INSERT INTO provider_operator_delegations
			(operator_id, customer_tenant_id, operation, granted_by, granted_at)
			VALUES ('upgrade-operator', $1, 'read', 'upgrade-admin', $2)`, []any{tenantID, now}},
		{`INSERT INTO provider_tenant_quotas
			(tenant_id, max_certificates_stored, updated_by, updated_at)
			VALUES ($1, $2, 'upgrade-admin', $3)`, []any{tenantID, limit, now}},
		{`INSERT INTO tenant_branding
			(tenant_id, product_name, custom_domain, token_overrides, updated_at)
			VALUES ($1, 'Upgrade Trust', 'upgrade.acme.test', $2, $3)`,
			[]any{tenantID, []byte(`{"nav.certificates":"Credentials"}`), now}},
		{`INSERT INTO provider_breakglass_grants
			(id, tenant_id, operator_id, reason, requested_at, expires_at, use_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			[]any{grant.ID, grant.TenantID, grant.OperatorID, grant.Reason,
				grant.RequestedAt, grant.ExpiresAt, grant.UseCount}},
	} {
		if _, err := st.SystemPool().Exec(ctx, fixture.statement, fixture.args...); err != nil {
			t.Fatalf("seed pre-event authority fixture: %v", err)
		}
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	if err := runtime.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap(first): %v", err)
	}
	firstHead, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("LastSequence(first): %v", err)
	}
	if firstHead != 5 {
		t.Fatalf("bootstrap event count = %d, want one event for each of five existing rows", firstHead)
	}
	if err := runtime.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap(retry): %v", err)
	}
	secondHead, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("LastSequence(second): %v", err)
	}
	if secondHead != firstHead {
		t.Fatalf("bootstrap retry advanced head %d -> %d", firstHead, secondHead)
	}

	want := providerAuthoritySnapshot(t, st, tenantID, grant.ID)
	truncateProviderAuthority(t, st)
	if err := projections.New(st, runtime.ProjectionOptions...).Project(ctx, log); err != nil {
		t.Fatalf("rebuild bootstrapped history: %v", err)
	}
	if got := providerAuthoritySnapshot(t, st, tenantID, grant.ID); got != want {
		t.Fatalf("bootstrapped rebuild = %+v, want pre-event rows %+v", got, want)
	}
	brand, err := whitelabel.NewPGStore(st).TenantBrand(ctx, tenantID)
	if err != nil || brand == nil || brand.TokenOverrides["nav.certificates"] != "Credentials" {
		t.Fatalf("bootstrapped token overrides = %+v / %v", brand, err)
	}
}

// The served mutation wraps the independently durable event receiver with the
// canonical idempotency ledger. It must replay the exact first HTTP result,
// reject a changed authenticated command, and leave a post-append projection
// failure retryable rather than caching the 500 as the result.
func TestProviderServedMutationIsExactAndHealsPostAppendFailure(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	servedSlug := "served-acme-" + suffix
	failureSlug := "failure-acme-" + suffix
	concurrentSlug := "concurrent-acme-" + suffix
	servedTenant := CustomerID(servedSlug)
	failureTenant := CustomerID(failureSlug)
	concurrentTenant := CustomerID(concurrentSlug)
	servedKey := "served-create-1-" + suffix
	failureKey := "served-create-failure-" + suffix
	concurrentKey := "served-concurrent-1-" + suffix
	servedBody := fmt.Sprintf(`{"slug":%q,"name":"Served Acme"}`, servedSlug)
	failureBody := fmt.Sprintf(`{"slug":%q,"name":"Failure Acme"}`, failureSlug)
	concurrentBody := fmt.Sprintf(`{"slug":%q,"name":"Concurrent Acme"}`, concurrentSlug)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	var ticks atomic.Int64
	clock := func() time.Time {
		return time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC).Add(time.Duration(ticks.Add(1)) * time.Second)
	}
	newHandler := func() http.Handler {
		return NewHandler(Config{
			License:       providerLicense(t, 10),
			Store:         NewPGStore(st),
			Mutations:     runtime.Mutations,
			Idempotency:   orchestrator.NewIdempotency(st),
			Authenticator: stubAuth{accept: "Bearer real-credential"},
			Delegations:   fullyDelegated("op-1", servedTenant, failureTenant, concurrentTenant),
			Clock:         clock,
		})
	}
	handler := newHandler()
	request := func(path, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer real-credential")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	missing := request("/provider/v1/tenants", "", servedBody)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing key status = %d, want 400: %s", missing.Code, missing.Body.String())
	}
	for _, mutation := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/provider/v1/tenants", `{"slug":"route-proof","name":"Route Proof"}`},
		{http.MethodPost, "/provider/v1/tenants/route-proof/suspend", `{}`},
		{http.MethodPost, "/provider/v1/tenants/route-proof/offboard", `{}`},
		{http.MethodPut, "/provider/v1/tenants/route-proof/quota", `{}`},
		{http.MethodPut, "/provider/v1/tenants/route-proof/brand", `{}`},
		{http.MethodPost, "/provider/v1/isolation-drill", `{}`},
		{http.MethodPost, "/provider/v1/breakglass", `{"tenant_id":"route-proof"}`},
		{http.MethodPost, "/provider/v1/breakglass/grant-proof/consent", `{"tenant_id":"route-proof"}`},
		{http.MethodPost, "/provider/v1/breakglass/grant-proof/results", `{}`},
	} {
		req := httptest.NewRequest(mutation.method, mutation.path, bytes.NewBufferString(mutation.body))
		req.Header.Set("Authorization", "Bearer real-credential")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Idempotency-Key") {
			t.Fatalf("%s %s without key = %d/%s, want idempotency 400",
				mutation.method, mutation.path, rec.Code, rec.Body.String())
		}
	}
	first := request("/provider/v1/tenants", servedKey, servedBody)
	if first.Code != http.StatusCreated {
		t.Fatalf("first mutation = %d: %s", first.Code, first.Body.String())
	}
	replay := request("/provider/v1/tenants", servedKey, servedBody)
	if replay.Code != first.Code || !bytes.Equal(replay.Body.Bytes(), first.Body.Bytes()) {
		t.Fatalf("idempotent replay = %d/%q, want exact %d/%q", replay.Code, replay.Body.Bytes(), first.Code, first.Body.Bytes())
	}
	changed := request("/provider/v1/tenants", servedKey,
		fmt.Sprintf(`{"slug":%q,"name":"Changed Command"}`, servedSlug))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed command = %d, want 409: %s", changed.Code, changed.Body.String())
	}

	failedOnce := atomic.Bool{}
	runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
		if event.Type == AuditTenantProvisioned && event.TenantID == failureTenant && !failedOnce.Swap(true) {
			return errors.New("injected post-append projection failure")
		}
		return nil
	}
	failed := request("/provider/v1/tenants", failureKey, failureBody)
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("post-append failure = %d, want 500: %s", failed.Code, failed.Body.String())
	}
	healed := request("/provider/v1/tenants", failureKey, failureBody)
	if healed.Code != http.StatusCreated {
		t.Fatalf("retry after projection failure = %d, want 201: %s", healed.Code, healed.Body.String())
	}
	var failureEvents int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == AuditTenantProvisioned && event.TenantID == failureTenant {
			failureEvents++
		}
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if failureEvents != 1 {
		t.Fatalf("post-append retry produced %d events, want exactly one", failureEvents)
	}

	var concurrent [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	for i := range concurrent {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			concurrent[index] = request("/provider/v1/tenants", concurrentKey, concurrentBody)
		}(i)
	}
	wg.Wait()
	if concurrent[0].Code != http.StatusCreated || concurrent[1].Code != http.StatusCreated ||
		!bytes.Equal(concurrent[0].Body.Bytes(), concurrent[1].Body.Bytes()) {
		t.Fatalf("concurrent identical retries = %d/%q and %d/%q, want one exact 201 result",
			concurrent[0].Code, concurrent[0].Body.Bytes(), concurrent[1].Code, concurrent[1].Body.Bytes())
	}
	var concurrentEvents int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == AuditTenantProvisioned && event.TenantID == concurrentTenant {
			concurrentEvents++
		}
		return nil
	}); err != nil {
		t.Fatalf("Replay(concurrent): %v", err)
	}
	if concurrentEvents != 1 {
		t.Fatalf("concurrent identical retries produced %d events, want one", concurrentEvents)
	}
}

// AUD-61 requires the crash-gap proof at every custom Provider handler, not
// just tenant creation. Each first request below commits its authority event
// and then loses projection, returning 500. The identical retry must heal the
// view, return the original successful bytes on later replay, and leave the log
// head exactly one event higher.
func TestEveryProviderMutationConvergesAcrossPostAppendFailure(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	var ticks atomic.Int64
	clock := func() time.Time {
		return time.Date(2026, 8, 9, 21, 0, 0, 0, time.UTC).Add(time.Duration(ticks.Add(1)) * time.Second)
	}
	tenantID := CustomerID("crash-acme")
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         NewPGStore(st),
		Mutations:     runtime.Mutations,
		Activity:      NewEventLogActivitySource(log),
		Idempotency:   orchestrator.NewIdempotency(st),
		Authenticator: authorityAuthenticator{},
		Delegations:   fullyDelegated("op-1", tenantID),
		Quotas:        billing.NewPGStore(st),
		Brands:        authorityBrandCache{},
		Telemetry:     NewPGStore(st),
		Drills: &stubDriller{report: IsolationDrillReport{
			Passed: true, Checks: []IsolationDrillCheck{{Name: "cross_tenant_read_denied", Passed: true}},
		}},
		Clock: clock,
	})
	request := func(method, path, auth, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	crashAndHeal := func(method, path, auth, key, body, eventType string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatalf("LastSequence(before %s): %v", key, err)
		}
		var failed atomic.Bool
		runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
			if event.Type == eventType && event.Sequence > before && !failed.Swap(true) {
				return errors.New("injected authority projection crash gap")
			}
			return nil
		}
		first := request(method, path, auth, key, body)
		if first.Code != http.StatusInternalServerError {
			t.Fatalf("%s first crash-gap response = %d/%s, want 500", key, first.Code, first.Body.String())
		}
		afterFailure, err := log.LastSequence(ctx)
		if err != nil || afterFailure != before+1 {
			t.Fatalf("%s log head after failure = %d/%v, want %d", key, afterFailure, err, before+1)
		}
		healed := request(method, path, auth, key, body)
		if healed.Code != wantStatus {
			t.Fatalf("%s healed response = %d/%s, want %d", key, healed.Code, healed.Body.String(), wantStatus)
		}
		replay := request(method, path, auth, key, body)
		if replay.Code != healed.Code || !bytes.Equal(replay.Body.Bytes(), healed.Body.Bytes()) {
			t.Fatalf("%s replay = %d/%q, want exact %d/%q", key,
				replay.Code, replay.Body.Bytes(), healed.Code, healed.Body.Bytes())
		}
		afterReplay, err := log.LastSequence(ctx)
		if err != nil || afterReplay != before+1 {
			t.Fatalf("%s log head after replay = %d/%v, want %d", key, afterReplay, err, before+1)
		}
		runtime.Projection.applyHook = nil
		return healed
	}

	crashAndHeal(http.MethodPost, "/provider/v1/tenants", "Bearer requester", "crash-provision-1",
		`{"slug":"crash-acme","name":"Crash Acme"}`, AuditTenantProvisioned, http.StatusCreated)
	crashAndHeal(http.MethodPut, "/provider/v1/tenants/"+tenantID+"/quota", "Bearer requester", "crash-quota-1",
		`{"max_certificates_stored":3}`, EventTenantQuotaSet, http.StatusNoContent)
	crashAndHeal(http.MethodPut, "/provider/v1/tenants/"+tenantID+"/brand", "Bearer requester", "crash-brand-1",
		`{"product_name":"Crash Trust","custom_domain":"trust.crash.test"}`, EventTenantBrandSet, http.StatusNoContent)
	crashAndHeal(http.MethodPost, "/provider/v1/tenants/"+tenantID+"/suspend", "Bearer requester", "crash-suspend-1",
		`{}`, AuditTenantSuspended, http.StatusNoContent)
	grantResponse := crashAndHeal(http.MethodPost, "/provider/v1/breakglass", "Bearer requester", "crash-breakglass-request-1",
		fmt.Sprintf(`{"tenant_id":%q,"reason":"incident","ttl":"15m"}`, tenantID), AuditBreakGlassRequested, http.StatusCreated)
	var grant BreakGlassGrant
	if err := json.Unmarshal(grantResponse.Body.Bytes(), &grant); err != nil {
		t.Fatalf("decode healed break-glass grant: %v", err)
	}
	consentPath := "/provider/v1/breakglass/" + grant.ID + "/consent"
	consentBody := fmt.Sprintf(`{"tenant_id":%q,"approve":true}`, tenantID)
	crashAndHeal(http.MethodPost, consentPath, "Bearer approver-a", "crash-breakglass-consent-1",
		consentBody, AuditBreakGlassConsented, http.StatusOK)
	secondConsent := request(http.MethodPost, consentPath, "Bearer approver-b", "crash-breakglass-consent-2", consentBody)
	if secondConsent.Code != http.StatusOK {
		t.Fatalf("second break-glass consent = %d/%s", secondConsent.Code, secondConsent.Body.String())
	}
	crashAndHeal(http.MethodPost, "/provider/v1/breakglass/"+grant.ID+"/results", "Bearer requester",
		"crash-breakglass-results-1", `{}`, AuditBreakGlassAccessed, http.StatusOK)
	crashAndHeal(http.MethodPost, "/provider/v1/isolation-drill", "Bearer requester", "crash-isolation-drill-1",
		`{}`, "provider.isolation.drill", http.StatusOK)
	crashAndHeal(http.MethodPost, "/provider/v1/tenants/"+tenantID+"/offboard", "Bearer requester", "crash-offboard-1",
		`{}`, AuditTenantOffboarded, http.StatusNoContent)

	activityResponse := request(http.MethodGet, "/provider/v1/activity?limit=20", "Bearer requester", "", "")
	if activityResponse.Code != http.StatusOK {
		t.Fatalf("provider activity = %d/%s, want 200", activityResponse.Code, activityResponse.Body.String())
	}
	var activity struct {
		Items []ProviderActivity `json:"items"`
	}
	if err := json.Unmarshal(activityResponse.Body.Bytes(), &activity); err != nil {
		t.Fatalf("decode provider activity: %v", err)
	}
	if len(activity.Items) != 10 {
		t.Fatalf("provider activity items = %d, want all 10 immutable mutations: %#v", len(activity.Items), activity.Items)
	}
	if activity.Items[0].Type != AuditTenantOffboarded || activity.Items[0].TenantID != tenantID {
		t.Fatalf("newest provider activity = %#v, want offboard for %s", activity.Items[0], tenantID)
	}
	if strings.Contains(activityResponse.Body.String(), "request_binding") || strings.Contains(activityResponse.Body.String(), "tenant_snapshot") {
		t.Fatalf("provider activity leaked command binding or tenant snapshot: %s", activityResponse.Body.String())
	}
}

func TestProviderActivityIsEventBackedAndDelegationScoped(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	allowed := CustomerID("activity-allowed")
	denied := CustomerID("activity-denied")
	for index, tenantID := range []string{allowed, denied} {
		payload, err := json.Marshal(AuthorityEvent{Audit: AuditEvent{
			Type: AuditTenantSuspended, TenantID: tenantID, OperatorID: "op-1",
			At: time.Date(2026, 8, 9, 21, index, 0, 0, time.UTC),
		}})
		if err != nil {
			t.Fatalf("marshal activity payload: %v", err)
		}
		if _, err := log.Append(ctx, events.Event{Type: AuditTenantSuspended, TenantID: tenantID, Data: payload}); err != nil {
			t.Fatalf("append tenant activity: %v", err)
		}
	}
	drillPayload, err := json.Marshal(AuthorityEvent{Audit: AuditEvent{
		Type: "provider.isolation.drill", OperatorID: "op-1", Reason: "passed",
		At: time.Date(2026, 8, 9, 21, 2, 0, 0, time.UTC),
	}})
	if err != nil {
		t.Fatalf("marshal drill activity: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{Type: "provider.isolation.drill", TenantID: providerAuditTenant, Data: drillPayload}); err != nil {
		t.Fatalf("append drill activity: %v", err)
	}

	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: authorityAuthenticator{},
		Delegations:   fullyDelegated("op-1", allowed),
		Activity:      NewEventLogActivitySource(log),
	})
	req := httptest.NewRequest(http.MethodGet, "/provider/v1/activity", nil)
	req.Header.Set("Authorization", "Bearer requester")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activity response = %d/%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []ProviderActivity `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode activity response: %v", err)
	}
	if len(response.Items) != 2 || response.Items[0].Type != "provider.isolation.drill" || response.Items[1].TenantID != allowed {
		t.Fatalf("delegation-scoped activity = %#v, want global drill plus allowed tenant", response.Items)
	}
	for _, item := range response.Items {
		if item.TenantID == denied {
			t.Fatalf("activity leaked undelegated tenant %s: %#v", denied, response.Items)
		}
	}
}

// Full read-model rebuild is one transaction. An EE projection may not reset
// its tables on a separate connection and leave them truncated/partially
// replayed when a later event fails validation.
func TestProviderAuthorityFailedFullRebuildRollsBackItsProjection(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	tenantID := CustomerID("atomic-rebuild")
	now := time.Date(2026, 8, 9, 21, 0, 0, 0, time.UTC)
	if _, err := runtime.Mutations.Append(ctx, "atomic-create", AuditTenantProvisioned, tenantID, AuthorityEvent{
		Tenant: &Tenant{ID: tenantID, Slug: "atomic-rebuild", Name: "From Event", Status: TenantActive,
			CreatedAt: now, UpdatedAt: now},
		Audit: AuditEvent{Type: AuditTenantProvisioned, TenantID: tenantID, At: now},
	}); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	// This sentinel is the currently served state. A failed rebuild must leave
	// it untouched; only a successful rebuild may replace it with From Event.
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE provider_tenants SET name = 'Before Failed Rebuild' WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatalf("seed served sentinel: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: AuditTenantSuspended, TenantID: tenantID, Data: []byte(`{"tenant":`),
	}); err != nil {
		t.Fatalf("append malformed provider event: %v", err)
	}
	projector := projections.New(st, runtime.ProjectionOptions...)
	if err := projector.Rebuild(ctx, log); err == nil {
		t.Fatal("malformed provider event did not fail full rebuild")
	}
	got, err := NewPGStore(st).Tenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("read state after failed rebuild: %v", err)
	}
	if got.Name != "Before Failed Rebuild" {
		t.Fatalf("failed rebuild left provider view %q, want pre-rebuild sentinel", got.Name)
	}
}

type authoritySnapshot struct {
	tenants, operators, delegations, quotas, brands, grants int
	quotaLimit, useCount                                    int
	productName                                             string
}

func (s authoritySnapshot) nonzero() bool {
	return s.tenants != 0 || s.operators != 0 || s.delegations != 0 || s.quotas != 0 || s.brands != 0 || s.grants != 0
}

func providerAuthoritySnapshot(t *testing.T, st *corestore.Store, tenantID, grantID string) authoritySnapshot {
	t.Helper()
	// This deliberately reads all six projection tables in one SQL statement,
	// making the before/after replay comparison exact and compact.
	var out authoritySnapshot
	err := st.SystemPool().QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM provider_tenants WHERE tenant_id = $1),
		  (SELECT count(*) FROM provider_operators WHERE tenant_id = '`+providerAuthorityTenant+`'),
		  (SELECT count(*) FROM provider_operator_delegations WHERE tenant_id = '`+providerAuthorityTenant+`' AND customer_tenant_id = $1::text),
		  (SELECT count(*) FROM provider_tenant_quotas WHERE tenant_id = $1),
		  (SELECT count(*) FROM tenant_branding WHERE tenant_id = $1),
		  (SELECT count(*) FROM provider_breakglass_grants WHERE id = $2),
		  COALESCE((SELECT max_certificates_stored FROM provider_tenant_quotas WHERE tenant_id = $1), 0),
		  COALESCE((SELECT product_name FROM tenant_branding WHERE tenant_id = $1), ''),
		  COALESCE((SELECT use_count FROM provider_breakglass_grants WHERE id = $2), 0)`, tenantID, grantID).
		Scan(&out.tenants, &out.operators, &out.delegations, &out.quotas, &out.brands, &out.grants,
			&out.quotaLimit, &out.productName, &out.useCount)
	if err != nil {
		t.Fatalf("authority snapshot: %v", err)
	}
	return out
}

func truncateProviderAuthority(t *testing.T, st *corestore.Store) {
	t.Helper()
	if _, err := st.SystemPool().Exec(context.Background(), `TRUNCATE
		provider_operator_delegations, provider_operators, provider_breakglass_grants, provider_tenant_quotas,
		tenant_branding, provider_tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate provider authority: %v", err)
	}
}
