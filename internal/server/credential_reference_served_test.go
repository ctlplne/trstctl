// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostedkey"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/rotationcommand"
	"trstctl.com/trstctl/internal/store"
)

func TestDynamicRevocationIntentKeepsOnlyLeaseIdentity(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111139"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, issued, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "fixture-issue", "sha256:fixture-issue")
	secret.Wipe(issued)
	if err != nil {
		t.Fatal(err)
	}
	expiring, issued, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "fixture-expiring", "sha256:fixture-expiring")
	secret.Wipe(issued)
	if err != nil {
		t.Fatal(err)
	}
	stop()

	assertIntent := func(leaseID, operationID, eventKind, eventType string) orchestrator.Message {
		t.Helper()
		record, err := st.GetDynamicSecretLease(ctx, tenant, leaseID)
		if err != nil || record.RevokeOutboxID == nil {
			t.Fatalf("read exact revoke intent: %v", err)
		}
		entry, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
		if err != nil {
			t.Fatal(err)
		}
		event, found, err := log.EventByID(ctx, dynamicSecretEventID(tenant, record.TenantEpoch, eventKind, operationID))
		if err != nil || !found || event.Type != eventType {
			t.Fatalf("canonical revoke event missing: found=%t err=%v", found, err)
		}
		if event.SchemaVersion != 3 {
			t.Errorf("fresh %s schema is v%d, want v3", eventType, event.SchemaVersion)
		}
		for _, raw := range [][]byte{event.Data, entry.Payload} {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			for name := range fields {
				if strings.EqualFold(strings.ReplaceAll(name, "_", ""), "BackendRef") {
					t.Error("revocation intent copied the issued reference")
				}
			}
		}
		return orchestrator.Message{
			ID: entry.ID, TenantID: tenant, Destination: entry.Destination,
			IdempotencyKey: entry.IdempotencyKey, EffectLane: "dynsecret.provider:" + provider.name,
			Payload: entry.Payload, Attempts: 10,
		}
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-revoke", "sha256:fixture-revoke"); err != nil {
		t.Fatal(err)
	}
	first := assertIntent(lease.ID, dynamicSecretOperationID(tenant, "fixture-revoke"),
		"lease-revocation-requested", projections.EventDynamicSecretLeaseRevocationRequested)
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, first, errors.New("fixture unavailable")); err != nil || !handled {
		t.Fatalf("record failed initial attempt: handled=%t err=%v", handled, err)
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-retry", "sha256:fixture-retry"); err != nil {
		t.Fatal(err)
	}
	assertIntent(lease.ID, dynamicSecretOperationID(tenant, "fixture-retry"),
		"lease-revocation-retry-requested", projections.EventDynamicSecretLeaseRevocationRetryRequested)
	if count, err := lifecycle.ExpireDue(ctx, time.Now().Add(time.Hour)); err != nil || count != 1 {
		t.Fatalf("expire exact remaining lease: count=%d err=%v", count, err)
	}
	assertIntent(expiring.ID, "legacy-revoke:"+expiring.ID,
		"lease-revocation-requested", projections.EventDynamicSecretLeaseRevocationRequested)
}

type historicalReferenceProvider struct{ *issueOutboxProvider }

func (*historicalReferenceProvider) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	if req.Role == "hosted" {
		return dynsecret.Credential{BackendRef: "fixture-binding/fixture-value",
			Secret: []byte(`{"api_key":"fixture-value","key_hash":"fixture-value"}`)}, nil
	}
	return dynsecret.Credential{BackendRef: "fixture-site/fixture-id",
		Secret: []byte(`{"api_key":"fixture-native-key","key_id":"fixture-id","site":"fixture-site"}`)}, nil
}

func TestDynamicRevocationChecksHistoricalSourceAfterProviderTypeChange(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111148"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	original := &historicalReferenceProvider{provider}
	dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {original}}
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{original}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	leases := make(map[string]dynsecret.Lease)
	for _, role := range []string{"hosted", "native"} {
		lease, value, err := lifecycle.IssueBound(ctx, provider.name, role, time.Hour, "fixture-issue-"+role, "sha256:fixture-issue-"+role)
		secret.Wipe(value)
		if err != nil {
			t.Fatal(err)
		}
		leases[role] = lease
	}
	stop()
	current := &issueOutboxProvider{name: provider.name, providerType: "datadog"}
	dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {current}}
	for _, role := range []string{"hosted", "native"} {
		lease := leases[role]
		if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-revoke-"+role, "sha256:fixture-revoke-"+role); err != nil {
			t.Fatal(err)
		}
		record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
		if err != nil || record.RevokeOutboxID == nil {
			t.Fatalf("read revocation authority: %v", err)
		}
		item, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
		if err != nil {
			t.Fatal(err)
		}
		handled, err := dispatcher.Deliver(ctx, orchestrator.Message{TenantID: tenant, ID: item.ID, Destination: item.Destination,
			IdempotencyKey: item.IdempotencyKey, Payload: item.Payload, Attempts: 1})
		if !handled {
			t.Fatal("revocation did not reach the secret dispatcher")
		}
		if role == "hosted" {
			if err == nil || strings.Contains(err.Error(), "fixture-value") || len(current.Revocations()) != 0 {
				t.Errorf("historical hosted reference crossed the provider boundary: refused=%t calls=%d", err != nil, len(current.Revocations()))
			}
			continue
		}
		if err != nil {
			t.Fatalf("historical native reference was refused: %v", err)
		}
	}
	if calls := current.Revocations(); len(calls) != 1 || calls[0] != "fixture-site/fixture-id" {
		t.Fatalf("expected exactly one native revocation, got %d calls", len(calls))
	}
}

func TestDynamicRevocationRecoversLegacyNativeIssuedSource(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111149"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	provider.providerType = "gcp-iam"
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, func() {})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	appendV1 := func(kind string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{TenantID: tenant, Type: kind, SchemaVersion: 1, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		return event
	}
	for _, fixture := range []struct {
		role      string
		reference string
		document  string
	}{
		{"native", "projects/fixture/serviceAccounts/fixture/keys/fixture-id", `{"private_key":"fixture-native-value","type":"service_account"}`},
		{"previous-hosted", "fixture-binding/fixture-value", `{"api_key":"fixture-value","key_hash":"fixture-value"}`},
	} {
		leaseID := "lease-" + uuid.NewString()
		expiresAt := time.Now().UTC().Add(time.Hour)
		pending := projections.DynamicSecretLeasePending{ID: leaseID, IdempotencyKey: "fixture-issue-" + fixture.role,
			RequestBinding: "sha256:fixture-issue-" + fixture.role, Provider: provider.name, Role: fixture.role,
			ExpiresAt: expiresAt, HardExpiresAt: expiresAt}
		appendV1(projections.EventDynamicSecretLeasePending, pending)
		sealed, err := sealTenantValue(ctx, nil, kek, tenant, []byte(fixture.document), dynamicSecretCredentialAAD(tenant, leaseID, provider.name))
		if err != nil {
			t.Fatal(err)
		}
		issued := appendV1(projections.EventDynamicSecretLeaseIssued, projections.DynamicSecretLeaseIssued{
			ID: leaseID, IdempotencyKey: pending.IdempotencyKey, RequestBinding: pending.RequestBinding,
			Provider: provider.name, Role: fixture.role, BackendRef: fixture.reference,
			SealedCredential: sealed, ExpiresAt: expiresAt, HardExpiresAt: expiresAt,
		})
		if _, err := lifecycle.RevokeBound(ctx, leaseID, "fixture-revoke-"+fixture.role, "sha256:fixture-revoke-"+fixture.role); err != nil {
			t.Fatal(err)
		}
		record, err := st.GetDynamicSecretLease(ctx, tenant, leaseID)
		if err != nil || record.RevokeOutboxID == nil || issued.ID == dynamicSecretEventID(tenant, record.TenantEpoch, "provider-issued", leaseID) {
			t.Fatalf("fixture must retain a v1 source and live revocation authority: %v", err)
		}
		item, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
		if err != nil {
			t.Fatal(err)
		}
		before := len(provider.Revocations())
		handled, err := dispatcher.Deliver(ctx, orchestrator.Message{TenantID: tenant, ID: item.ID, Destination: item.Destination,
			IdempotencyKey: item.IdempotencyKey, Payload: item.Payload, Attempts: 1})
		if !handled {
			t.Fatal("revocation did not reach the secret dispatcher")
		}
		calls := provider.Revocations()
		if fixture.role == "native" {
			if err != nil || len(calls) != before+1 || calls[before] != fixture.reference {
				t.Fatalf("historical native source did not authorize its exact revocation: calls=%d err=%v", len(calls)-before, err)
			}
		} else if err == nil || len(calls) != before || strings.Contains(err.Error(), "fixture-value") {
			t.Fatalf("historical hosted reference crossed the native provider boundary: refused=%t calls=%d", err != nil, len(calls)-before)
		}
	}
}

type referencePublishingProvider struct{ issueOutboxProvider }

func (p *referencePublishingProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{
		BackendRef: "unlimited/fixture-value",
		Secret:     []byte(`{"api_key":"fixture-value","key_hash":"fixture-value"}`),
		Metadata:   map[string]string{"provider_type": "openrouter"},
	}, nil
}

func (*referencePublishingProvider) AllowsStaticRotation(string) bool { return true }

func (*referencePublishingProvider) DynamicSecretBindsRole(role, binding string) bool {
	return role == "fixture/hosted" && binding == "unlimited"
}

func (*referencePublishingProvider) VerifyStaticCredential(context.Context, string, []byte) (string, error) {
	return "not_available", nil
}

func TestServedCredentialPublicationChecksIssuedReference(t *testing.T) {
	const key = "fixture/hosted"
	provider := &referencePublishingProvider{issueOutboxProvider{name: "fixture-account", providerType: "openrouter"}}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, "fixture-bad-issue",
		map[string]any{"provider": provider.name, "role": key, "ttl_seconds": 60})
	if status < 400 || bytes.Contains(body, []byte("fixture-value")) {
		t.Errorf("lease publication admitted an unsafe reference or credential, status %d", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "fixture-current",
		map[string]any{"name": key, "value": "fixture-initial"})
	if status != http.StatusCreated {
		t.Fatalf("write current secret: status %d", status)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "fixture-static",
		map[string]any{"provider": provider.name, "key": key, "old_ref": "none"})
	var result struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil || result.CommandID == "" {
		t.Fatalf("queue reference check: status %d", status)
	}
	ctx := t.Context()
	_ = h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, result.CommandID, 1)
	cmd, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, result.CommandID)
	if err != nil || cmd.NewRef != "" || len(cmd.SealedNew) != 0 {
		t.Errorf("static staging persisted an unsafe successor: %v", err)
	}
	if err := h.log.Replay(ctx, 1, func(e events.Event) error {
		if (e.Type == projections.EventDynamicSecretLeaseIssued || e.Type == projections.EventSecretStaticRotationAdvanced) &&
			bytes.Contains(e.Data, []byte("fixture-value")) {
			t.Errorf("event type %s published credential bytes as a reference", e.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServedHostedRotationRejectsUnprovedPredecessorBeforePublication(t *testing.T) {
	const marker = "fixture-value"
	const role = "fixture/hosted"
	var calls atomic.Int32
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer vendor.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "fixture-account", Type: "openrouter", Endpoint: vendor.URL,
		APIKeyRef:    writeServedCredentialFile(t, "fixture-admin", "fixture-management"),
		AllowedRoles: []string{role}, RoleBindings: map[string]string{role: "unlimited"},
		MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
	}}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, serverTestPrincipalKEK(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "Reference admission fixture")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "fixture-write",
		map[string]any{"name": role, "value": `{"api_key":"fixture-value","key_hash":"fixture-value"}`})
	if status != http.StatusCreated {
		t.Fatalf("write fixture current secret: status=%d", status)
	}
	sequence, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"provider": "fixture-account", "key": role, "old_ref": "unlimited/" + marker}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations/preview", token, request)
	if status != http.StatusOK || bytes.Contains(body, []byte(marker)) {
		t.Errorf("preview exposed unproved reference or returned status %d", status)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "fixture-rotate", request)
	if status < 400 || status >= 500 || bytes.Contains(body, []byte(marker)) {
		t.Errorf("queue did not safely reject unproved reference, status %d", status)
	}
	request["name"] = "fixture-schedule"
	request["interval_seconds"] = 120
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", token, "fixture-schedule", request)
	if status < 400 || status >= 500 || bytes.Contains(body, []byte(marker)) {
		t.Errorf("schedule did not safely reject unproved reference, status %d", status)
	}
	after, err := h.log.LastSequence(t.Context())
	if err != nil || sequence != after || calls.Load() != 0 {
		t.Errorf("refused request produced durable or vendor effects: event advance=%d calls=%d err=%v", after-sequence, calls.Load(), err)
	}
}

func TestServedLegacyScheduleDoesNotCopyUnprovedReference(t *testing.T) {
	const oldRef = "unlimited/fixture-predecessor"
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Retained schedule fixture")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	payload := projections.SecretRotationScheduleUpserted{
		ID: uuid.NewString(), Name: "legacy-schedule", Provider: "fixture-removed-provider",
		Key: "fixture/rotation", OldRef: oldRef, IntervalSeconds: 120,
		Enabled: true, NextRunAt: time.Now().UTC().Add(-time.Minute),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventSecretRotationScheduleUpserted, SchemaVersion: 1, Data: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/secrets/rotation-schedules", "/api/v1/secrets/rotation-schedules/" + payload.ID} {
		status, body := secretsReq(t, h, http.MethodGet, path, token, nil)
		if status != http.StatusOK || bytes.Contains(body, []byte(oldRef)) {
			t.Errorf("schedule metadata exposed historical reference or returned status %d", status)
		}
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", token, "fixture-legacy-tick", nil)
	if status != http.StatusOK || bytes.Contains(body, []byte(oldRef)) {
		t.Errorf("tick did not safely defer the historical reference, status %d", status)
	}
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var copies int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM secret_rotation_schedule_tick_rows WHERE tenant_id = $1 AND schedule_id = $2 AND old_ref = $3`,
			h.tenant, payload.ID, oldRef).Scan(&copies); err != nil {
			return err
		}
		if copies != 0 {
			t.Errorf("a fresh tick snapshot copied the legacy reference %d time(s)", copies)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/"+payload.ID+"/pause", token, "fixture-legacy-pause", nil)
	if status != http.StatusOK || bytes.Contains(body, []byte(oldRef)) {
		t.Errorf("control receipt exposed the old reference or returned status %d", status)
	}
	if err := h.log.Replay(ctx, event.Sequence+1, func(added events.Event) error {
		if added.TenantID == h.tenant && bytes.Contains(added.Data, []byte(oldRef)) {
			t.Errorf("fresh %s event copied a legacy reference", added.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServedLegacyScheduleControlCacheKeepsIdentityWithoutReference(t *testing.T) {
	const originalRef = "unlimited/fixture-retained-reference"
	const key = "fixture-retained-control"
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Retained schedule control result fixture")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	id := uuid.NewString()
	path := "/api/v1/secrets/rotation-schedules/" + id + "/pause"
	binding := crypto.SHA256Hex([]byte(`{"domain":"trstctl.api.mutation-route-binding.v1","principal":"secrets-test","method":"POST","escaped_path":"` + path + `"}`))
	original := json.RawMessage(`{"id":"` + id + `","provider":"fixture-removed-provider","enabled":false,"old_ref":"` + originalRef + `"}`)
	stored, err := h.srv.idem.DoDurableEffectBound(t.Context(), h.tenant, key, binding, func(context.Context) ([]byte, error) {
		return json.Marshal(map[string]any{"s": http.StatusOK, "b": original, "h": binding})
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, path, token, key, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(id)) || bytes.Contains(body, []byte(originalRef)) {
		t.Errorf("historical cached control HTTP status %d, identity kept=%t, marker returned=%t",
			status, bytes.Contains(body, []byte(id)), bytes.Contains(body, []byte(originalRef)))
	}
	replay, err := h.srv.idem.DoDurableEffectBound(t.Context(), h.tenant, key, binding, func(context.Context) ([]byte, error) {
		return nil, errors.New("fixture must recover original cache without executing")
	})
	if err != nil || !bytes.Equal(replay, stored) {
		t.Fatalf("historical protected result changed: %v", err)
	}
}

func TestProjectionRestoresLegacyStaticJobWithoutCopyingReference(t *testing.T) {
	const oldRef = "unlimited/fixture-predecessor"
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Retained static job fixture")
	epoch, err := h.store.ApplicationSecretTenantEpoch(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.SecretStaticRotationQueued{
		ID: uuid.NewString(), TenantEpoch: epoch, Provider: "fixture-removed-provider", Key: "fixture/rotation",
		OldRef: oldRef, ExpectedVersion: 1, IdempotencyKeyDigest: crypto.SHA256Hex([]byte("fixture-static-key")),
		RequestBinding: crypto.SHA256Hex([]byte("fixture-authenticated-static-command")),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(ctx, events.Event{
		ID: payload.ID, TenantID: h.tenant, Type: projections.EventSecretStaticRotationQueued, SchemaVersion: 1, Data: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, payload.ID)
	if err != nil || cmd.OutboxID == 0 || cmd.OldRef != oldRef {
		t.Fatalf("legacy command did not preserve original authority: %v", err)
	}
	entry, err := orchestrator.NewOutbox(h.store).Get(ctx, h.tenant, cmd.OutboxID)
	if err != nil || entry.IdempotencyKey != store.SecretStaticRotationOutboxIdempotencyKey(epoch, payload.ID) {
		t.Fatalf("restored job did not preserve command identity: %v", err)
	}
	if bytes.Contains(entry.Payload, []byte(oldRef)) {
		t.Fatal("restored outbox copied the legacy predecessor")
	}
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	for _, path := range []string{"/api/v1/secrets/rotations", "/api/v1/secrets/rotations/" + payload.ID} {
		status, body := secretsReq(t, h, http.MethodGet, path, token, nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte(payload.ID)) || bytes.Contains(body, []byte(oldRef)) {
			t.Errorf("historical command HTTP status %d, identity kept=%t, marker returned=%t",
				status, bytes.Contains(body, []byte(payload.ID)), bytes.Contains(body, []byte(oldRef)))
		}
	}

	retained, found, err := h.log.EventByID(ctx, payload.ID)
	if err != nil || !found || !bytes.Equal(retained.Data, raw) {
		t.Fatalf("the original immutable source changed: found=%t err=%v", found, err)
	}

	// A coordinated upgrade can retain an exact old job and its original ID.
	// Keep that evidence and bind it to this command without creating a copy.
	payload.ID = uuid.NewString()
	payload.Key = "fixture/retained-rotation"
	legacyBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var retainedJobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
			VALUES ($1, 'secret.static-rotation', $2, $3) RETURNING id`,
			h.tenant, legacyBody, store.SecretStaticRotationOutboxIdempotencyKey(epoch, payload.ID)).Scan(&retainedJobID)
	}); err != nil {
		t.Fatal(err)
	}
	legacyEvent, err := h.log.Append(ctx, events.Event{
		ID: payload.ID, TenantID: h.tenant, Type: projections.EventSecretStaticRotationQueued, SchemaVersion: 1, Data: legacyBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, legacyEvent); err != nil {
		t.Fatal(err)
	}
	legacyCommand, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, payload.ID)
	if err != nil || legacyCommand.OutboxID != retainedJobID {
		t.Fatalf("legacy job lost its original outbox identity: %v", err)
	}
	retainedJob, err := orchestrator.NewOutbox(h.store).Get(ctx, h.tenant, retainedJobID)
	if err != nil || !bytes.Equal(retainedJob.Payload, legacyBody) {
		t.Fatalf("legacy outbox evidence was overwritten: %v", err)
	}

	if _, err := h.store.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, retainedJobID); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, legacyEvent); err != nil {
		t.Fatalf("replay the surviving command with a missing physical job: %v", err)
	}
	restored, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, payload.ID)
	if err != nil || restored.OutboxID == retainedJobID || restored.OutboxID == 0 {
		t.Fatalf("surviving command did not adopt its reconstructed outbox: %v", err)
	}
	newJob, err := orchestrator.NewOutbox(h.store).Get(ctx, h.tenant, restored.OutboxID)
	if err != nil || bytes.Contains(newJob.Payload, []byte(oldRef)) {
		t.Fatalf("new dispatch did not retain safe compact data: %v", err)
	}
}

func TestServedLegacyTerminalTickCachesSafeViewAndKeepsSource(t *testing.T) {
	const (
		key    = "fixture-retained-tick"
		role   = "fixture/rotation"
		marker = "unlimited/fixture-retained-reference"
		path   = "/api/v1/secrets/rotation-schedules/run-due"
	)
	ctx := t.Context()
	provider := &staticRotationProviderDouble{name: "fixture-static", role: role}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "Retained scheduler terminal fixture")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "fixture-seed",
		map[string]string{"name": role, "value": "fixture-native-source"})
	if status != http.StatusCreated {
		t.Fatalf("seed scheduler credential: status %d", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", token, "fixture-schedule",
		map[string]any{"name": "fixture-schedule", "provider": provider.name, "key": role,
			"old_ref": "none", "interval_seconds": 1800, "next_run_at": time.Now().Add(-time.Minute)})
	if status != http.StatusCreated {
		t.Fatalf("seed scheduler cadence: status %d", status)
	}
	status, fresh := secretsReqKey(t, h, http.MethodPost, path, token, key, nil)
	if status != http.StatusOK || !bytes.Contains(fresh, []byte(`"ran":1`)) {
		t.Fatalf("seed one terminal scheduler result: status %d", status)
	}
	original := bytes.Replace(fresh, []byte(`"old_ref":"none"`), []byte(`"old_ref":"`+marker+`"`), 1)
	if bytes.Equal(original, fresh) {
		t.Fatal("seeded receipt did not contain its predecessor field")
	}
	var outer, binding string
	if err := h.store.WithTenantProjection(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT idempotency_key, request_binding FROM secret_rotation_schedule_ticks
			WHERE tenant_id = $1 AND terminal_body = $2`, h.tenant, fresh).Scan(&outer, &binding); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_tick_rows SET reference_provider_type = '', old_ref = $3
			WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, outer, marker); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_ticks SET terminal_body = $3, receipt = $4::jsonb
			WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, outer, original, original); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE idempotency_keys SET status = 'bound', result = NULL, completed_at = NULL
			WHERE tenant_id = $1 AND key = $2`, h.tenant, outer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, read := secretsReqKey(t, h, http.MethodPost, path, token, key, nil)
	if status != http.StatusOK || !bytes.Contains(read, []byte(`"ran":1`)) || bytes.Contains(read, []byte(marker)) {
		t.Fatalf("legacy terminal-before-cache returned status %d, preserved run=%t, copied marker=%t",
			status, bytes.Contains(read, []byte(`"ran":1`)), bytes.Contains(read, []byte(marker)))
	}
	var captured struct {
		Body   json.RawMessage `json:"b"`
		Source string          `json:"t"`
	}
	protected, err := h.srv.idem.DoDurableEffectBound(ctx, h.tenant, outer, binding, func(context.Context) ([]byte, error) {
		return nil, errors.New("fixture terminal replay must not rerun the effect")
	})
	if err != nil || json.Unmarshal(protected, &captured) != nil || !bytes.Equal(captured.Body, read) ||
		captured.Source != store.SecretRotationScheduleTerminalReferenceSource(original) || bytes.Contains(protected, []byte(marker)) {
		t.Fatalf("protected terminal reference view did not verify or copied legacy bytes: %v", err)
	}
	retained, err := h.store.GetSecretRotationScheduleTick(ctx, h.tenant, outer)
	if err != nil || !bytes.Equal(retained.TerminalBody, original) {
		t.Fatalf("the original SQL terminal authority changed: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `DELETE FROM secret_rotation_schedule_commands
		WHERE tenant_id = $1 AND tick_idempotency_key = $2`, h.tenant, outer); err != nil {
		t.Fatal(err)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, path, token, key, nil); status != http.StatusOK || !bytes.Equal(replay, read) {
		t.Fatalf("verified protected replay did not survive child collection, status %d", status)
	}
}

func TestMixedVersionRevocationRebuildKeepsSettledLogicalAttempts(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111140"
	const oldOperation = "fixture-retained-initial"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, issued, err := lifecycle.IssueBound(ctx, provider.name, "reader", time.Hour, "fixture-issue", "sha256:fixture-issue")
	secret.Wipe(issued)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(projections.DynamicSecretLeaseRevocationRequested{
		TenantEpoch: record.TenantEpoch, OperationID: oldOperation, ID: record.ID,
		Provider: record.Provider, BackendRef: record.BackendRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	old, err := log.Append(ctx, events.Event{
		ID:       dynamicSecretEventID(tenant, record.TenantEpoch, "lease-revocation-requested", oldOperation),
		TenantID: tenant, Type: projections.EventDynamicSecretLeaseRevocationRequested, SchemaVersion: 2, Data: legacy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	currentIntent := func() orchestrator.Message {
		t.Helper()
		record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
		if err != nil || record.RevokeOutboxID == nil {
			t.Fatalf("load scoped revoke attempt: %v", err)
		}
		item, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
		if err != nil {
			t.Fatal(err)
		}
		return orchestrator.Message{TenantID: tenant, ID: item.ID, Destination: item.Destination,
			IdempotencyKey: item.IdempotencyKey, Payload: item.Payload, Attempts: 10}
	}
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, currentIntent(), errors.New("fixture unavailable")); err != nil || !handled {
		t.Fatalf("settle the old initial attempt as failed: handled=%t err=%v", handled, err)
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-new-retry", "sha256:fixture-new-retry"); err != nil {
		t.Fatal(err)
	}
	retry := currentIntent()
	if handled, err := dispatcher.Deliver(ctx, retry); err != nil || !handled {
		t.Fatalf("settle the new retry: handled=%t err=%v", handled, err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("record projected high-water mark: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = 'dynsecret.revoke'`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild mixed retained sources after outbox collection: %v", err)
	}
	rebuilt, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || rebuilt.RevocationStatus != store.DynamicSecretRevocationCompleted || rebuilt.RevokeOutboxID == nil || *rebuilt.RevokeOutboxID == retry.ID {
		t.Fatalf("mixed replay did not resolve a new physical row to the same settled attempt: %v", err)
	}
	rows, err := st.SystemPool().Query(ctx, `SELECT status, payload FROM outbox WHERE tenant_id = $1 AND destination = 'dynsecret.revoke'`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var status string
		var payload []byte
		if err := rows.Scan(&status, &payload); err != nil {
			t.Fatal(err)
		}
		count++
		if status != "delivered" || bytes.Contains(payload, []byte(record.BackendRef)) {
			t.Errorf("rebuild created work or copied a reference for a settled attempt: status %s", status)
		}
	}
	if rows.Err() != nil || count != 2 || len(provider.Revocations()) != 1 {
		t.Fatalf("settled effect count changed: attempts=%d removals=%d err=%v", count, len(provider.Revocations()), rows.Err())
	}
}

// CR-663: the next request must recover the durable lease-level choice after
// an append/projection interruption, even when its own authenticated key differs.
func TestDynamicRevocationDifferentKeysRecoverOneAppendedRetry(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111141"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, issued, err := lifecycle.IssueBound(ctx, provider.name, "reader", time.Hour, "fixture-issue", "sha256:fixture-issue")
	secret.Wipe(issued)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-initial", "sha256:fixture-initial"); err != nil {
		t.Fatal(err)
	}
	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || record.RevokeOutboxID == nil {
		t.Fatalf("read the original intent: %v", err)
	}
	item, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	m := orchestrator.Message{TenantID: tenant, ID: item.ID, Destination: item.Destination,
		IdempotencyKey: item.IdempotencyKey, Payload: item.Payload, Attempts: 10}
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, m, errors.New("fixture unavailable")); !handled || err != nil {
		t.Fatalf("commit the original failed attempt: %v", err)
	}
	crashed := errors.New("fixture stopped after the first retry was appended")
	var interrupted atomic.Bool
	lifecycle.afterCanonicalAppend = func(e events.Event) error {
		if e.Type == projections.EventDynamicSecretLeaseRevocationRetryRequested && interrupted.CompareAndSwap(false, true) {
			return crashed
		}
		return nil
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "fixture-first-retry", "sha256:fixture-first-retry"); !errors.Is(err, crashed) {
		t.Fatalf("first retry did not stop at the intended boundary: %v", err)
	}
	for _, key := range []string{"fixture-other-request", "fixture-first-retry"} {
		if _, err := lifecycle.RevokeBound(ctx, lease.ID, key, "sha256:"+key); err != nil {
			t.Errorf("bounded retry did not recover the earlier intent: %v", err)
		}
	}
	var requests int
	if err := log.Replay(ctx, 1, func(e events.Event) error {
		if e.TenantID == tenant && e.Type == projections.EventDynamicSecretLeaseRevocationRetryRequested {
			requests++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Errorf("append-before-project created %d retry requests for one failed attempt", requests)
	}
	projected, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || projected.RevokeOutboxID == nil || projected.RevocationStatus != store.DynamicSecretRevocationPending {
		t.Fatalf("load the one recovered retry: %v", err)
	}
	next, err := outbox.Get(ctx, tenant, *projected.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	claimed := orchestrator.Message{TenantID: tenant, ID: next.ID, Destination: next.Destination,
		IdempotencyKey: next.IdempotencyKey, Payload: next.Payload, Attempts: 10}
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, claimed, errors.New("fixture unavailable again")); !handled || err != nil {
		t.Fatalf("settle the recovered retry: %v", err)
	}
	type response struct {
		key string
		err error
	}
	start := make(chan struct{})
	responses := make(chan response, 2)
	for _, key := range []string{"fixture-contending-one", "fixture-contending-two"} {
		go func() {
			<-start
			_, err := lifecycle.RevokeBound(ctx, lease.ID, key, "sha256:"+key)
			responses <- response{key, err}
		}()
	}
	close(start)
	var retryKeys []string
	for range 2 {
		reply := <-responses
		if errors.Is(reply.err, store.ErrResourceAdmissionBusy) {
			retryKeys = append(retryKeys, reply.key)
		} else if reply.err != nil {
			t.Error(reply.err)
		}
	}
	for _, key := range retryKeys {
		if _, err := lifecycle.RevokeBound(ctx, lease.ID, key, "sha256:"+key); err != nil {
			t.Fatalf("retry the same bound request after admission contention: %v", err)
		}
	}
	requests = 0
	if err := log.Replay(ctx, 1, func(e events.Event) error {
		if e.TenantID == tenant && e.Type == projections.EventDynamicSecretLeaseRevocationRetryRequested {
			requests++
		}
		return nil
	}); err != nil || requests != 2 {
		t.Fatalf("competing keys did not converge to one successor per prior failure: count=%d err=%v", requests, err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild the exact retry after two request keys: %v", err)
	}
}

func TestNativeScheduleDoesNotChainHistoricalHostedReference(t *testing.T) {
	assertReplacementScheduleKeepsPredecessor(t, &staticRotationProviderDouble{name: "fixture-native", role: "fixture/rotation"},
		"fixture-native", "fixture/rotation", 0)
}

// CR-663. A legacy native engine can terminalize a plain due edge without a
// provider call. Its name never authorizes a qualified historical reference.
func TestHistoricalStaticCadenceKeepsOnlyPlainNativeDueEdges(t *testing.T) {
	const provider = "fixture-historical-static"
	const qualified = "fixture-binding/fixture-unproved-reference"
	rotator := &countingRotationRotator{}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretRotators = map[string]rotation.Rotator{provider: rotator}
	})
	registerServedTenant(t, h, "Historical native schedule fixture")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	dueAt := time.Now().UTC().Add(-time.Minute)
	for name, ref := range map[string]string{"native": "fixture-native-ref", "qualified": qualified} {
		if _, err := h.srv.orch.UpsertSecretRotationSchedule(t.Context(), h.tenant, store.SecretRotationSchedule{
			Name: name, Provider: provider, Key: "fixture/" + name, OldRef: ref,
			IntervalSeconds: 1800, NextRunAt: dueAt, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, "fixture-historical-native", nil)
	var reply secretRotationDueRunValue
	if status != http.StatusOK || json.Unmarshal(body, &reply) != nil || reply.Scanned != 1 ||
		reply.Ran != 1 || len(reply.Runs) != 1 || reply.Runs[0].Status != "unsupported" ||
		bytes.Contains(body, []byte(qualified)) || rotator.calls != 0 {
		t.Fatalf("historical cadence did not terminalize only the native edge: status=%d scanned=%d ran=%d calls=%d",
			status, reply.Scanned, reply.Ran, rotator.calls)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		var copied int
		if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM secret_rotation_schedule_tick_rows
			WHERE tenant_id=$1 AND old_ref=$2`, h.tenant, qualified).Scan(&copied); err != nil {
			return err
		}
		if copied != 0 {
			t.Error("qualified historical reference entered a new snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDynamicLeaseScheduleDoesNotChainHistoricalHostedReference(t *testing.T) {
	provider := &leaseRotationDouble{}
	assertReplacementScheduleKeepsPredecessor(t, provider, "dynamic-lease:"+provider.Name(), "reporting", 300)
}

func assertReplacementScheduleKeepsPredecessor(t *testing.T, provider dynsecret.Provider, scheduleProvider, role string, ttl int) {
	t.Helper()
	const previousRef = "unlimited/fixture-historical-reference"
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "Native replacement schedule fixture")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "fixture-seed",
		map[string]string{"name": role, "value": "fixture-successor"})
	if status != http.StatusCreated {
		t.Fatalf("seed the current secret: HTTP %d", status)
	}
	epoch, err := h.store.ApplicationSecretTenantEpoch(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	prior := projections.SecretStaticRotationQueued{
		ID: uuid.NewString(), TenantEpoch: epoch, Provider: "fixture-prior-hosted",
		Key: role, OldRef: "none", ExpectedVersion: 1,
		IdempotencyKeyDigest: crypto.SHA256Hex([]byte("fixture-previous-command")),
		RequestBinding:       crypto.SHA256Hex([]byte("fixture-previous-binding")),
	}
	raw, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(ctx, events.Event{
		ID: prior.ID, TenantID: h.tenant, SchemaVersion: 1, Type: projections.EventSecretStaticRotationQueued, Data: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	// Restore the old projected terminal tuple as an upgrade fixture.
	_, err = h.store.SystemPool().Exec(ctx, `UPDATE secret_static_rotation_commands
		SET phase='completed', provider_type='openrouter', result_version=1, terminal_at=now(), new_ref=$3
		WHERE tenant_id=$1 AND id=$2`, h.tenant, prior.ID, previousRef)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"name": "fixture-replacement-schedule", "provider": scheduleProvider, "key": role, "old_ref": "none",
		"interval_seconds": 1800, "next_run_at": time.Now().Add(-time.Minute)}
	if ttl != 0 {
		request["ttl_seconds"] = ttl
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "fixture-schedule", request)
	if status != http.StatusCreated {
		t.Fatalf("admit replacement schedule: HTTP %d", status)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, "fixture-tick", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ran":1`)) || bytes.Contains(body, []byte(previousRef)) {
		t.Errorf("replacement schedule did not keep its admitted predecessor: status=%d, old value present=%t",
			status, bytes.Contains(body, []byte(previousRef)))
	}
	if err := h.log.Replay(ctx, event.Sequence+1, func(added events.Event) error {
		if added.TenantID == h.tenant && bytes.Contains(added.Data, []byte(previousRef)) {
			t.Errorf("fresh %s copied an unproved hosted predecessor", added.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyNumericRetryRequiresOriginalOutboxAuthority(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111142"
	ctx := t.Context()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, issued, err := lifecycle.IssueBound(ctx, provider.name, "reader", time.Hour, "fixture-issue", "sha256:fixture-issue")
	secret.Wipe(issued)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	binding := store.DynamicSecretRevokeOutboxBinding{
		TenantEpoch: record.TenantEpoch, LeaseID: lease.ID, Provider: record.Provider, BackendRef: record.BackendRef,
	}
	legacyPayload, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	key := store.DynamicSecretRevokeOutboxIdempotencyKey(record.TenantEpoch, lease.ID)
	var outboxID int64
	if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key)
			VALUES ($1,'dynsecret.revoke',$2,$3) RETURNING id`, tenant, legacyPayload, key).Scan(&outboxID)
	}); err != nil {
		t.Fatal(err)
	}
	original := projections.DynamicSecretLeaseRevocationRequested{
		TenantEpoch: record.TenantEpoch, OperationID: "fixture-old-initial", ID: lease.ID,
		Provider: record.Provider, BackendRef: record.BackendRef,
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := log.Append(ctx, events.Event{
		ID:       dynamicSecretEventID(tenant, record.TenantEpoch, "lease-revocation-requested", original.OperationID),
		TenantID: tenant, Type: projections.EventDynamicSecretLeaseRevocationRequested, SchemaVersion: 2, Data: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	if err := projector.Apply(ctx, source); err != nil {
		t.Fatal(err)
	}
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, orchestrator.Message{
		TenantID: tenant, ID: outboxID, Destination: "dynsecret.revoke", IdempotencyKey: key, Payload: legacyPayload, Attempts: 10,
	}, errors.New("fixture unavailable")); !handled || err != nil {
		t.Fatalf("settle initial legacy attempt: %v", err)
	}

	last, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retryID := "fixture-old-retry"
	retrySource := func(previous int64) events.Event {
		t.Helper()
		body, err := json.Marshal(projections.DynamicSecretLeaseRevocationRetryRequested{
			TenantEpoch: record.TenantEpoch, OperationID: retryID, ID: lease.ID,
			Provider: record.Provider, BackendRef: record.BackendRef, PreviousOutboxID: previous,
		})
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{
			ID:       dynamicSecretEventID(tenant, record.TenantEpoch, "lease-revocation-retry-requested", retryID),
			TenantID: tenant, Type: projections.EventDynamicSecretLeaseRevocationRetryRequested, SchemaVersion: 2,
			Data: body, Time: time.Now().UTC(), Sequence: last + 1,
		}
	}
	if err := projector.Apply(ctx, retrySource(outboxID+1)); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different physical identity established a legacy retry: %v", err)
	}
	binding.BackendRef = ""
	binding.RefSource = store.DynamicSecretRevokeFromIssuedLease
	rebuiltPayload, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	setOriginalPayload := func(payload []byte) {
		t.Helper()
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenant, outboxID, payload)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setOriginalPayload(rebuiltPayload)
	if err := projector.Apply(ctx, retrySource(outboxID)); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Errorf("reconstructed encoding established original legacy numeric authority: %v", err)
	}
	setOriginalPayload(legacyPayload)
	next, err := log.Append(ctx, retrySource(outboxID))
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, next); err != nil {
		t.Fatalf("exact retained physical predecessor did not restore the v2 retry: %v", err)
	}
	observed, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || observed.RevocationStatus != store.DynamicSecretRevocationPending ||
		observed.RevokeOutboxID == nil || *observed.RevokeOutboxID == outboxID {
		t.Fatalf("valid v2 retry did not bind a new exact command: %v", err)
	}
}

func TestServedImportedCredentialNeedsCompletePublicReferenceProof(t *testing.T) {
	const role = "fixture/imported"
	const hexID = "aabbccddaabbccddaabbccddaabbccdd"
	cases := []struct {
		kind     string
		binding  string
		id       string
		document string
	}{
		{"openrouter", "unlimited", "fixture-public-id",
			`{"api_key":"fixture-authenticator","key_hash":"fixture-public-id"}`},
		{"cloudflare-r2", "account " + hexID + " template " + hexID, hexID,
			`{"secret_access_key":"fixture-derived-material","access_key_id":"` + hexID + `"}`},
		{"fireworks", "fixture-account/fixture-user", "fixture-public-id",
			`{"api_key":"fixture-authenticator","key_id":"fixture-other-id","KEY_ID":"fixture-public-id"}`},
	}
	for _, fixture := range cases {
		t.Run(fixture.kind, func(t *testing.T) {
			var providerCalls atomic.Int32
			vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				providerCalls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer vendor.Close()
			provider := config.DynamicSecretProviderConfig{
				TenantID: servedTestTenant, ID: "fixture-provider", Type: fixture.kind, Endpoint: vendor.URL,
				APIKeyRef:    writeServedCredentialFile(t, "fixture-admin", "fixture-management"),
				AllowedRoles: []string{role}, RoleBindings: map[string]string{role: fixture.binding},
				MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
			}
			registry, err := dynamicSecretProvidersFromConfig(t.Context(), []config.DynamicSecretProviderConfig{provider}, nil, serverTestPrincipalKEK(), nil)
			if err != nil {
				t.Fatal(err)
			}
			h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
				d.TenantDynamicSecretProviders = registry
			})
			registerServedTenant(t, h, "Imported reference fixture")
			tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
			if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "fixture-import",
				map[string]string{"name": role, "value": fixture.document}); status != http.StatusCreated {
				t.Fatalf("store the historical protected document: HTTP %d", status)
			}
			binding, err := hostedkey.ParseBinding(fixture.kind, fixture.binding)
			if err != nil {
				t.Fatal(err)
			}
			last, err := h.log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request := map[string]any{"provider": provider.ID, "key": role, "old_ref": binding + "/" + fixture.id}
			if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "fixture-static", request); status != http.StatusConflict ||
				bytes.Contains(body, []byte(fixture.id)) {
				t.Errorf("direct static admission did not safely refuse incomplete proof: HTTP %d", status)
			}
			request["name"], request["interval_seconds"] = "fixture-cadence", 120
			if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok, "fixture-schedule", request); status != http.StatusConflict ||
				bytes.Contains(body, []byte(fixture.id)) {
				t.Errorf("schedule admission did not safely refuse incomplete proof: HTTP %d", status)
			}
			after, err := h.log.LastSequence(t.Context())
			if err != nil || after != last || providerCalls.Load() != 0 {
				t.Fatalf("refused references produced effects: sequence advance=%d calls=%d err=%v", after-last, providerCalls.Load(), err)
			}
		})
	}
}

func TestServedSchedulerChecksLegacySuccessorEvenWithNoPredecessor(t *testing.T) {
	for _, mode := range []string{"prepared", "queue-replay", "unstarted", "wrong-revision"} {
		t.Run(mode, func(t *testing.T) {
			const role = "fixture/hosted"
			const marker = "unlimited/fixture-unproved-successor"
			const key = "fixture-resume-scheduler"
			const path = "/api/v1/secrets/rotation-schedules/run-due"
			const oldOwner = "fixture-scheduler-owner"
			const oldChild = "fixture-scheduler-child"
			ctx := t.Context()
			provider := &referencePublishingProvider{issueOutboxProvider{name: "fixture-provider", providerType: "openrouter"}}
			h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
				d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
			})
			registerServedTenant(t, h, "Historical scheduler successor fixture")
			tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
			if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "fixture-seed",
				map[string]string{"name": role, "value": "fixture-initial"}); status != http.StatusCreated {
				t.Fatalf("store the current secret: HTTP %d", status)
			}
			schedule, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
				ID: "dae27b65-5eda-4ca9-a655-fd6153570311", Name: "fixture-schedule", Provider: provider.name, Key: role, OldRef: "none",
				ReferenceProviderType: "openrouter", IntervalSeconds: 1800, Enabled: true, NextRunAt: time.Now().UTC().Add(-time.Minute),
			})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unstarted" {
				if _, err := h.srv.orch.UpsertSecretRotationSchedule(ctx, h.tenant, store.SecretRotationSchedule{
					ID: "dae27b65-5eda-4ca9-a655-fd6153570312", Name: "fixture-eligible-schedule",
					Provider: provider.name, Key: role, OldRef: "none", ReferenceProviderType: "openrouter",
					IntervalSeconds: 1800, Enabled: true, NextRunAt: time.Now().UTC().Add(-time.Minute),
				}); err != nil {
					t.Fatal(err)
				}
			}
			reg, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, h.log, h.store, h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			keyDigest := crypto.SHA256Hex([]byte(key))
			outer := rotationcommand.OuterKeyV3Prefix + crypto.SHA256Hex([]byte(fmt.Sprintf(
				`{"domain":"trstctl.secret-rotation-schedule.tick-key.v3","tenant_id":%q,"tenant_registration_event_sequence":%d,"idempotency_key_sha256":%q}`,
				h.tenant, reg.EventSequence, keyDigest)))
			routeBinding := crypto.SHA256Hex([]byte(`{"domain":"trstctl.api.mutation-route-binding.v1","principal":"secrets-test","method":"POST","escaped_path":"` + path + `"}`))
			binding := crypto.SHA256Hex([]byte(fmt.Sprintf(
				`{"domain":"trstctl.secret-rotation-schedule.tick-binding.v3","tenant_id":%q,"tenant_registration_event_sequence":%d,"outer_key":%q,"route_binding":%q}`,
				h.tenant, reg.EventSequence, outer, routeBinding)))
			tick, state, err := h.store.ClaimSecretRotationScheduleTick(ctx, h.tenant, outer, binding, reg.EventID, reg.EventSequence,
				oldOwner, oldChild, time.Minute)
			if err != nil || state != store.SecretRotationScheduleTickAcquired {
				t.Fatalf("claim the pre-upgrade tick: state=%s err=%v", state, err)
			}
			row, err := h.store.GetSecretRotationScheduleTickRow(ctx, h.tenant, outer, 1)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unstarted" {
				if err := h.store.WithTenantProjection(ctx, h.tenant, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_tick_rows
						SET provider='fixture-removed', old_ref=$3, reference_provider_type=''
						WHERE tenant_id=$1 AND idempotency_key=$2 AND ordinal=1`, h.tenant, outer, marker); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_scan_cursors
						SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND active_tick_key=$2`, h.tenant, outer)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				status, body := secretsReqKey(t, h, http.MethodPost, path, tok, key, nil)
				if status != http.StatusOK || !bytes.Contains(body, []byte(store.SecretRotationScheduleReferenceReviewRequired)) ||
					!bytes.Contains(body, []byte(`"ran":1`)) || bytes.Contains(body, []byte(marker)) {
					t.Fatalf("unstarted fenced work did not allow the next eligible row: HTTP %d", status)
				}
				return
			}
			if _, err := h.store.StartSecretRotationScheduleTickRow(ctx, tick, oldOwner, tick.OwnerGeneration, row, oldChild, time.Minute); err != nil {
				t.Fatal(err)
			}
			runID := orchestrator.SecretRotationScheduleRunID(h.tenant, reg.EventSequence, row.ID, row.NextRunAt)
			commandKey := orchestrator.SecretRotationScheduleCommandKey(runID)
			commandBinding := crypto.SHA256Hex([]byte(fmt.Sprintf(
				`{"domain":"trstctl.secret-rotation-schedule.child-binding.v3","tenant_id":%q,"tenant_registration_event_sequence":%d,"schedule_id":%q,"due_at":%q,"provider":%q,"key":%q,"old_ref":"none","command_key":%q}`,
				h.tenant, reg.EventSequence, schedule.ID, row.NextRunAt.UTC().Format(time.RFC3339Nano), row.Provider, row.Key, commandKey)))
			command := store.SecretRotationScheduleCommand{
				TenantID: h.tenant, IdentityVersion: store.SecretRotationScheduleIdentityVersion,
				TenantRegistrationEventID: reg.EventID, TenantRegistrationEventSequence: reg.EventSequence,
				ScheduleID: row.ID, RunID: runID, DueAt: row.NextRunAt, Provider: row.Provider, Key: row.Key, OldRef: "none",
				IntervalSeconds: row.IntervalSeconds, ConfigEventSequence: row.ConfigEventSequence,
				TickIdempotencyKey: outer, TickOrdinal: 1, CommandKey: commandKey,
				RequestBinding: commandBinding, TerminalEventID: orchestrator.SecretRotationScheduleRunEventID(runID),
			}
			if _, acquired, err := h.store.ClaimSecretRotationScheduleCommand(ctx, command, oldChild, time.Minute,
				h.srv.orch.GuardUnprojectedSecretRotationScheduleControl); err != nil || !acquired {
				t.Fatalf("claim the exact original child: acquired=%t err=%v", acquired, err)
			}
			if mode == "prepared" || mode == "wrong-revision" {
				ranAt := time.Now().UTC()
				data, err := json.Marshal(projections.SecretRotationScheduleRan{
					ScheduleID: row.ID, RunID: runID, DueAt: row.NextRunAt,
					TenantRegistrationEventID: reg.EventID, TenantRegistrationEventSequence: reg.EventSequence,
					Provider: row.Provider, Key: row.Key, OldRef: "none",
					IntervalSeconds: row.IntervalSeconds, ConfigEventSequence: row.ConfigEventSequence,
					CommandKey: commandKey, RequestBinding: commandBinding, Status: "queued", NewRef: marker,
				})
				if err != nil {
					t.Fatal(err)
				}
				_, err = h.store.PrepareSecretRotationScheduleCommandTerminal(ctx, store.SecretRotationScheduleRun{
					TenantID: h.tenant, IdentityVersion: store.SecretRotationScheduleIdentityVersion,
					TenantRegistrationEventID: reg.EventID, TenantRegistrationEventSequence: reg.EventSequence,
					ScheduleID: row.ID, RunID: runID, DueAt: row.NextRunAt, Provider: row.Provider, Key: row.Key, OldRef: "none",
					IntervalSeconds: row.IntervalSeconds, ConfigEventSequence: row.ConfigEventSequence,
					CommandKey: commandKey, RequestBinding: commandBinding, Status: "queued", NewRef: marker, RanAt: ranAt,
					EventID: command.TerminalEventID, EventType: projections.EventSecretRotationScheduleRan, EventDigest: crypto.SHA256Hex(data),
					SchemaVersion:      projections.SecretRotationScheduleRanEventSchemaVersion,
					TickIdempotencyKey: outer, TickOrdinal: 1, LeaseToken: oldChild,
				})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "wrong-revision" {
					if _, err := h.log.Append(ctx, events.Event{ID: command.TerminalEventID,
						TenantID: h.tenant, Type: projections.EventSecretRotationScheduleRan,
						Actor:         &events.Actor{Subject: "secret-rotation-schedule:" + row.ID},
						SchemaVersion: projections.SecretRotationScheduleRanEventSchemaVersion, Time: ranAt, Data: data}); err != nil {
						t.Fatal(err)
					}
					if err := h.store.WithTenantProjection(ctx, h.tenant, func(tx pgx.Tx) error {
						if _, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_tick_rows
							SET config_event_sequence=config_event_sequence+1, reference_provider_type='fireworks'
							WHERE tenant_id=$1 AND idempotency_key=$2 AND ordinal=1`, h.tenant, outer); err != nil {
							return err
						}
						_, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_ticks
							SET current_config_event_sequence=current_config_event_sequence+1, current_reference_provider_type='fireworks'
							WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, outer)
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				epoch, err := h.store.ApplicationSecretTenantEpoch(ctx, h.tenant)
				if err != nil {
					t.Fatal(err)
				}
				digest := crypto.SHA256Hex([]byte(commandKey))
				namespace := uuid.MustParse("639435c4-b02a-59fc-9f05-d3ae2e0d0042")
				cmdID := uuid.NewSHA1(namespace, []byte(h.tenant+"\x00"+epoch+"\x00"+role+"\x00static-rotate\x00"+digest)).String()
				raw, err := json.Marshal(projections.SecretStaticRotationQueued{
					ID: cmdID, TenantEpoch: epoch, Provider: row.Provider, Key: role, OldRef: "none",
					ExpectedVersion: 1, RequestBinding: commandBinding, IdempotencyKeyDigest: digest, ScheduleID: row.ID,
				})
				if err != nil {
					t.Fatal(err)
				}
				e, err := h.log.Append(ctx, events.Event{ID: cmdID, Type: projections.EventSecretStaticRotationQueued, TenantID: h.tenant,
					SchemaVersion: 1, Data: raw})
				if err != nil {
					t.Fatal(err)
				}
				if err := h.srv.proj.Apply(ctx, e); err != nil {
					t.Fatal(err)
				}
				if _, err := h.store.SystemPool().Exec(ctx, `UPDATE secret_static_rotation_commands
					SET phase='failed', provider_type='openrouter', new_ref=$3, terminal_at=now()
					WHERE tenant_id=$1 AND id=$2`, h.tenant, cmdID, marker); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.store.WithTenantProjection(ctx, h.tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_scan_cursors
					SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND active_tick_key=$2`, h.tenant, outer); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE secret_rotation_schedule_commands
					SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND run_id=$2`, h.tenant, runID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			status, body := secretsReqKey(t, h, http.MethodPost, path, tok, key, nil)
			if mode == "wrong-revision" {
				retained, err := h.store.GetSecretRotationScheduleCommand(ctx, h.tenant, row.ID, runID)
				if status != http.StatusServiceUnavailable || err != nil || retained.Status != "claimed" || bytes.Contains(body, []byte(marker)) {
					t.Fatalf("fenced recovery consumed another revision's receipt: HTTP %d command=%s err=%v", status, retained.Status, err)
				}
				return
			}
			if status != http.StatusOK || !bytes.Contains(body, []byte(store.SecretRotationScheduleReferenceReviewRequired)) ||
				!bytes.Contains(body, []byte(`"ran":0`)) || bytes.Contains(body, []byte(marker)) {
				t.Fatalf("unsafe legacy successor was not deferred with safe metadata: HTTP %d", status)
			}
			if _, found, err := h.log.EventByID(ctx, command.TerminalEventID); err != nil || found {
				t.Fatalf("a fenced legacy command emitted a fresh terminal event: found=%t err=%v", found, err)
			}
		})
	}
}
