// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

// A tenant of its own, so nothing another projections test leaves behind
// reaches it.
const s7Tenant = "a7770000-0000-4000-8000-000000000073"

// openS7HistoryLog opens the embedded JetStream log with the history-rewrite
// coordinator and proof walls a tenant key-domain lifecycle needs (the same
// wiring as internal/store's openTenantKeyDomainHistory).
func openS7HistoryLog(t *testing.T, s *store.Store) (*events.Log, []events.TenantDataRewriteOption, func(tenantseal.Access)) {
	t.Helper()
	var access tenantseal.Access
	log, err := eventstest.OpenFixture(
		context.Background(),
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		// This fixture uses the actual tenant key resolver. Public registration
		// precedes its construction; sealed events must wait for it and prove
		// every container against the exact field AAD before publication.
		events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			// CR-045: deployment and tenant key-state snapshots borrow an
			// exclusive SQL owner; history A must precede that owner B.
			if events.RequiresExclusiveKeyStateAdmission(event.Type) &&
				!events.IngressHistoryReadPreheld(ctx) {
				return events.Event{}, fmt.Errorf("CR-045 snapshot %s opened B before history A", event.Type)
			}
			switch event.Type {
			case projections.EventApplicationSecretCreated, projections.EventApplicationSecretRotated,
				projections.EventApplicationSecretRecovered, projections.EventApplicationSecretDeleted,
				projections.EventApplicationSecretUndeleted:
				if access == nil {
					return events.Event{}, errors.New("application-secret fixture custody is unavailable")
				}
				var mutation projections.ApplicationSecretMutation
				if err := json.Unmarshal(event.Data, &mutation); err != nil {
					return events.Event{}, err
				}
				if err := tenantseal.AuthenticateApplicationSecretMutationContainers(ctx, access, event.TenantID, mutation); err != nil {
					return events.Event{}, err
				}
			case projections.EventSecretSyncQueued:
				if access == nil {
					return events.Event{}, errors.New("secret-sync fixture custody is unavailable")
				}
				var queued projections.SecretSyncQueued
				if err := json.Unmarshal(event.Data, &queued); err != nil {
					return events.Event{}, err
				}
				if queued.ID == "" || queued.Target == "" || queued.RemoteKey == "" || len(queued.Sealed) == 0 {
					return events.Event{}, errors.New("secret-sync fixture command is incomplete")
				}
				aad := []byte(event.TenantID + "/secret-sync/" + queued.Target + "/" + queued.ID + "/" + queued.RemoteKey)
				verified, err := tenantseal.VerifyRewrapPair(ctx, access, event.TenantID, queued.Sealed, queued.Sealed, aad)
				if err != nil {
					return events.Event{}, fmt.Errorf("secret-sync fixture container authentication: %w", err)
				}
				if !verified {
					return events.Event{}, errors.New("secret-sync fixture container authentication failed")
				}
			default:
				if fixtureHasSealedField(event.Data) {
					return events.Event{}, fmt.Errorf("unclassified sealed fixture event %s", event.Type)
				}
			}
			return publish(ctx)
		}),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)),
		events.WithHistoryRewriteContinuityVerifier(func(
			_ context.Context,
			evidence events.TenantDataContinuityEvidence,
		) error {
			if evidence.TenantID == "" || evidence.Receipt.Type != projections.EventHistoryTenantDataRewriteContinuity {
				return errors.New("invalid tenant-domain continuity receipt")
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, []events.TenantDataRewriteOption{
		events.WithTenantDataCutoverPreparation(s.PrepareTenantDataCutover),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: "s7-genesis"}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			data, err := json.Marshal(report)
			return events.Event{
				ID:       "s7-continuity-" + report.OperationID,
				Type:     projections.EventHistoryTenantDataRewriteContinuity,
				TenantID: report.TenantID, Time: report.CompletedAt,
				SchemaVersion: events.DefaultSchemaVersion, Data: data,
			}, err
		}),
	}, func(current tenantseal.Access) { access = current }
}

func fixtureHasSealedField(data []byte) bool {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		lower := strings.ToLower(string(data))
		return strings.Contains(lower, "sealed") || strings.Contains(lower, "ciphertext")
	}
	var walk func(any) bool
	walk = func(value any) bool {
		switch current := value.(type) {
		case map[string]any:
			for name, nested := range current {
				lower := strings.ToLower(name)
				metadata := lower == "sealed_at" || lower == "sealed_sha256" ||
					lower == "sealed_only_floor" || lower == "sealed_results" ||
					lower == "sealed_tenants_not_opened" || lower == "sealed_copies" ||
					lower == "ciphertext_sha256"
				if !metadata && (lower == "sealed" || strings.HasPrefix(lower, "sealed_") ||
					lower == "requester_sealed" || lower == "ciphertext" || strings.HasPrefix(lower, "ciphertext_")) {
					return true
				}
				if walk(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range current {
				if walk(nested) {
					return true
				}
			}
		}
		return false
	}
	return walk(payload)
}

// TestS7L3RebuildStillSucceedsAfterATenantKeyDomainMigration (R1 review
// S7-L3). The read model is a pure function of the log (AN-2): a full rebuild
// that succeeds before a tenant migrates its key domain must still succeed
// afterwards. The migration rewrites the sealed bytes inside the tenant's
// application-secret event, while the independent mutation receipt keeps the
// digest of the original bytes.
func TestS7L3RebuildStillSucceedsAfterATenantKeyDomainMigration(t *testing.T) {
	s := storetest.OpenRewrapCutoverStore(t, newStore(t), testDSN)
	ctx := context.Background()
	log, rewriteOptions, setAdmissionAccess := openS7HistoryLog(t, s)

	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: s7Tenant,
		Data: tenantRegistered("s7-key-domain-rebuild"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatalf("project tenant registration: %v", err)
	}

	deployment, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x75}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deployment.Destroy)
	wrapperPath := filepath.Join(t.TempDir(), "s7-custody.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x76}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "s7-custody", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(s, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}
	setAdmissionAccess(access)
	lifecycle, err := tenantseal.NewLifecycle(s, log, deployment, registry, rewriteOptions...)
	if err != nil {
		t.Fatal(err)
	}

	// An application secret created through the event path, sealed exactly as
	// the secrets service seals it (tenant resolver, tenant+name AAD).
	const name = "s7/db/password"
	aad := []byte(s7Tenant + "/secret-store/" + name)
	var sealed []byte
	if err := access.WithTenant(ctx, s7Tenant, func(cipher tenantseal.Cipher) (err error) {
		sealed, err = cipher.Seal([]byte("value-one"), aad)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, s7Tenant)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.ApplicationSecretMutation{
		TenantEpoch: epoch, Action: "create", Name: name, ResultVersion: 1, Sealed: sealed,
		IdempotencyKeyDigest: hex64('1'), RequestBinding: hex64('2'),
		CommandEvidence: hex64('3'), Surface: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "a7770000-0000-4000-8000-0000000000e1", Type: projections.EventApplicationSecretCreated,
		TenantID: s7Tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project the application-secret create: %v", err)
	}
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("control: rebuild before the migration: %v", err)
	}

	if _, err := lifecycle.Migrate(ctx, s7Tenant, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "s7-custody",
	}); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// The migrated secret still opens for its tenant (the migration itself worked).
	current, err := s.GetSecret(ctx, s7Tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := access.WithTenant(ctx, s7Tenant, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(current.Sealed, aad)
		return err
	}); err != nil {
		t.Fatalf("control: the migrated secret does not open: %v", err)
	}

	if err := projections.New(s).Rebuild(ctx, log); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("S7-L3: bare rebuild after tenant key migration = %v, want custody refusal", err)
	}
	if err := vh83RecoveryProjector(t, vh83Rig{s: s, log: log, deployment: deployment, registry: registry}).Rebuild(ctx, log); err != nil {
		t.Fatalf("S7-L3: full rebuild fails after the tenant's key-domain migration: %v", err)
	}
}

const s7LegacyTenant = "a7770000-0000-4000-8000-000000000074"

// TestS7L3RebuildStillSucceedsAfterADeploymentKEKRotation (R1 review S7-L3,
// operator variant): the deployment KEK rotation (A198) re-wraps the data key
// of every legacy tenant's history containers, so the same receipt mismatch
// follows an ordinary operator rotation for every tenant that never migrated.
func TestS7L3RebuildStillSucceedsAfterADeploymentKEKRotation(t *testing.T) {
	s := storetest.OpenRewrapCutoverStore(t, newStore(t), testDSN)
	ctx := context.Background()
	log, rewriteOptions, setAdmissionAccess := openS7HistoryLog(t, s)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: s7LegacyTenant,
		Data: tenantRegistered("s7-deployment-rotation-rebuild"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatalf("project tenant registration: %v", err)
	}
	keyFile, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keyFile.Destroy)
	nextPath := filepath.Join(t.TempDir(), "s7-deployment-next.key")
	if err := os.WriteFile(nextPath, bytes.Repeat([]byte{0x78}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "s7-deployment-next", Path: nextPath}})
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := tenantseal.NewDeploymentKeyring(keyFile, s, registry)
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(s, keyring, registry)
	if err != nil {
		t.Fatal(err)
	}
	setAdmissionAccess(access)
	rotation, err := tenantseal.NewDeploymentRotation(s, log, keyring, registry,
		tenantseal.WithDeploymentSettle(0), tenantseal.WithDeploymentHistoryRewriteOptions(rewriteOptions...))
	if err != nil {
		t.Fatal(err)
	}

	const name = "s7/legacy/password"
	aad := []byte(s7LegacyTenant + "/secret-store/" + name)
	var sealed []byte
	if err := access.WithTenant(ctx, s7LegacyTenant, func(cipher tenantseal.Cipher) (err error) {
		sealed, err = cipher.Seal([]byte("legacy-value"), aad)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, s7LegacyTenant)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.ApplicationSecretMutation{
		TenantEpoch: epoch, Action: "create", Name: name, ResultVersion: 1, Sealed: sealed,
		IdempotencyKeyDigest: hex64('4'), RequestBinding: hex64('5'),
		CommandEvidence: hex64('6'), Surface: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "a7770000-0000-4000-8000-0000000000e2", Type: projections.EventApplicationSecretCreated,
		TenantID: s7LegacyTenant, Time: time.Now().UTC(),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project the application-secret create: %v", err)
	}
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("control: rebuild before the deployment KEK rotation: %v", err)
	}

	if _, err := rotation.Begin(ctx, s7LegacyTenant, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "s7-deployment-next",
	}); err != nil {
		t.Fatal(err)
	}
	for step := 0; ; step++ {
		if step > 200 {
			t.Fatal("deployment KEK rotation did not complete in 200 steps")
		}
		if _, err := rotation.Step(ctx); err != nil {
			t.Fatalf("deployment KEK rotation step %d: %v", step, err)
		}
		state, found, err := rotation.Status(ctx)
		if err != nil || !found {
			t.Fatalf("deployment KEK status found=%t err=%v", found, err)
		}
		if state.OperationStatus == store.DeploymentKEKOperationCompleted {
			t.Logf("deployment KEK rotation completed: generation=%d history_events_rewrapped=%d",
				state.Generation, state.HistoryEventsRewrapped)
			break
		}
		if state.OperationStatus == store.DeploymentKEKOperationFailed {
			t.Fatalf("deployment KEK rotation failed: %s %s", state.LastErrorCode, state.LastError)
		}
	}
	current, err := s.GetSecret(ctx, s7LegacyTenant, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := access.WithTenant(ctx, s7LegacyTenant, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(current.Sealed, aad)
		return err
	}); err != nil {
		t.Fatalf("control: the secret does not open after the rotation: %v", err)
	}
	if err := projections.New(s).Rebuild(ctx, log); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("S7-L3: bare rebuild after deployment rotation = %v, want custody refusal", err)
	}
	if err := vh83RecoveryProjector(t, vh83Rig{s: s, log: log, deployment: keyring, registry: registry}).Rebuild(ctx, log); err != nil {
		t.Fatalf("S7-L3: full rebuild fails after the operator's deployment KEK rotation: %v", err)
	}
}
