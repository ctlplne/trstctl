// SPDX-License-Identifier: BUSL-1.1
package projections_test

// PLAN-SIB-55 exercises the retained secret-sync outbox after a tenant or
// deployment key rewrap, including the ordinary rebuild path.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

type vh83Rig struct {
	s          *store.Store
	log        *events.Log
	access     tenantseal.Access
	deployment seal.KeyWrapper
	registry   tenantseal.DomainKEKRegistry
	seal       func(value string, aad []byte) []byte
	open       func(sealed, aad []byte) error
	rewrap     func()
	tryMigrate func() error
	tryRotate  func() error
}

func vh83RecoveryProjector(t *testing.T, rig vh83Rig) *projections.Projector {
	return vh83RecoveryProjectorWithPairProbe(t, rig, nil)
}

func vh83RecoveryProjectorWithPairProbe(t *testing.T, rig vh83Rig, probe func(context.Context, string) error) *projections.Projector {
	t.Helper()
	recoveryAccess := func(operationID string) (tenantseal.Access, error) {
		reader, err := rig.s.NewTenantKeyRecoveryDomainStore(operationID)
		if err != nil {
			return nil, err
		}
		return tenantseal.NewAccess(reader, rig.deployment, rig.registry)
	}
	return projections.New(rig.s,
		projections.WithApplicationSecretRecoveryVerifierFactory(func(operationID string) (func(context.Context, string, projections.ApplicationSecretMutation) error, error) {
			access, err := recoveryAccess(operationID)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context, tenantID string, mutation projections.ApplicationSecretMutation) error {
				return tenantseal.AuthenticateApplicationSecretMutationContainers(ctx, access, tenantID, mutation)
			}, nil
		}),
		projections.WithRewrapRecoveryPairVerifierFactory(func(operationID string) (func(context.Context, string, []byte, []byte, []byte) (bool, error), error) {
			access, err := recoveryAccess(operationID)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context, tenantID string, before, after, aad []byte) (bool, error) {
				if probe != nil {
					if err := probe(ctx, tenantID); err != nil {
						return false, err
					}
				}
				return tenantseal.VerifyRewrapPair(ctx, access, tenantID, before, after, aad)
			}, nil
		}),
	)
}

// newVH83Rig registers a tenant and wires either the tenant key-domain
// migration ("migrate") or the deployment KEK rotation ("rotate") exactly as
// the S7-L3 reproduction does.
func newVH83Rig(t *testing.T, tenant, mode string) vh83Rig {
	t.Helper()
	ctx := context.Background()
	s := storetest.OpenRewrapCutoverStore(t, newStore(t), testDSN)
	log, rewriteOptions, setAdmissionAccess := openS7HistoryLog(t, s)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantRegistered("vh83-" + mode),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	key, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x75}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	wrapperPath := filepath.Join(t.TempDir(), "vh83-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x76}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "vh83-wrapper", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	ref := tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "vh83-wrapper"}
	rig := vh83Rig{s: s, log: log}
	rig.registry = registry
	var withCipher func(func(tenantseal.Cipher) error) error
	switch mode {
	case "migrate":
		access, err := tenantseal.NewAccess(s, key, registry)
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := tenantseal.NewLifecycle(s, log, key, registry, rewriteOptions...)
		if err != nil {
			t.Fatal(err)
		}
		withCipher = func(fn func(tenantseal.Cipher) error) error { return access.WithTenant(ctx, tenant, fn) }
		rig.access = access
		setAdmissionAccess(access)
		rig.deployment = key
		rig.tryMigrate = func() error {
			_, err := lifecycle.Migrate(ctx, tenant, ref)
			return err
		}
		rig.rewrap = func() {
			if err := rig.tryMigrate(); err != nil {
				t.Fatalf("tenant key-domain migration: %v", err)
			}
		}
	case "rotate":
		keyring, err := tenantseal.NewDeploymentKeyring(key, s, registry)
		if err != nil {
			t.Fatal(err)
		}
		access, err := tenantseal.NewAccess(s, keyring, registry)
		if err != nil {
			t.Fatal(err)
		}
		rotation, err := tenantseal.NewDeploymentRotation(s, log, keyring, registry,
			tenantseal.WithDeploymentSettle(0), tenantseal.WithDeploymentHistoryRewriteOptions(rewriteOptions...))
		if err != nil {
			t.Fatal(err)
		}
		withCipher = func(fn func(tenantseal.Cipher) error) error { return access.WithTenant(ctx, tenant, fn) }
		rig.access = access
		setAdmissionAccess(access)
		rig.deployment = keyring
		rig.tryRotate = func() error {
			_, err := rotation.Begin(ctx, tenant, ref)
			return err
		}
		rig.rewrap = func() {
			if _, err := rotation.Begin(ctx, tenant, ref); err != nil {
				t.Fatalf("deployment KEK rotation begin: %v", err)
			}
			for step := 0; step <= 200; step++ {
				if _, err := rotation.Step(ctx); err != nil {
					t.Fatalf("deployment KEK rotation step %d: %v", step, err)
				}
				state, found, err := rotation.Status(ctx)
				if err != nil || !found {
					t.Fatalf("deployment KEK status found=%t err=%v", found, err)
				}
				switch state.OperationStatus {
				case store.DeploymentKEKOperationCompleted:
					t.Logf("deployment KEK rotation completed: generation=%d history_events_rewrapped=%d",
						state.Generation, state.HistoryEventsRewrapped)
					gate, found, err := rig.s.GetTenantApplicationSecretRewrapGate(ctx, tenant)
					if err != nil || !found || gate.InProgress {
						t.Fatalf("deployment rewrap gate after completed rotation found=%t in_progress=%t err=%v", found, gate.InProgress, err)
					}
					return
				case store.DeploymentKEKOperationFailed:
					t.Fatalf("deployment KEK rotation failed: %s %s", state.LastErrorCode, state.LastError)
				}
			}
			t.Fatal("deployment KEK rotation did not complete in 200 steps")
		}
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	rig.seal = func(value string, aad []byte) []byte {
		var out []byte
		if err := withCipher(func(cipher tenantseal.Cipher) (err error) {
			out, err = cipher.Seal([]byte(value), aad)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rig.open = func(sealed, aad []byte) error {
		return withCipher(func(cipher tenantseal.Cipher) error {
			_, err := cipher.Open(sealed, aad)
			return err
		})
	}
	return rig
}

// vh83SyncRebuild: one secret-sync intent (internal/projections/
// secret_integrations.go:891-919 binds the event's sealed copy into the outbox
// payload at :905). A full rebuild truncates secret_sync_jobs but keeps the
// outbox, so the rebuilt intent reattaches to the retained row only when its
// sealed bytes equal the row's (store/secret_integration_outbox.go:309).
func vh83SyncRebuild(t *testing.T, tenant, mode string, tamperAfterProof bool) {
	ctx := context.Background()
	rig := newVH83Rig(t, tenant, mode)
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	const jobID = "a7770000-0000-4000-8000-0000000083a1"
	aad := []byte(tenant + "/secret-sync/ci/" + jobID + "/TOKEN")
	sealed := rig.seal("sync-value", aad)
	payload, err := json.Marshal(projections.SecretSyncQueued{
		TenantEpoch: epoch, ID: jobID, SecretName: "vh83/db/password", SecretVersion: 1,
		Target: "ci", RemoteKey: "TOKEN", ValueDigest: hex64('a'),
		IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID), RequestBinding: hex64('b'),
		Sealed: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.log.Append(ctx, events.Event{
		ID: store.SecretSyncQueuedEventID(tenant, jobID), Type: projections.EventSecretSyncQueued,
		TenantID: tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(rig.s).ProjectCatchUp(ctx, rig.log); err != nil {
		t.Fatalf("project the secret-sync intent: %v", err)
	}
	outboxSealed := func() []byte {
		t.Helper()
		var raw []byte
		if err := rig.s.SystemPool().QueryRow(ctx,
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'secret.sync.ci'`, tenant).Scan(&raw); err != nil {
			t.Fatalf("read the retained secret-sync outbox row: %v", err)
		}
		var binding struct {
			Sealed []byte `json:"sealed"`
		}
		if err := json.Unmarshal(raw, &binding); err != nil {
			t.Fatal(err)
		}
		return binding.Sealed
	}
	before := outboxSealed()
	if !bytes.Equal(before, sealed) {
		t.Fatal("setup: the outbox row does not carry the event's sealed copy")
	}
	if err := projections.New(rig.s).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("control: rebuild before the %s: %v", mode, err)
	}
	rig.rewrap()
	after := outboxSealed()
	if err := rig.open(after, aad); err != nil {
		t.Fatalf("control: the retained outbox copy does not open after the %s: %v", mode, err)
	}
	t.Logf("%s: the retained outbox row's sealed copy changed=%t", mode, !bytes.Equal(before, after))
	projector := vh83RecoveryProjector(t, rig)
	if tamperAfterProof {
		changed := false
		projector = vh83RecoveryProjectorWithPairProbe(t, rig, func(probeCtx context.Context, tenantID string) error {
			if changed {
				return nil
			}
			changed = true
			_, err := rig.s.SystemPool().Exec(probeCtx,
				`UPDATE outbox SET last_error='proof-probe'
				 WHERE tenant_id=$1 AND idempotency_key=$2 AND destination='secret.sync.ci'`,
				tenantID, store.SecretSyncOutboxIdempotencyKey("ci", jobID))
			return err
		})
		err := projector.Rebuild(ctx, rig.log)
		if !changed || !errors.Is(err, store.ErrRecoveryPairProofMismatch) {
			t.Fatalf("changed outbox after preproof changed=%t err=%v, want exact proof refusal", changed, err)
		}
		var jobs int
		if err := rig.s.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM secret_sync_jobs WHERE tenant_id=$1 AND id=$2`, tenant, jobID).Scan(&jobs); err != nil || jobs != 1 {
			t.Fatalf("atomic rebuild rollback jobs=%d err=%v, want old job retained", jobs, err)
		}
		return
	}
	if err := projector.Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("PLAN-SIB-55 (%s): full rebuild stops at the retained secret-sync outbox: %v", mode, err)
	}
	t.Logf("%s: rebuild succeeded", mode)
}

func TestVH83PlanSib55SyncOutboxRebuildAfterAKeyDomainMigration(t *testing.T) {
	vh83SyncRebuild(t, "a7770000-0000-4000-8000-000000008301", "migrate", false)
}

func TestVH83PlanSib55SyncOutboxRebuildAfterADeploymentKEKRotation(t *testing.T) {
	vh83SyncRebuild(t, "a7770000-0000-4000-8000-000000008302", "rotate", false)
}

func TestVH83RetainedOutboxChangedAfterPreproofRollsBackRebuild(t *testing.T) {
	vh83SyncRebuild(t, "a7770000-0000-4000-8000-000000008304", "migrate", true)
}

// The recover site (application_secrets.go:357 -> store/secret_store.go:1244)
// under the deployment KEK rotation. Needs the CR-045 digest stand-in.
func TestVH83PlanSib55RecoverRebuildAfterADeploymentKEKRotation(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000008303"
	rig := newVH83Rig(t, tenant, "rotate")
	const name = "vh83/db/password"
	aad := []byte(tenant + "/secret-store/" + name)
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	appendMutation := func(id, typ string, m projections.ApplicationSecretMutation, digestSeed byte) {
		t.Helper()
		m.TenantEpoch, m.Name, m.Surface = epoch, name, "native"
		m.IdempotencyKeyDigest, m.RequestBinding, m.CommandEvidence = hex64(digestSeed), hex64(digestSeed+1), hex64(digestSeed+2)
		payload, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.log.Append(ctx, events.Event{
			ID: id, Type: typ, TenantID: tenant, Time: time.Now().UTC(),
			SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: payload,
		}); err != nil {
			t.Fatal(err)
		}
		if err := projections.New(rig.s).ProjectCatchUp(ctx, rig.log); err != nil {
			t.Fatalf("project %s (%s): %v", typ, m.Action, err)
		}
	}
	appendMutation("a7770000-0000-4000-8000-0000000083f1", projections.EventApplicationSecretCreated,
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: rig.seal("value-one", aad)}, '1')
	v1, err := rig.s.GetSecretVersionAt(ctx, tenant, name, time.Now().UTC())
	if err != nil || v1.Version != 1 {
		t.Fatalf("v1 = %+v err=%v", v1.Version, err)
	}
	time.Sleep(5 * time.Millisecond)
	appendMutation("a7770000-0000-4000-8000-0000000083f2", projections.EventApplicationSecretRotated,
		projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("value-two", aad)}, '4')
	appendMutation("a7770000-0000-4000-8000-0000000083f3", projections.EventApplicationSecretRecovered,
		projections.ApplicationSecretMutation{Action: "recover", ExpectedVersion: 2, ResultVersion: 3, Sealed: v1.Sealed,
			SourceVersion: 1, SourceWrittenAt: v1.WrittenAt.UTC()}, '7')
	if err := projections.New(rig.s).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("control: rebuild before the rotation (CR-045 stand-in applied): %v", err)
	}
	rig.rewrap()
	current, err := rig.s.GetSecret(ctx, tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.open(current.Sealed, aad); err != nil {
		t.Fatalf("control: the current version does not open after the rotation: %v", err)
	}
	if err := vh83RecoveryProjector(t, rig).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("PLAN-SIB-55 (rotate): full rebuild stops at the recover event even with CR-045's digest fixed: %v", err)
	}
	t.Logf("rotate: rebuild after the rotation re-applied the recover; current version %d", current.Version)
}
