// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

func appendUnprojectedSecretMutation(t *testing.T, rig vh83Rig, tenant, epoch, id, eventType string, mutation projections.ApplicationSecretMutation) {
	t.Helper()
	mutation.TenantEpoch = epoch
	mutation.Surface = "native"
	mutation.IdempotencyKeyDigest = hex64('c')
	mutation.RequestBinding = hex64('d')
	mutation.CommandEvidence = hex64('e')
	data, err := json.Marshal(mutation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.log.Append(context.Background(), events.Event{
		ID: id, Type: eventType, TenantID: tenant, Time: time.Now().UTC(),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
}

func rewrappedEventByID(t *testing.T, rig vh83Rig, id string) events.Event {
	t.Helper()
	var found events.Event
	if err := rig.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == id {
			found = event
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if found.ID == "" {
		t.Fatalf("rewrapped history has no event %s", id)
	}
	return found
}

func rewrapPairOption(rig vh83Rig) projections.Option {
	return projections.WithRewrapPairVerifier(func(ctx context.Context, tenant string, before, after, aad []byte) (bool, error) {
		return tenantseal.VerifyRewrapPair(ctx, rig.access, tenant, before, after, aad)
	})
}

// The recover event is retained in history before the rewrap, but its first
// projection runs afterward. The history and source-version copies get distinct
// wrapper nonces; matching authenticated payload bytes must still be accepted.
func TestRewrapUnprojectedRecoveryAcceptsMatchingSourceVersion(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009201"
	const name = "rewrap/recover-source"
	const recoverID = "a7770000-0000-4000-8000-000000009204"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(tenant + "/secret-store/" + name)
	v1Sealed := rig.seal("first-value", aad)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009202", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: v1Sealed}, '1')
	source, err := rig.s.GetSecretVersion(ctx, tenant, name, 1)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009203", projections.EventApplicationSecretRotated, "native",
		projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("second-value", aad)}, '4')
	appendUnprojectedSecretMutation(t, rig, tenant, epoch, recoverID, projections.EventApplicationSecretRecovered,
		projections.ApplicationSecretMutation{Action: "recover", Name: name, ExpectedVersion: 2, ResultVersion: 3,
			Sealed: source.Sealed, SourceVersion: 1, SourceWrittenAt: source.WrittenAt})
	rig.rewrap()
	event := rewrappedEventByID(t, rig, recoverID)
	if err := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log), rewrapPairOption(rig)).Apply(ctx, event); err != nil {
		if errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("rewrapped recover/source pair was refused by raw byte comparison: %v", err)
		}
		t.Fatalf("project rewrapped recover event: %v", err)
	}
	current, err := rig.s.GetSecret(ctx, tenant, name)
	if err != nil || current.Version != 3 {
		t.Fatalf("recovered secret version=%d err=%v, want 3", current.Version, err)
	}
}

// A tombstone version is an independent retained copy. Undelete must accept the
// same authenticated payload after each copy is rewrapped independently.
func TestRewrapUnprojectedUndeleteAcceptsMatchingTombstone(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009211"
	const name = "rewrap/undelete-source"
	const undeleteID = "a7770000-0000-4000-8000-000000009214"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(tenant + "/secret-store/" + name)
	v1Sealed := rig.seal("first-value", aad)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009212", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: v1Sealed}, '1')
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009213", projections.EventApplicationSecretDeleted, "native",
		projections.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1}, '4')
	var deletedAt time.Time
	if err := rig.s.SystemPool().QueryRow(ctx,
		`SELECT deleted_at FROM secret_store_tombstones WHERE tenant_id=$1 AND name=$2`, tenant, name).Scan(&deletedAt); err != nil {
		t.Fatal(err)
	}
	appendUnprojectedSecretMutation(t, rig, tenant, epoch, undeleteID, projections.EventApplicationSecretUndeleted,
		projections.ApplicationSecretMutation{Action: "undelete", Name: name, ExpectedVersion: 1, ResultVersion: 1,
			Sealed: v1Sealed, SourceVersion: 1, SourceWrittenAt: deletedAt})
	rig.rewrap()
	event := rewrappedEventByID(t, rig, undeleteID)
	if err := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log), rewrapPairOption(rig)).Apply(ctx, event); err != nil {
		if errors.Is(err, store.ErrApprovalDrifted) {
			t.Fatalf("rewrapped undelete/tombstone pair was refused by raw byte comparison: %v", err)
		}
		t.Fatalf("project rewrapped undelete event: %v", err)
	}
	current, err := rig.s.GetSecret(ctx, tenant, name)
	if err != nil || current.Version != 1 {
		t.Fatalf("undeleted secret version=%d err=%v, want 1", current.Version, err)
	}
}

func testUnprojectedSourceRebuildPreproof(t *testing.T, action string, freshTarget, tamperAfterProof bool) {
	t.Helper()
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009221"
	const name = "rewrap/source-preproof"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(tenant + "/secret-store/" + name)
	first := rig.seal("first-value", aad)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009222", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: first}, '1')
	var eventID, eventType string
	var mutation projections.ApplicationSecretMutation
	if action == "recover" {
		source, err := rig.s.GetSecretVersion(ctx, tenant, name, 1)
		if err != nil {
			t.Fatal(err)
		}
		vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009223", projections.EventApplicationSecretRotated, "native",
			projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("second-value", aad)}, '4')
		eventID, eventType = "a7770000-0000-4000-8000-000000009224", projections.EventApplicationSecretRecovered
		mutation = projections.ApplicationSecretMutation{Action: action, Name: name, ExpectedVersion: 2, ResultVersion: 3,
			Sealed: source.Sealed, SourceVersion: 1, SourceWrittenAt: source.WrittenAt}
	} else {
		vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009225", projections.EventApplicationSecretDeleted, "native",
			projections.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1}, '4')
		var deletedAt time.Time
		if err := rig.s.SystemPool().QueryRow(ctx, `SELECT deleted_at FROM secret_store_tombstones WHERE tenant_id=$1 AND name=$2`,
			tenant, name).Scan(&deletedAt); err != nil {
			t.Fatal(err)
		}
		eventID, eventType = "a7770000-0000-4000-8000-000000009226", projections.EventApplicationSecretUndeleted
		mutation = projections.ApplicationSecretMutation{Action: action, Name: name, ExpectedVersion: 1, ResultVersion: 1,
			Sealed: first, SourceVersion: 1, SourceWrittenAt: deletedAt}
	}
	appendUnprojectedSecretMutation(t, rig, tenant, epoch, eventID, eventType, mutation)
	rig.rewrap()
	if freshTarget {
		for _, table := range []string{"application_secret_mutation_receipts", "secret_store_versions",
			"secret_store", "secret_store_tombstone_versions", "secret_store_tombstones"} {
			if _, err := rig.s.SystemPool().Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1`, tenant); err != nil {
				t.Fatalf("clear %s for fresh target: %v", table, err)
			}
		}
	}
	pretruncate := 0
	changed := false
	probe := func(verifyCtx context.Context, tenantID string) error {
		probeCtx, cancel := context.WithTimeout(verifyCtx, 2*time.Second)
		defer cancel()
		var count int
		if err := rig.s.SystemPool().QueryRow(probeCtx,
			`SELECT count(*) FROM tenant_key_domains WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("source pair verifier ran after the old key-domain model was truncated")
		}
		pretruncate++
		if tamperAfterProof && !changed {
			changed = true
			query := `UPDATE secret_store_versions SET recovered_from_version=1
				WHERE tenant_id=$1 AND name=$2 AND version=1`
			if action == "undelete" {
				query = `UPDATE secret_store_tombstones SET created_at=created_at + interval '1 second'
					WHERE tenant_id=$1 AND name=$2`
			}
			_, err := rig.s.SystemPool().Exec(verifyCtx, query, tenantID, name)
			return err
		}
		return nil
	}
	err = vh83RecoveryProjectorWithPairProbe(t, rig, probe).Rebuild(ctx, rig.log)
	if tamperAfterProof {
		if !changed || !errors.Is(err, store.ErrRecoveryPairProofMismatch) {
			t.Fatalf("%s changed source after proof changed=%t err=%v, want exact proof refusal", action, changed, err)
		}
		if action == "recover" {
			current, readErr := rig.s.GetSecret(ctx, tenant, name)
			if readErr != nil || current.Version != 2 {
				t.Fatalf("recover rollback current version=%d err=%v, want old version 2", current.Version, readErr)
			}
		} else {
			var tombstones int
			readErr := rig.s.SystemPool().QueryRow(ctx,
				`SELECT count(*) FROM secret_store_tombstones WHERE tenant_id=$1 AND name=$2`, tenant, name).Scan(&tombstones)
			if readErr != nil || tombstones != 1 {
				t.Fatalf("undelete rollback tombstones=%d err=%v, want prior tombstone", tombstones, readErr)
			}
		}
		return
	}
	if err != nil {
		t.Fatalf("%s rebuild pair preproof: %v", action, err)
	}
	if pretruncate == 0 {
		t.Fatalf("%s rebuild never authenticated the differing source pair", action)
	}
}

func TestRewrapUnprojectedRecoveryRebuildPreproof(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "recover", false, false)
}

func TestRewrapUnprojectedUndeleteRebuildPreproof(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "undelete", false, false)
}

func TestRewrapFreshTargetRecoverySourceBuiltFromHistoryPreproof(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "recover", true, false)
}

func TestRewrapFreshTargetUndeleteTombstoneBuiltFromHistoryPreproof(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "undelete", true, false)
}

func TestRewrapRecoverySourceChangedAfterProofRollsBackRebuild(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "recover", false, true)
}

func TestRewrapUndeleteTombstoneChangedAfterProofRollsBackRebuild(t *testing.T) {
	testUnprojectedSourceRebuildPreproof(t, "undelete", false, true)
}

func testSourcePairRejectsFreshEncryption(t *testing.T, action string) {
	t.Helper()
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009231"
	const name = "rewrap/source-fresh-payload"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(tenant + "/secret-store/" + name)
	vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009232", projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1, Sealed: rig.seal("same-value", aad)}, '1')
	var id, typ string
	var mutation projections.ApplicationSecretMutation
	if action == "recover" {
		source, err := rig.s.GetSecretVersion(ctx, tenant, name, 1)
		if err != nil {
			t.Fatal(err)
		}
		vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009233", projections.EventApplicationSecretRotated, "native",
			projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2, Sealed: rig.seal("other-value", aad)}, '4')
		id, typ = "a7770000-0000-4000-8000-000000009234", projections.EventApplicationSecretRecovered
		mutation = projections.ApplicationSecretMutation{Action: action, Name: name, ExpectedVersion: 2, ResultVersion: 3,
			SourceVersion: 1, SourceWrittenAt: source.WrittenAt}
	} else {
		vh84Append(t, rig, tenant, epoch, name, "a7770000-0000-4000-8000-000000009235", projections.EventApplicationSecretDeleted, "native",
			projections.ApplicationSecretMutation{Action: "delete", ExpectedVersion: 1}, '4')
		var deletedAt time.Time
		if err := rig.s.SystemPool().QueryRow(ctx, `SELECT deleted_at FROM secret_store_tombstones WHERE tenant_id=$1 AND name=$2`,
			tenant, name).Scan(&deletedAt); err != nil {
			t.Fatal(err)
		}
		id, typ = "a7770000-0000-4000-8000-000000009236", projections.EventApplicationSecretUndeleted
		mutation = projections.ApplicationSecretMutation{Action: action, Name: name, ExpectedVersion: 1, ResultVersion: 1,
			SourceVersion: 1, SourceWrittenAt: deletedAt}
	}
	mutation.Sealed = rig.seal("same-value", aad) // same plaintext, fresh nonce/ciphertext
	appendUnprojectedSecretMutation(t, rig, tenant, epoch, id, typ, mutation)
	event := rewrappedEventByID(t, rig, id)
	if err := projections.New(rig.s, rewrapPairOption(rig)).Apply(ctx, event); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("%s fresh encryption = %v, want source drift", action, err)
	}
}

func TestRecoverSourcePairRejectsFreshPayloadEncryption(t *testing.T) {
	testSourcePairRejectsFreshEncryption(t, "recover")
}

func TestUndeleteTombstonePairRejectsFreshPayloadEncryption(t *testing.T) {
	testSourcePairRejectsFreshEncryption(t, "undelete")
}
