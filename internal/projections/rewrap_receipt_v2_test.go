// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// The source event itself is fetched after the rewrite. Its v2 digest matches
// the retained receipt, while its v1 wrapper digest differs. A fresh current
// container must authenticate before replay can borrow that old receipt.
func TestApplicationSecretReceiptV2ReplayRequiresCurrentContainerAuthentication(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009431"
	const eventID = "a7770000-0000-4000-8000-000000009432"
	const name = "receipt/live-replay"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("live-value", []byte(tenant+"/secret-store/"+name))}, '1')
	rig.rewrap()
	current, found, err := rig.log.EventByID(ctx, eventID)
	if err != nil || !found {
		t.Fatalf("current event found=%t err=%v", found, err)
	}
	if err := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log)).Apply(ctx, current); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("replay without custody verifier=%v, want conflict", err)
	}
	withVerifier := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log), projections.WithApplicationSecretReceiptVerifier(
		func(verifyCtx context.Context, tenantID string, mutation projections.ApplicationSecretMutation) error {
			return tenantseal.AuthenticateApplicationSecretMutationContainers(verifyCtx, rig.access, tenantID, mutation)
		},
	))
	if err := withVerifier.Apply(ctx, current); err != nil {
		t.Fatalf("authenticated current replay: %v", err)
	}
	var currentMutation projections.ApplicationSecretMutation
	if err := json.Unmarshal(current.Data, &currentMutation); err != nil {
		t.Fatal(err)
	}
	beforeV2, err := projections.ApplicationSecretMutationSemanticDigestV2(current, currentMutation)
	if err != nil {
		t.Fatal(err)
	}
	currentMutation.Sealed[10] ^= 1 // domain header, outside the stable payload digest
	afterV2, err := projections.ApplicationSecretMutationSemanticDigestV2(current, currentMutation)
	if err != nil || beforeV2 != afterV2 {
		t.Fatalf("test setup changed stable payload digest: before=%s after=%s err=%v", beforeV2, afterV2, err)
	}
	tampered := current
	tampered.Data, err = json.Marshal(currentMutation)
	if err != nil {
		t.Fatal(err)
	}
	// CR-045: local tampering is refused at the earlier canonical-source guard;
	// a projector may authenticate only bytes fetched from current history.
	if err := withVerifier.Apply(ctx, tampered); !errors.Is(err, projections.ErrCanonicalEventRequired) {
		t.Fatalf("rewrap-shaped local event with unauthenticated container=%v, want canonical refusal", err)
	}
	withChangedReceipt := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log), projections.WithApplicationSecretReceiptVerifier(
		func(verifyCtx context.Context, tenantID string, mutation projections.ApplicationSecretMutation) error {
			if err := tenantseal.AuthenticateApplicationSecretMutationContainers(verifyCtx, rig.access, tenantID, mutation); err != nil {
				return err
			}
			_, err := rig.s.SystemPool().Exec(verifyCtx,
				`UPDATE application_secret_mutation_receipts
				    SET applied_at = applied_at + interval '1 second'
				  WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID)
			return err
		},
	))
	if err := withChangedReceipt.Apply(ctx, current); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("receipt changed between authentication and locked re-read=%v, want conflict", err)
	}
}

func TestRecoveryKeySnapshotComesFromHistoryWhenReadModelIsMissing(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009441"
	const eventID = "a7770000-0000-4000-8000-000000009442"
	const operation = "a7770000-0000-4000-8000-000000009443"
	const name = "receipt/recovery-domain"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("recovery-value", []byte(tenant+"/secret-store/"+name))}, '1')
	rig.rewrap()
	if err := projections.StageTenantKeyRecoveryHistory(ctx, rig.s, rig.log, operation); err != nil {
		t.Fatalf("derive recovery snapshots from pinned history: %v", err)
	}
	if _, err := rig.s.SystemPool().Exec(ctx, `DELETE FROM tenant_key_domains WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	reader, err := rig.s.NewTenantKeyRecoveryDomainStore(operation)
	if err != nil {
		t.Fatal(err)
	}
	recoveryAccess, err := tenantseal.NewAccess(reader, rig.deployment, rig.registry)
	if err != nil {
		t.Fatal(err)
	}
	current, found, err := rig.log.EventByID(ctx, eventID)
	if err != nil || !found {
		t.Fatalf("read rewritten event found=%t err=%v", found, err)
	}
	var mutation projections.ApplicationSecretMutation
	if err := json.Unmarshal(current.Data, &mutation); err != nil {
		t.Fatal(err)
	}
	if err := tenantseal.AuthenticateApplicationSecretMutationContainers(ctx, recoveryAccess, tenant, mutation); err != nil {
		t.Fatalf("event-derived recovery key failed to authenticate current container: %v", err)
	}
	// CR-045: raw full restore needs the same snapshot before the target log is
	// populated, using only the HMAC-verified source artifact.
	const artifactOperation = "a7770000-0000-4000-8000-000000009444"
	artifactKey := []byte("fixture-key-domain-artifact-hmac")
	var artifact bytes.Buffer
	if _, err := backup.WriteLogWithKey(ctx, rig.log, &artifact, artifactKey); err != nil {
		t.Fatal(err)
	}
	if err := backup.WithVerifiedHistoryReader(ctx, bytes.NewReader(artifact.Bytes()), artifactKey,
		func(source *backup.VerifiedHistoryReader) error {
			return projections.StageTenantKeyRecoveryArtifactHistory(ctx, rig.s, source, artifactOperation)
		}); err != nil {
		t.Fatalf("stage recovery snapshot from HMAC artifact: %v", err)
	}
	artifactDomain, err := rig.s.NewTenantKeyRecoveryDomainStore(artifactOperation)
	if err != nil {
		t.Fatal(err)
	}
	artifactAccess, err := tenantseal.NewAccess(artifactDomain, rig.deployment, rig.registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenantseal.AuthenticateApplicationSecretMutationContainers(ctx, artifactAccess, tenant, mutation); err != nil {
		t.Fatalf("HMAC-artifact recovery key failed to authenticate current container: %v", err)
	}
}

func TestApplicationSecretV2ReceiptBindsStableTopLevelAndEmbeddedPayload(t *testing.T) {
	keyA, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer keyA.Destroy()
	keyB, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer keyB.Destroy()
	const tenant = "a7770000-0000-4000-8000-000000009401"
	const job = "a7770000-0000-4000-8000-000000009402"
	secretAAD := []byte(tenant + "/secret-store/name")
	syncAAD := []byte(tenant + "/secret-sync/ci/" + job + "/VALUE")
	secretBefore, err := seal.Seal(keyA, []byte("value"), secretAAD)
	if err != nil {
		t.Fatal(err)
	}
	syncBefore, err := seal.Seal(keyA, []byte("value"), syncAAD)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "a7770000-0000-4000-8000-000000009403", TenantID: tenant,
		Type: projections.EventApplicationSecretRotated, Time: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion}
	payload := projections.ApplicationSecretMutation{
		TenantEpoch: "a7770000-0000-4000-8000-000000009404", Action: "rotate", Name: "name",
		ExpectedVersion: 1, ResultVersion: 2, Sealed: secretBefore,
		IdempotencyKeyDigest: hex64('1'), RequestBinding: hex64('2'), CommandEvidence: hex64('3'),
		Surface: "rotation", Sync: &projections.SecretSyncQueued{
			ID: job, SecretName: "name", SecretVersion: 2, Target: "ci", RemoteKey: "VALUE",
			ValueDigest: hex64('4'), IdempotencyKey: "sync-receipt", RequestBinding: hex64('2'), Sealed: syncBefore,
		},
	}
	v1Before, err := projections.ApplicationSecretMutationSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	v2Before, err := projections.ApplicationSecretMutationSemanticDigestV2(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	secretAfter, err := seal.RewrapDomain(keyA, keyB, secretBefore, []byte("domain-1"))
	if err != nil {
		t.Fatal(err)
	}
	syncAfter, err := seal.RewrapDomain(keyA, keyB, syncBefore, []byte("domain-1"))
	if err != nil {
		t.Fatal(err)
	}
	payload.Sealed = secretAfter
	syncCopy := *payload.Sync
	syncCopy.Sealed = syncAfter
	payload.Sync = &syncCopy
	v1After, err := projections.ApplicationSecretMutationSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	v2After, err := projections.ApplicationSecretMutationSemanticDigestV2(event, payload)
	if err != nil || v2Before != v2After || v1Before == v1After {
		t.Fatalf("rewrap digests: v1 before=%s after=%s v2 before=%s after=%s err=%v", v1Before, v1After, v2Before, v2After, err)
	}
	fresh, err := seal.SealDomain(keyB, []byte("value"), secretAAD, []byte("domain-1"))
	if err != nil {
		t.Fatal(err)
	}
	payload.Sealed = fresh
	if freshDigest, err := projections.ApplicationSecretMutationSemanticDigestV2(event, payload); err != nil || freshDigest == v2After {
		t.Fatalf("fresh re-encryption v2=%s err=%v, want changed digest", freshDigest, err)
	}
}

func TestMigrationBackfillsAuthenticatedV1OnlyReceiptBeforeHistoryRewrap(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009421"
	const eventID = "a7770000-0000-4000-8000-000000009422"
	const name = "receipt/legacy-backfill"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("legacy-value", []byte(tenant+"/secret-store/"+name))}, '1')
	var originalV1 string
	if err := rig.s.SystemPool().QueryRow(ctx,
		`SELECT semantic_sha256 FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND event_id=$2`,
		tenant, eventID).Scan(&originalV1); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.s.SystemPool().Exec(ctx,
		`UPDATE application_secret_mutation_receipts SET semantic_sha256_v2=NULL WHERE tenant_id=$1 AND event_id=$2`,
		tenant, eventID); err != nil {
		t.Fatal(err)
	}
	rig.rewrap()
	var v1, v2 string
	if err := rig.s.SystemPool().QueryRow(ctx,
		`SELECT semantic_sha256,coalesce(semantic_sha256_v2,'') FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND event_id=$2`,
		tenant, eventID).Scan(&v1, &v2); err != nil {
		t.Fatal(err)
	}
	if v1 != originalV1 || len(v2) != 64 {
		t.Fatalf("legacy receipt after migration v1=%q v2=%q, want original v1 and authenticated v2", v1, v2)
	}
	verifiedBeforeTruncate := 0
	if err := projections.New(rig.s, projections.WithApplicationSecretRecoveryVerifierFactory(
		func(operationID string) (func(context.Context, string, projections.ApplicationSecretMutation) error, error) {
			reader, err := rig.s.NewTenantKeyRecoveryDomainStore(operationID)
			if err != nil {
				return nil, err
			}
			recoveryAccess, err := tenantseal.NewAccess(reader, rig.deployment, rig.registry)
			if err != nil {
				return nil, err
			}
			return func(verifyCtx context.Context, tenantID string, mutation projections.ApplicationSecretMutation) error {
				probeCtx, cancel := context.WithTimeout(verifyCtx, 2*time.Second)
				defer cancel()
				var count int
				if err := rig.s.SystemPool().QueryRow(probeCtx,
					`SELECT count(*) FROM tenant_key_domains WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
					return err
				}
				if count != 1 {
					return errors.New("receipt verifier ran after key-domain read model was truncated")
				}
				verifiedBeforeTruncate++
				return tenantseal.AuthenticateApplicationSecretMutationContainers(verifyCtx, recoveryAccess, tenantID, mutation)
			}, nil
		},
	)).Rebuild(ctx, rig.log); err != nil {
		t.Fatalf("rebuild after authenticated receipt backfill: %v", err)
	}
	if verifiedBeforeTruncate == 0 {
		t.Fatal("rebuild did not authenticate the mismatching receipt before TRUNCATE")
	}
	var remainingProofs, remainingSnapshots int
	if err := rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.recovery_pair_proofs
		WHERE tenant_id=$1`, tenant).Scan(&remainingProofs); err != nil {
		t.Fatal(err)
	}
	if err := rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE tenant_id=$1`, tenant).Scan(&remainingSnapshots); err != nil {
		t.Fatal(err)
	}
	if remainingProofs != 0 || remainingSnapshots != 0 {
		t.Fatalf("successful atomic rebuild left recovery proof=%d snapshot=%d", remainingProofs, remainingSnapshots)
	}
}

func TestRecoveryReceiptProofRejectsRowChangeBeforeAtomicReplay(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009451"
	const eventID = "a7770000-0000-4000-8000-000000009452"
	const name = "receipt/changed-before-replay"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("stable-value", []byte(tenant+"/secret-store/"+name))}, '1')
	rig.rewrap()
	before, err := rig.s.GetSecret(ctx, tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	operationID := ""
	changed := false
	projector := projections.New(rig.s, projections.WithApplicationSecretRecoveryVerifierFactory(
		func(op string) (func(context.Context, string, projections.ApplicationSecretMutation) error, error) {
			operationID = op
			reader, err := rig.s.NewTenantKeyRecoveryDomainStore(op)
			if err != nil {
				return nil, err
			}
			recoveryAccess, err := tenantseal.NewAccess(reader, rig.deployment, rig.registry)
			if err != nil {
				return nil, err
			}
			return func(verifyCtx context.Context, tenantID string, mutation projections.ApplicationSecretMutation) error {
				if err := tenantseal.AuthenticateApplicationSecretMutationContainers(verifyCtx, recoveryAccess, tenantID, mutation); err != nil {
					return err
				}
				if !changed {
					changed = true
					_, err := rig.s.SystemPool().Exec(verifyCtx,
						`UPDATE application_secret_mutation_receipts
						 SET applied_at=applied_at + interval '1 second'
						 WHERE tenant_id=$1 AND event_id=$2`, tenantID, eventID)
					return err
				}
				return nil
			}, nil
		},
	))
	if err := projector.Rebuild(ctx, rig.log); !errors.Is(err, store.ErrRecoveryPairProofMismatch) {
		t.Fatalf("changed independent receipt accepted by atomic rebuild: %v", err)
	}
	if !changed || operationID == "" {
		t.Fatal("test did not change the receipt between preproof and replay")
	}
	after, err := rig.s.GetSecret(ctx, tenant, name)
	if err != nil || !bytes.Equal(before.Sealed, after.Sealed) {
		t.Fatalf("failed rebuild changed served secret: same=%t err=%v", bytes.Equal(before.Sealed, after.Sealed), err)
	}
	var remainingProofs, retainedSnapshots int
	if err := rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.recovery_pair_proofs
		WHERE tenant_id=$1 AND operation_id=$2`, tenant, operationID).Scan(&remainingProofs); err != nil {
		t.Fatal(err)
	}
	if err := rig.s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE tenant_id=$1 AND operation_id=$2`, tenant, operationID).Scan(&retainedSnapshots); err != nil {
		t.Fatal(err)
	}
	if remainingProofs != 0 || retainedSnapshots == 0 {
		t.Fatalf("failed rebuild proof=%d staged snapshots=%d, want rolled-back proof and retained diagnostic snapshot", remainingProofs, retainedSnapshots)
	}
}

func TestNewApplicationSecretMutationCommitsBothReceiptVersions(t *testing.T) {
	ctx := context.Background()
	const tenant = "a7770000-0000-4000-8000-000000009411"
	const eventID = "a7770000-0000-4000-8000-000000009412"
	const name = "receipt/new-mutation"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("secret-value", []byte(tenant+"/secret-store/"+name))}, '1')
	var event events.Event
	if err := rig.log.Replay(ctx, 0, func(candidate events.Event) error {
		if candidate.ID == eventID {
			event = candidate
		}
		return nil
	}); err != nil || event.ID == "" {
		t.Fatalf("read canonical mutation event=%s err=%v", event.ID, err)
	}
	var payload projections.ApplicationSecretMutation
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		t.Fatal(err)
	}
	wantV1, err := projections.ApplicationSecretMutationSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	wantV2, err := projections.ApplicationSecretMutationSemanticDigestV2(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	var v1, v2 string
	if err := rig.s.SystemPool().QueryRow(ctx,
		`SELECT semantic_sha256,coalesce(semantic_sha256_v2,'') FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND event_id=$2`,
		tenant, eventID).Scan(&v1, &v2); err != nil {
		t.Fatal(err)
	}
	if v1 != wantV1 || v2 != wantV2 {
		t.Fatalf("committed receipt v1=%q v2=%q, want v1=%q v2=%q", v1, v2, wantV1, wantV2)
	}
}
