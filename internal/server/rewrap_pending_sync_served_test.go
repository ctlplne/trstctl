// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// VH84-N1: a pending secret-sync intent is rewrapped in both the event log and
// retained outbox. The worker must still open the command and deliver it once.
func TestServedPendingSecretSyncDeliversAfterTenantDomainMigration(t *testing.T) {
	wrapperPath := filepath.Join(t.TempDir(), "sync-domain-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x69}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: "sync-domain-wrapper", Path: wrapperPath}})
	if err != nil {
		t.Fatal(err)
	}
	owned := newServerRewrapStore(t)
	rewriteKey, err := jose.GenerateRSASigningKey("pending-sync-history")
	if err != nil {
		t.Fatal(err)
	}
	pusher := &outboxSyncPusher{}
	var ingressAccess tenantseal.Access
	h := newServedHarnessWithOwnedStore(t, config.Protocols{}, []events.OpenOption{
		events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(owned)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(rewriteKey)),
		restoreEventIngressOptionWithCustody(owned, func() tenantseal.Access { return ingressAccess }),
	}, owned, withSecretsEnabled(t, nil), func(d *Deps) {
		access, accessErr := tenantseal.NewAccess(d.Store, d.KEK, registry)
		if accessErr != nil {
			t.Fatal(accessErr)
		}
		ingressAccess = access
		lifecycle, lifecycleErr := tenantseal.NewLifecycle(d.Store, d.Log, d.KEK, registry,
			historyRewriteProofOptions(owned, rewriteKey)...)
		if lifecycleErr != nil {
			t.Fatal(lifecycleErr)
		}
		protector, protectorErr := tenantseal.NewResultProtector(access)
		if protectorErr != nil {
			t.Fatal(protectorErr)
		}
		d.TenantCrypto = access
		d.TenantRecoveryAccessFactory = func(operationID string) (tenantseal.Access, error) {
			reader, err := d.Store.NewTenantKeyRecoveryDomainStore(operationID)
			if err != nil {
				return nil, err
			}
			return tenantseal.NewAccess(reader, d.KEK, registry)
		}
		d.TenantKeyDomains = lifecycle
		d.IdempotencyResultProtector = protector
		d.TenantSecretSyncTargets = SecretSyncTargetRegistry{servedTestTenant: {
			"durable-target": secretsync.NewTarget("durable-target", pusher),
		}}
	})
	registerServedTenant(t, h, "pending secret sync rewrap tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "keys:read", "keys:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": "sync/pending-rewrap", "value": "pending-value"})
	if status != http.StatusCreated {
		t.Fatalf("create source status=%d body=%s", status, body)
	}
	const rawKey = "pending-rewrap-sync"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", token, rawKey,
		map[string]any{"name": "sync/pending-rewrap", "target": "durable-target", "remote_key": "VALUE"})
	if status != http.StatusOK {
		t.Fatalf("queue sync status=%d body=%s", status, body)
	}
	jobID := currentSecretSyncJobIDForTest(t, h.store, h.tenant, rawKey)
	job, err := h.store.GetSecretSyncJob(t.Context(), h.tenant, jobID)
	if err != nil || job.Status != store.SecretSyncJobPending || len(pusher.values) != 0 {
		t.Fatalf("sync before migration job=%+v err=%v effects=%d", job, err, len(pusher.values))
	}
	// A producer may seal while the old wrapper is current, then pause before
	// Append. The common ingress must authenticate that candidate after taking
	// key-state A/B; a successful rewrap cannot publish this stale ciphertext.
	const staleJobID = "11111111-1111-4111-8111-111111111805"
	staleValue := []byte("stale-candidate-value")
	staleSealed, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, staleValue, secretSyncAAD(h.tenant, "durable-target", staleJobID, "STALE"))
	if err != nil {
		t.Fatal(err)
	}
	staleEpoch, err := h.store.ApplicationSecretTenantEpoch(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	const preparedID = "11111111-1111-4111-8111-111111111807"
	const issuedID = "11111111-1111-4111-8111-111111111808"
	stalePreparation, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("prepared-identity"), dynamicSecretPreparationAAD(h.tenant, preparedID, "stub"))
	if err != nil {
		t.Fatal(err)
	}
	staleCredential, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("issued-identity"), dynamicSecretCredentialAAD(h.tenant, issuedID, "stub"))
	if err != nil {
		t.Fatal(err)
	}
	const codeOperationID = "11111111-1111-4111-8111-111111111809"
	codeRequestHash := crypto.SHA256Hex([]byte("candidate-code-signing-request"))
	codeAAD := codeSigningCommandAAD(h.tenant, codeOperationID, "managed", codeRequestHash)
	staleCodeCommand, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-code-signing-command"), codeAAD)
	if err != nil {
		t.Fatal(err)
	}
	const staticCommandID = "11111111-1111-4111-8111-111111111810"
	staticParts := []struct {
		part   string
		sealed []byte
	}{{part: "prepared"}, {part: "new"}, {part: "old"}}
	for index := range staticParts {
		part := &staticParts[index]
		part.sealed, err = sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-static-"+part.part),
			[]byte(h.tenant+"/static-rotation/"+staticCommandID+"/"+part.part))
		if err != nil {
			t.Fatal(err)
		}
	}
	const slackTeamID = "T-INGRESS-REWRAP"
	staleSlackToken, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-slack-token"), slackBotTokenAAD(h.tenant, slackTeamID))
	if err != nil {
		t.Fatal(err)
	}
	const batchVersionName = "batch/ingress"
	batchVersionAAD := []byte(h.tenant + "/secret-store/" + batchVersionName)
	staleBatchVersion, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-batch-version"), batchVersionAAD)
	if err != nil {
		t.Fatal(err)
	}
	const batchImportName = "batch/imported-ingress"
	batchImportAAD := []byte(h.tenant + "/secret-store/" + batchImportName)
	staleBatchImport, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-batch-import"), batchImportAAD)
	if err != nil {
		t.Fatal(err)
	}
	const kmipObjectID = "kmip-902"
	kmipAAD := []byte("trstctl.kmip.state.v1|" + h.tenant + "|" + kmipObjectID + "|1")
	staleKMIPKey, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-kmip-key"), kmipAAD)
	if err != nil {
		t.Fatal(err)
	}
	const pqcRunID = "candidate-pqc-run"
	const pqcAssetID = "candidate-pqc-asset"
	const pqcTargetRevision = "candidate-pqc-revision"
	pqcAAD := []byte("pqc-tls-posture-outbox-v1\x00" + h.tenant +
		"\x00connector.licensed_crypto.migration.tls_posture\x00licensed-crypto-migration-tls:" +
		pqcRunID + ":" + pqcAssetID + "\x00" + pqcRunID + "\x00" + pqcAssetID +
		"\x00" + pqcTargetRevision)
	stalePQCOutbox, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-pqc-outbox"), pqcAAD)
	if err != nil {
		t.Fatal(err)
	}
	const secretVersionPath = "candidate/version-path"
	secretVersionAAD := []byte(h.tenant + "|" + secretVersionPath)
	staleSecretVersion, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-secret-version"), secretVersionAAD)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G101 -- this is a fixed non-secret idempotency marker in an isolated test
	stalePayload, err := json.Marshal(projections.SecretSyncQueued{
		TenantEpoch: staleEpoch, ID: staleJobID, SecretName: "sync/pending-rewrap", SecretVersion: 1,
		Target: "durable-target", RemoteKey: "STALE", ValueDigest: crypto.SHA256Hex(staleValue),
		IdempotencyKey: "stale-candidate-key", RequestBinding: "stale-candidate-request", Sealed: staleSealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate", token,
		"pending-rewrap-domain-migrate", map[string]any{"wrapper_kind": "local_file", "wrapper_id": "sync-domain-wrapper"})
	if status != http.StatusOK {
		t.Fatalf("migrate with pending sync status=%d body=%s", status, body)
	}
	if opened, err := openTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek, h.tenant,
		staleSealed, secretSyncAAD(h.tenant, "durable-target", staleJobID, "STALE")); err == nil {
		secret.Wipe(opened)
		t.Fatal("old sealed candidate still opens after completed tenant migration")
	}
	staleEventID := store.SecretSyncQueuedEventID(h.tenant, staleJobID)
	if _, err := h.log.Append(t.Context(), events.Event{
		ID: staleEventID, Type: projections.EventSecretSyncQueued, TenantID: h.tenant,
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: stalePayload,
	}); err == nil {
		t.Fatal("stale sealed secret-sync candidate appended after completed migration")
	}
	if _, found, err := h.log.EventByID(t.Context(), staleEventID); err != nil || found {
		t.Fatalf("stale candidate publication found=%t err=%v, want no NATS event", found, err)
	}
	var unresolvedIngress int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*)
		FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND activity_kind='ingress'
		AND lane='event-append' AND event_id=$2 AND phase='started'`, h.tenant, staleEventID).
		Scan(&unresolvedIngress); err != nil || unresolvedIngress != 0 {
		t.Fatalf("refused candidate left %d unresolved ingress tokens: %v", unresolvedIngress, err)
	}
	job, err = h.store.GetSecretSyncJob(t.Context(), h.tenant, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var rawOutbox []byte
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT payload FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, job.OutboxID).Scan(&rawOutbox); err != nil {
		t.Fatal(err)
	}
	var retained secretSyncOutboxPayload
	if err := json.Unmarshal(rawOutbox, &retained); err != nil {
		t.Fatal(err)
	}
	if err := validateProjectedSecretSyncSourceWithCustody(t.Context(), h.store, h.log, h.srv.tenantCrypto, job, retained); err != nil {
		t.Fatalf("rewrapped retained sync source refused before receiver I/O: %v", err)
	}
	freshCopy, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek, h.tenant,
		[]byte("pending-value"), secretSyncAAD(h.tenant, job.Target, job.ID, job.RemoteKey))
	if err != nil {
		t.Fatal(err)
	}
	changed := retained
	changed.Sealed = freshCopy
	if err := validateProjectedSecretSyncSourceWithCustody(t.Context(), h.store, h.log, h.srv.tenantCrypto, job, changed); err == nil {
		t.Fatal("fresh ciphertext with the same plaintext was accepted as a DEK-only rewrap")
	}
	job = drainSecretSyncUntil(t, h, jobID, store.SecretSyncJobDelivered, 3)
	if job.Status != store.SecretSyncJobDelivered || len(pusher.values) != 1 || !bytes.Equal(pusher.values[0], []byte("pending-value")) {
		t.Fatalf("pending sync after migration job=%+v effects=%d, want one exact delivery", job, len(pusher.values))
	}
	const afterKey = "post-rewrap-sync"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", token, afterKey,
		map[string]any{"name": "sync/pending-rewrap", "target": "durable-target", "remote_key": "AFTER"})
	if status != http.StatusOK {
		t.Fatalf("queue sync after migration status=%d body=%s", status, body)
	}
	afterID := currentSecretSyncJobIDForTest(t, h.store, h.tenant, afterKey)
	after := drainSecretSyncUntil(t, h, afterID, store.SecretSyncJobDelivered, 3)
	if after.Status != store.SecretSyncJobDelivered || len(pusher.values) != 2 || !bytes.Equal(pusher.values[1], []byte("pending-value")) {
		t.Fatalf("new sync after migration job=%+v effects=%d, want one exact delivery", after, len(pusher.values))
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("served projector cannot rebuild retained migrated secret and sync copies: %v", err)
	}
	// The operator recovery constructor must use the same configured wrapper
	// registry and event-derived snapshot resolver as the served projector.
	recoveryConfig := config.Default()
	recoveryConfig.Secrets.TenantSealLocalWrappers = []config.TenantSealLocalWrapper{{
		ID: "sync-domain-wrapper", File: wrapperPath,
	}}
	recoveryCore, err := newRunTenantCustodyCore(recoveryConfig, h.store, h.srv.kek, h.signer)
	if err != nil {
		t.Fatal(err)
	}
	recoveryOptions, err := recoveryProjectionOptionsWithCustody(t.Context(), recoveryConfig,
		h.store, h.log, testAuditSigningKey(t), recoveryCore, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store, recoveryOptions...).Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("configured recovery projector cannot rebuild retained migrated copies: %v", err)
	}
	for _, candidate := range []struct {
		name, eventType, id string
		stale               []byte
		payload             func([]byte) any
	}{
		{"prepared", projections.EventDynamicSecretLeasePrepared, preparedID, stalePreparation,
			func(sealed []byte) any {
				return projections.DynamicSecretLeasePrepared{
					TenantEpoch: staleEpoch, ID: preparedID, Provider: "stub", SealedPreparation: sealed,
				}
			}},
		{"issued", projections.EventDynamicSecretLeaseIssued, issuedID, staleCredential,
			func(sealed []byte) any {
				return projections.DynamicSecretLeaseIssued{
					TenantEpoch: staleEpoch, ID: issuedID, IdempotencyKey: "issued-ingress-key",
					RequestBinding: "issued-ingress-request", Provider: "stub", Role: "readonly",
					BackendRef: "local-ref", SealedCredential: sealed,
					ExpiresAt: time.Now().Add(time.Hour), HardExpiresAt: time.Now().Add(2 * time.Hour),
				}
			}},
	} {
		t.Run("dynamic-"+candidate.name, func(t *testing.T) {
			makeEvent := func(sealed []byte, suffix string) events.Event {
				t.Helper()
				data, err := json.Marshal(candidate.payload(sealed))
				if err != nil {
					t.Fatal(err)
				}
				return events.Event{ID: "dynamic-ingress-" + candidate.name + "-" + suffix,
					Type: candidate.eventType, TenantID: h.tenant,
					SchemaVersion: projections.DynamicSecretEventSchemaVersion, Data: data}
			}
			stale := makeEvent(candidate.stale, "stale")
			if _, err := h.log.Append(t.Context(), stale); err == nil {
				t.Error("stale dynamic-secret candidate appended after migration")
			}
			if _, found, err := h.log.EventByID(t.Context(), stale.ID); err != nil || found {
				t.Errorf("stale dynamic-secret event found=%t err=%v", found, err)
			}
			var aad []byte
			if candidate.name == "prepared" {
				aad = dynamicSecretPreparationAAD(h.tenant, candidate.id, "stub")
			} else {
				aad = dynamicSecretCredentialAAD(h.tenant, candidate.id, "stub")
			}
			freshSealed, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
				h.tenant, []byte(candidate.name+"-identity"), aad)
			if err != nil {
				t.Fatal(err)
			}
			fresh := makeEvent(freshSealed, "fresh")
			if _, err := h.log.Append(t.Context(), fresh); err != nil {
				t.Errorf("current dynamic-secret candidate rejected: %v", err)
			}
		})
	}
	codeEvent := func(sealed []byte, suffix string) events.Event {
		t.Helper()
		data, err := json.Marshal(projections.CodeSigningCommanded{
			OperationID: codeOperationID, IdempotencyKeyRef: "code-signing-reference",
			RequestBinding: "code-signing-binding", Mode: "managed",
			RequestHash: codeRequestHash, SealedCommand: sealed,
		})
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{ID: "code-signing-ingress-" + suffix,
			Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
			SchemaVersion: projections.CodeSigningPrivacySafeEventSchemaVersion, Data: data}
	}
	staleCode := codeEvent(staleCodeCommand, "stale")
	if _, err := h.log.Append(t.Context(), staleCode); err == nil {
		t.Error("stale code-signing command appended after migration")
	}
	if _, found, err := h.log.EventByID(t.Context(), staleCode.ID); err != nil || found {
		t.Errorf("stale code-signing command found=%t err=%v", found, err)
	}
	freshCodeCommand, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-code-signing-command"), codeAAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), codeEvent(freshCodeCommand, "fresh")); err != nil {
		t.Errorf("current code-signing command rejected: %v", err)
	}
	for _, part := range staticParts {
		t.Run("static-"+part.part, func(t *testing.T) {
			makeEvent := func(sealed []byte, suffix string) events.Event {
				t.Helper()
				payload := projections.SecretStaticRotationAdvanced{
					ID: staticCommandID, TenantEpoch: staleEpoch, FromPhase: "queued", Phase: "staged",
				}
				switch part.part {
				case "prepared":
					payload.SealedPreparation = sealed
				case "new":
					payload.SealedNew = sealed
				case "old":
					payload.SealedOld = sealed
				}
				data, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				return events.Event{ID: "static-ingress-" + part.part + "-" + suffix,
					Type: projections.EventSecretStaticRotationAdvanced, TenantID: h.tenant,
					SchemaVersion: 2, Data: data}
			}
			stale := makeEvent(part.sealed, "stale")
			if _, err := h.log.Append(t.Context(), stale); err == nil {
				t.Error("stale static-rotation candidate appended after migration")
			}
			if _, found, err := h.log.EventByID(t.Context(), stale.ID); err != nil || found {
				t.Errorf("stale static-rotation event found=%t err=%v", found, err)
			}
			freshSealed, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
				h.tenant, []byte("candidate-static-"+part.part),
				[]byte(h.tenant+"/static-rotation/"+staticCommandID+"/"+part.part))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.log.Append(t.Context(), makeEvent(freshSealed, "fresh")); err != nil {
				t.Errorf("current static-rotation candidate rejected: %v", err)
			}
		})
	}
	slackEvent := func(sealed []byte, suffix string) events.Event {
		t.Helper()
		data, err := json.Marshal(projections.SlackInstalled{
			TeamID: slackTeamID, TeamName: "Ingress Test", BotUserID: "U-INGRESS",
			AppID: "A-INGRESS", SealedBotToken: sealed, InstalledBy: "test-admin",
		})
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{ID: "slack-ingress-" + suffix, Type: projections.EventSlackInstalled,
			TenantID: h.tenant, SchemaVersion: 1, Data: data}
	}
	staleSlack := slackEvent(staleSlackToken, "stale")
	if _, err := h.log.Append(t.Context(), staleSlack); err == nil {
		t.Error("stale Slack token appended after migration")
	}
	if _, found, err := h.log.EventByID(t.Context(), staleSlack.ID); err != nil || found {
		t.Errorf("stale Slack install event found=%t err=%v", found, err)
	}
	freshSlackToken, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-slack-token"), slackBotTokenAAD(h.tenant, slackTeamID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), slackEvent(freshSlackToken, "fresh")); err != nil {
		t.Errorf("current Slack install candidate rejected: %v", err)
	}
	batchEvent := func(sealed []byte, suffix string) events.Event {
		t.Helper()
		data, err := json.Marshal(projections.ApplicationSecretBatchVersion{
			TenantEpoch: staleEpoch, IdempotencyKeyDigest: crypto.SHA256Hex([]byte("batch-key")),
			RequestBinding: "batch-request-binding", CommandEvidence: "batch-command-evidence",
			Surface: "secret-store", Operation: "promote", PlanDigest: crypto.SHA256Hex([]byte("batch-plan")),
			Items: []projections.ApplicationSecretBatchVersionItem{{
				Name: batchVersionName, ExpectedVersion: 0, ResultVersion: 1,
				Sealed: sealed, SourceName: "source/batch", SourceVersion: 1,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{ID: "batch-version-ingress-" + suffix,
			Type: projections.EventApplicationSecretBatchVersioned, TenantID: h.tenant,
			SchemaVersion: projections.ApplicationSecretBatchVersionSchemaVersion, Data: data}
	}
	staleBatch := batchEvent(staleBatchVersion, "stale")
	if _, err := h.log.Append(t.Context(), staleBatch); err == nil {
		t.Error("stale batch-version event appended after migration")
	}
	if _, found, err := h.log.EventByID(t.Context(), staleBatch.ID); err != nil || found {
		t.Errorf("stale batch-version event found=%t err=%v", found, err)
	}
	freshBatchVersion, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
		h.tenant, []byte("candidate-batch-version"), batchVersionAAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), batchEvent(freshBatchVersion, "fresh")); err != nil {
		t.Errorf("current batch-version candidate rejected: %v", err)
	}
	for _, schema := range []int{projections.ApplicationSecretBatchImportSchemaVersion,
		projections.ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion} {
		t.Run("batch-import-schema-"+strconv.Itoa(schema), func(t *testing.T) {
			makeEvent := func(sealed []byte, suffix string) events.Event {
				t.Helper()
				batch := projections.ApplicationSecretBatchImport{
					TenantEpoch: staleEpoch, IdempotencyKeyDigest: crypto.SHA256Hex([]byte("import-key")),
					RequestBinding: "import-request", CommandEvidence: "import-command",
					Surface: "secret-store", Items: []projections.ApplicationSecretBatchImportItem{
						{Name: batchImportName, Sealed: sealed},
					},
				}
				var payload any = batch
				if schema == projections.ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion {
					payload = projections.ApplicationSecretBatchImportPrivacyPruned{
						ApplicationSecretBatchImport: batch, PrivacyDisposition: "pruned",
						PrivacySubjectRef: "subject-reference", PrivacySourceSchemaVersion: 1,
						PrivacyRemovedCount: 1,
					}
				}
				data, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				return events.Event{ID: "batch-import-ingress-" + strconv.Itoa(schema) + "-" + suffix,
					Type: projections.EventApplicationSecretBatchImported, TenantID: h.tenant,
					SchemaVersion: schema, Data: data}
			}
			stale := makeEvent(staleBatchImport, "stale")
			if _, err := h.log.Append(t.Context(), stale); err == nil {
				t.Error("stale batch-import candidate appended after migration")
			}
			if _, found, err := h.log.EventByID(t.Context(), stale.ID); err != nil || found {
				t.Errorf("stale batch-import event found=%t err=%v", found, err)
			}
			freshSealed, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
				h.tenant, []byte("candidate-batch-import"), batchImportAAD)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.log.Append(t.Context(), makeEvent(freshSealed, "fresh")); err != nil {
				t.Errorf("current batch-import candidate rejected: %v", err)
			}
		})
	}
	for _, eventType := range []string{
		"kmip.state.object.created", "kmip.state.object.registered", "kmip.state.object.rekeyed",
	} {
		t.Run("kmip-"+eventType, func(t *testing.T) {
			makeEvent := func(sealed []byte) events.Event {
				t.Helper()
				data, err := json.Marshal(map[string]any{
					"id": kmipObjectID, "algorithm": "AES", "state": "active", "version": 1,
					"sealed_key": sealed,
				})
				if err != nil {
					t.Fatal(err)
				}
				return events.Event{Type: eventType, TenantID: h.tenant, SchemaVersion: 1, Data: data}
			}
			if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
				makeEvent(staleKMIPKey)); err == nil {
				t.Error("old KMIP key passed current tenant custody")
			}
			fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
				h.tenant, []byte("candidate-kmip-key"), kmipAAD)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
				makeEvent(fresh)); err != nil {
				t.Errorf("fresh KMIP key refused: %v", err)
			}
		})
	}
	t.Run("privacy-sync-erased-local-value", func(t *testing.T) {
		makeEvent := func(sealed []byte) events.Event {
			t.Helper()
			data, err := json.Marshal(projections.ApplicationSecretPrivacySyncErased{
				ApplicationSecretMutation: projections.ApplicationSecretMutation{
					Action: "create", Name: batchImportName, Sealed: sealed,
				},
				PrivacyDisposition:         events.ApplicationSecretPrivacyDispositionSyncErased,
				PrivacySubjectRef:          crypto.SHA256Hex([]byte("subject-reference")),
				PrivacySourceSchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
				PrivacySyncAuthorityErased: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			return events.Event{Type: projections.EventApplicationSecretCreated, TenantID: h.tenant,
				SchemaVersion: projections.ApplicationSecretPrivacyDispositionSchemaVersion, Data: data}
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(staleBatchImport)); err == nil {
			t.Error("old local privacy-disposition value passed current tenant custody")
		}
		fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-batch-import"), batchImportAAD)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(fresh)); err != nil {
			t.Errorf("fresh local privacy-disposition value refused: %v", err)
		}
	})
	t.Run("pqc-migration-sealed-outbox", func(t *testing.T) {
		makeEvent := func(sealed []byte) events.Event {
			t.Helper()
			wrapped, err := json.Marshal(map[string]any{
				"format": "trstctl.pqc-tls-posture.sealed", "version": 1,
				"run_id": pqcRunID, "asset_id": pqcAssetID,
				"target_revision": pqcTargetRevision, "sealed": sealed,
			})
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(projections.LicensedCryptoMigrationStarted{
				RunID: pqcRunID, TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{{
					RunID: pqcRunID, AssetID: pqcAssetID, TargetRevision: pqcTargetRevision,
					SealedOutboxPayload: wrapped,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			return events.Event{Type: projections.EventLicensedCryptoMigrationStarted,
				TenantID: h.tenant, SchemaVersion: 1, Data: data}
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(stalePQCOutbox)); err == nil {
			t.Error("old PQC outbox payload passed current tenant custody")
		}
		fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-pqc-outbox"), pqcAAD)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(fresh)); err != nil {
			t.Errorf("fresh PQC outbox payload refused: %v", err)
		}
	})
	t.Run("secret-version-path-aad", func(t *testing.T) {
		makeEvent := func(sealed []byte) events.Event {
			t.Helper()
			data, err := json.Marshal(map[string]any{
				"path": secretVersionPath, "version": 1, "sealed": sealed,
			})
			if err != nil {
				t.Fatal(err)
			}
			return events.Event{Type: "secret.version.written", TenantID: h.tenant,
				SchemaVersion: 1, Data: data}
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(staleSecretVersion)); err == nil {
			t.Error("old secret version value passed current tenant custody")
		}
		fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-secret-version"), secretVersionAAD)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(fresh)); err != nil {
			t.Errorf("fresh secret version value refused: %v", err)
		}
	})
	t.Run("secret-version-audit-name-aad", func(t *testing.T) {
		makeEvent := func(sealed []byte) events.Event {
			t.Helper()
			data, err := json.Marshal(map[string]any{
				"name": batchImportName, "version": 1, "sealed": sealed,
				"written_at": time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			return events.Event{Type: "secret.version.written", TenantID: h.tenant,
				SchemaVersion: 1, Data: data}
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(staleBatchImport)); err == nil {
			t.Error("old served audit version passed current tenant custody")
		}
		fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-batch-import"), batchImportAAD)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(fresh)); err != nil {
			t.Errorf("fresh served audit version refused: %v", err)
		}
	})
	t.Run("static-hosted-stage", func(t *testing.T) {
		makeEvent := func(sealed []byte) events.Event {
			t.Helper()
			data, err := json.Marshal(projections.SecretStaticRotationHostedStaged{
				ID: staticCommandID, TenantEpoch: staleEpoch,
				FromPhase: store.SecretStaticRotationQueued, Phase: store.SecretStaticRotationStaged,
				ProviderType: "vault", NewRef: "plain-reference", SealedNew: sealed,
			})
			if err != nil {
				t.Fatal(err)
			}
			return events.Event{Type: projections.EventSecretStaticRotationAdvanced,
				TenantID: h.tenant, SchemaVersion: projections.SecretStaticRotationHostedStageSchemaVersion,
				Data: data}
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(staticParts[1].sealed)); err == nil {
			t.Error("old hosted static stage passed current tenant custody")
		}
		fresh, err := sealTenantValue(t.Context(), h.srv.tenantCrypto, h.srv.kek,
			h.tenant, []byte("candidate-static-new"),
			[]byte(h.tenant+"/static-rotation/"+staticCommandID+"/new"))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSealedIngressCandidate(t.Context(), h.srv.tenantCrypto,
			makeEvent(fresh)); err != nil {
			t.Errorf("fresh hosted static stage refused: %v", err)
		}
	})
	currentSync, found, err := h.log.EventByID(t.Context(), store.SecretSyncQueuedEventID(h.tenant, jobID))
	if err != nil || !found {
		t.Fatalf("current pending sync event found=%t err=%v", found, err)
	}
	if err := projections.New(h.store).ApplyEventProjections(t.Context(), currentSync); err != nil {
		t.Fatalf("served direct attached projector lacks canonical source after rewrap: %v", err)
	}
}
