// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	sealedTestTenant   = "tenant-a"
	sealedTestRun      = "run-a"
	sealedTestAsset    = "asset-a"
	sealedTestRevision = "revision-a"
	sealedTestKey      = "licensed-crypto-migration-tls:run-a:asset-a"
)

func testIntegrityKey(t *testing.T) *seal.LocalKEK {
	t.Helper()
	key, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func testTLSIntent() pqcMigrationTLSPosturePayload {
	return pqcMigrationTLSPosturePayload{
		RunID: sealedTestRun, AssetID: sealedTestAsset, Kind: "tls-endpoint", FindingKind: "protocol",
		Location: "edge.internal:443", AssetProtocol: "TLSv1.0", Strength: "broken",
		QuantumVulnerable: true, OutOfPolicy: true, TargetID: "target-a",
		TargetRevision: sealedTestRevision, Connector: "envoy", Target: "edge-listener",
		TargetConfig: json.RawMessage(`{"endpoint":"https://envoy.test","redirect_marker":"must-not-leak"}`),
		Desired: connector.TLSPosture{
			MinimumVersion:    connector.TLSVersion13,
			CipherSuites:      []string{"TLS_AES_256_GCM_SHA384"},
			KeyExchangeGroups: []string{HybridTLSGroup, "X25519"},
		},
	}
}

func TestTLSPostureExternalEffectsUseConnectorBulkheadDestinations(t *testing.T) {
	for _, destination := range []string{
		licensedCryptoMigrationTLSPostureDestination,
		licensedCryptoMigrationTLSRollbackDestination,
	} {
		if !strings.HasPrefix(destination, "connector.") {
			t.Fatalf("TLS posture destination %q bypasses the connector outbox bulkhead", destination)
		}
	}
}

func sealTestIntent(t *testing.T, key seal.KeyWrapper, intent pqcMigrationTLSPosturePayload) []byte {
	t.Helper()
	encoded, err := sealTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey,
		intent.RunID, intent.AssetID, intent.TargetRevision, intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTLSPostureOutboxSealRejectsTamperAndAADSubstitution(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	encoded := sealTestIntent(t, key, intent)
	if bytes.Contains(encoded, []byte("must-not-leak")) || bytes.Contains(encoded, []byte("envoy.test")) {
		t.Fatalf("sealed outbox leaked redirect-capable target config: %s", encoded)
	}

	var opened pqcMigrationTLSPosturePayload
	wrapper, err := openTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey, encoded, &opened,
	)
	if err != nil {
		t.Fatalf("open correct context: %v", err)
	}
	if wrapper.RunID != intent.RunID || wrapper.AssetID != intent.AssetID ||
		wrapper.TargetRevision != intent.TargetRevision || opened.TargetID != intent.TargetID ||
		!connector.EqualTLSPosture(opened.Desired, intent.Desired) {
		t.Fatalf("opened intent lost bound metadata: wrapper=%+v intent=%+v", wrapper, opened)
	}

	for name, contextFields := range map[string][3]string{
		"cross-tenant": {"tenant-b", licensedCryptoMigrationTLSPostureDestination, sealedTestKey},
		"destination":  {sealedTestTenant, licensedCryptoMigrationTLSRollbackDestination, sealedTestKey},
		"idempotency":  {sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey + "-other"},
	} {
		t.Run(name, func(t *testing.T) {
			var got pqcMigrationTLSPosturePayload
			_, err := openTLSPostureOutbox(key, contextFields[0], contextFields[1], contextFields[2], encoded, &got)
			if err == nil {
				t.Fatal("sealed intent opened after AAD substitution")
			}
			if strings.Contains(err.Error(), "must-not-leak") || strings.Contains(err.Error(), "envoy.test") {
				t.Fatalf("open error leaked target config: %v", err)
			}
		})
	}

	var tampered sealedTLSPostureOutbox
	if err := json.Unmarshal(encoded, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Sealed[len(tampered.Sealed)-1] ^= 0x80
	tamperedBytes, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openTLSPostureOutbox(key, sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey, tamperedBytes, &opened); err == nil {
		t.Fatal("tampered ciphertext opened")
	}

	for name, mutate := range map[string]func(*sealedTLSPostureOutbox){
		"run":      func(w *sealedTLSPostureOutbox) { w.RunID = "run-b" },
		"asset":    func(w *sealedTLSPostureOutbox) { w.AssetID = "asset-b" },
		"revision": func(w *sealedTLSPostureOutbox) { w.TargetRevision = "revision-b" },
	} {
		t.Run("outer-"+name, func(t *testing.T) {
			var changed sealedTLSPostureOutbox
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			changedBytes, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := openTLSPostureOutbox(key, sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey, changedBytes, &opened); err == nil {
				t.Fatalf("sealed intent opened after %s substitution", name)
			}
		})
	}
}

func TestStartedEventOwnsByteEquivalentSealedReplayIntent(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	sealedPayload := sealTestIntent(t, key, intent)
	intent.TargetConfig = nil
	intent.SealedOutboxPayload = append(json.RawMessage(nil), sealedPayload...)
	started := projections.LicensedCryptoMigrationStarted{
		RunID: intent.RunID, AssetIDs: []string{intent.AssetID}, TargetAlgorithm: TargetMLDSA65,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: ProtocolACME, Queued: 1,
		TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{intent},
	}
	data, err := json.Marshal(started)
	if err != nil {
		t.Fatal(err)
	}
	var replay projections.LicensedCryptoMigrationStarted
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if len(replay.TLSPostures) != 1 || !bytes.Equal(replay.TLSPostures[0].SealedOutboxPayload, sealedPayload) {
		t.Fatal("event replay did not retain the exact committed sealed outbox bytes")
	}
	if bytes.Contains(data, []byte("must-not-leak")) || bytes.Contains(data, []byte("envoy.test")) {
		t.Fatalf("started event leaked plaintext target configuration: %s", data)
	}
	if bytes.Contains(data, []byte(`"target_config"`)) {
		t.Fatalf("started event retained a plaintext target_config field: %s", data)
	}
	var opened pqcMigrationTLSPosturePayload
	if _, err := openTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSPostureDestination, sealedTestKey,
		replay.TLSPostures[0].SealedOutboxPayload, &opened,
	); err != nil {
		t.Fatalf("open replayed exact intent: %v", err)
	}
}

func TestCompletedEventRetainsOnlyExactCiphertextAndRollbackReopensIt(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	sealedPayload := sealTestIntent(t, key, intent)
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSPostureDestination,
		IdempotencyKey: sealedTestKey, Payload: sealedPayload,
	}
	deployer := &scriptedTLSDeployer{}
	var prepared *TLSFindingPrepared
	var completed TLSFindingCompleted
	h := &outboxHandler{
		deployer: deployer, integrityKey: key,
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		lookupPrepared: func(context.Context, string, pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error) {
			if prepared == nil {
				return connector.TLSPosture{}, false, nil
			}
			return clonePosture(prepared.Previous), true, nil
		},
		appendEvent: func(_ context.Context, _ string, eventType string, payload any) error {
			switch eventType {
			case EventTLSFindingPrepared:
				value := payload.(TLSFindingPrepared)
				prepared = &value
			case EventTLSFindingCompleted:
				completed = payload.(TLSFindingCompleted)
			default:
				t.Fatalf("completion event type = %s", eventType)
			}
			return nil
		},
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err != nil {
		t.Fatalf("forward delivery handled=%v err=%v", handled, err)
	}
	data, err := json.Marshal(completed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("must-not-leak")) || bytes.Contains(data, []byte("envoy.test")) {
		t.Fatalf("completion event leaked plaintext target configuration: %s", data)
	}
	if bytes.Contains(data, []byte(`"target_config"`)) {
		t.Fatalf("completion event retained a plaintext target_config field: %s", data)
	}
	if !bytes.Equal(completed.Intent.SealedOutboxPayload, sealedPayload) {
		t.Fatal("completion event did not retain exact forward ciphertext")
	}
	reopened, err := openCompletedTLSForwardIntent(key, sealedTestTenant, completed)
	if err != nil {
		t.Fatalf("rollback reopen: %v", err)
	}
	if !bytes.Equal(reopened.TargetConfig, intent.TargetConfig) {
		t.Fatalf("rollback reopened target config = %s, want exact original", reopened.TargetConfig)
	}
}

func TestTLSPostureRollbackOutboxIsSealedAndEventReplayExact(t *testing.T) {
	key := testIntegrityKey(t)
	idempotencyKey := "licensed-crypto-migration-tls-rollback:run-a:target-a"
	payload := pqcMigrationTLSRollbackPayload{
		RunID: sealedTestRun, Reason: "operator rollback",
		Mutation: connector.TLSPostureMutation{
			RunID: sealedTestRun, FindingID: "rollback:target-a", FindingKind: "rollback",
			TargetID: "target-a", TargetRevision: sealedTestRevision, Connector: "envoy",
			Target: "edge-listener", TargetConfig: json.RawMessage(`{"redirect_marker":"rollback-must-not-leak"}`),
			Desired: connector.TLSPosture{
				MinimumVersion: "TLSv1.1", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
				KeyExchangeGroups: []string{"secp256r1"},
			},
		},
		Restores: []TLSAssetRestore{{
			RunID: sealedTestRun, AssetID: sealedTestAsset, Kind: "tls-endpoint",
			Location: "edge.internal:443", Protocol: "TLSv1.1", Strength: "broken",
			QuantumVulnerable: true, OutOfPolicy: true, FindingKind: "protocol", TargetID: "target-a",
		}},
	}
	sealedPayload, err := sealTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSRollbackDestination, idempotencyKey,
		payload.RunID, payload.Restores[0].AssetID, payload.Mutation.TargetRevision, payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealedPayload, []byte("rollback-must-not-leak")) {
		t.Fatalf("sealed rollback leaked redirect config: %s", sealedPayload)
	}
	requested := tlsRollbackRequested{RunID: sealedTestRun, Intents: []sealedTLSRollbackIntent{{
		TargetID: "target-a", AssetIDs: []string{sealedTestAsset}, IdempotencyKey: idempotencyKey,
		Payload: append(json.RawMessage(nil), sealedPayload...),
	}}}
	eventData, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	var replay tlsRollbackRequested
	if err := json.Unmarshal(eventData, &replay); err != nil {
		t.Fatal(err)
	}
	if len(replay.Intents) != 1 || !bytes.Equal(replay.Intents[0].Payload, sealedPayload) {
		t.Fatal("rollback-request event did not preserve exact sealed outbox bytes")
	}

	var opened pqcMigrationTLSRollbackPayload
	wrapper, err := openTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSRollbackDestination, idempotencyKey,
		replay.Intents[0].Payload, &opened,
	)
	if err != nil {
		t.Fatalf("open rollback: %v", err)
	}
	if wrapper.AssetID != sealedTestAsset || opened.Mutation.TargetRevision != sealedTestRevision || len(opened.Restores) != 1 {
		t.Fatalf("opened rollback lost binding: wrapper=%+v payload=%+v", wrapper, opened)
	}
	if _, err := openTLSPostureOutbox(
		key, "tenant-b", licensedCryptoMigrationTLSRollbackDestination, idempotencyKey,
		sealedPayload, &opened,
	); err == nil {
		t.Fatal("rollback sealed intent opened under another tenant")
	}
	var changed sealedTLSPostureOutbox
	if err := json.Unmarshal(sealedPayload, &changed); err != nil {
		t.Fatal(err)
	}
	changed.TargetRevision = "substituted-revision"
	changedBytes, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openTLSPostureOutbox(
		key, sealedTestTenant, licensedCryptoMigrationTLSRollbackDestination, idempotencyKey,
		changedBytes, &opened,
	); err == nil {
		t.Fatal("rollback sealed intent opened after target revision substitution")
	}

	deployer := &scriptedTLSDeployer{}
	var completed TLSFindingRollbackCompleted
	h := &outboxHandler{
		deployer: deployer, integrityKey: key,
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		appendEvent: func(_ context.Context, _ string, eventType string, eventPayload any) error {
			if eventType != EventTLSFindingRollbackCompleted {
				t.Fatalf("rollback event type = %s", eventType)
			}
			var ok bool
			completed, ok = eventPayload.(TLSFindingRollbackCompleted)
			if !ok {
				t.Fatalf("rollback payload type = %T", eventPayload)
			}
			return nil
		},
	}
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSRollbackDestination,
		IdempotencyKey: idempotencyKey, Payload: sealedPayload,
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err != nil {
		t.Fatalf("sealed rollback delivery handled=%v err=%v", handled, err)
	}
	if completed.RunID != sealedTestRun || len(completed.Restores) != 1 || completed.Restores[0].AssetID != sealedTestAsset {
		t.Fatalf("rollback completion = %+v", completed)
	}
}

type scriptedTLSDeployer struct {
	failures  int
	calls     int
	mutations int
	current   connector.TLSPosture
}

type unsupportedTLSDeployer struct{ scriptedTLSDeployer }

func (*unsupportedTLSDeployer) SupportsTLSPosture(string) bool { return false }

func (*scriptedTLSDeployer) SupportsTLSPosture(string) bool { return true }

func (d *scriptedTLSDeployer) ReadTLSPosture(context.Context, connector.TLSPostureMutation) (connector.TLSPosture, error) {
	return clonePosture(d.currentTLSPosture()), nil
}

func (d *scriptedTLSDeployer) ApplyTLSPosture(_ context.Context, mutation connector.TLSPostureMutation) (connector.TLSPostureReceipt, error) {
	d.calls++
	if d.calls <= d.failures {
		return connector.TLSPostureReceipt{}, errors.New("receiver failed with secret=do-not-project")
	}
	current := d.currentTLSPosture()
	receipt := connector.TLSPostureReceipt{
		RunID: mutation.RunID, FindingID: mutation.FindingID, FindingKind: mutation.FindingKind,
		TargetID: mutation.TargetID, TargetRevision: mutation.TargetRevision, Connector: mutation.Connector,
		Previous: clonePosture(current),
	}
	if mutation.ExpectedPrevious != nil {
		receipt.Previous = clonePosture(*mutation.ExpectedPrevious)
		if connector.EqualTLSPosture(current, mutation.Desired) {
			receipt.Observed = clonePosture(current)
			return receipt, nil
		}
		if !connector.EqualTLSPosture(current, *mutation.ExpectedPrevious) {
			return connector.TLSPostureReceipt{}, errors.New("receiver changed after preparation")
		}
	}
	if connector.EqualTLSPosture(current, mutation.Desired) {
		receipt.Observed = clonePosture(current)
		return receipt, nil
	}
	d.mutations++
	d.current = clonePosture(mutation.Desired)
	receipt.Observed, receipt.Applied = clonePosture(mutation.Desired), true
	return receipt, nil
}

func (d *scriptedTLSDeployer) RestoreTLSPosture(ctx context.Context, mutation connector.TLSPostureMutation) (connector.TLSPostureReceipt, error) {
	return d.ApplyTLSPosture(ctx, mutation)
}

func (d *scriptedTLSDeployer) currentTLSPosture() connector.TLSPosture {
	if d.current.MinimumVersion != "" {
		return clonePosture(d.current)
	}
	return connector.TLSPosture{
		MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
		KeyExchangeGroups: []string{"secp256r1"},
	}
}

func TestTLSPostureRetrySuccessDoesNotProjectFailure(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSPostureDestination,
		IdempotencyKey: sealedTestKey, Payload: sealTestIntent(t, key, intent),
	}
	deployer := &scriptedTLSDeployer{failures: 1}
	var eventTypes []string
	var prepared *TLSFindingPrepared
	h := &outboxHandler{
		deployer: deployer, integrityKey: key,
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		lookupPrepared: func(context.Context, string, pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error) {
			if prepared == nil {
				return connector.TLSPosture{}, false, nil
			}
			return clonePosture(prepared.Previous), true, nil
		},
		appendEvent: func(_ context.Context, _ string, eventType string, payload any) error {
			eventTypes = append(eventTypes, eventType)
			if eventType == EventTLSFindingPrepared {
				value := payload.(TLSFindingPrepared)
				prepared = &value
			}
			return nil
		},
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err == nil {
		t.Fatalf("first delivery handled=%v err=%v, want retryable receiver error", handled, err)
	}
	if len(eventTypes) != 1 || eventTypes[0] != EventTLSFindingPrepared {
		t.Fatalf("retryable attempt did not retain exactly one durable preparation: %v", eventTypes)
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err != nil {
		t.Fatalf("retry delivery handled=%v err=%v", handled, err)
	}
	if len(eventTypes) != 2 || eventTypes[1] != EventTLSFindingCompleted {
		t.Fatalf("retry-success events = %v, want preparation then completion and no failure", eventTypes)
	}
}

func TestTLSPostureCrashAfterReceiverMutationRetainsOriginalRollbackState(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSPostureDestination,
		IdempotencyKey: sealedTestKey, Payload: sealTestIntent(t, key, intent),
	}
	deployer := &scriptedTLSDeployer{}
	var prepared *TLSFindingPrepared
	var completed TLSFindingCompleted
	h := &outboxHandler{
		deployer: deployer, integrityKey: key,
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		lookupPrepared: func(context.Context, string, pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error) {
			if prepared == nil {
				return connector.TLSPosture{}, false, nil
			}
			return clonePosture(prepared.Previous), true, nil
		},
		appendEvent: func(_ context.Context, _ string, eventType string, payload any) error {
			switch eventType {
			case EventTLSFindingPrepared:
				value := payload.(TLSFindingPrepared)
				prepared = &value
			case EventTLSFindingCompleted:
				completed = payload.(TLSFindingCompleted)
			}
			return nil
		},
		afterTLSApply: func() error { return errors.New("crash after receiver read-back") },
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err == nil {
		t.Fatalf("crash attempt handled=%v err=%v", handled, err)
	}
	if prepared == nil || deployer.mutations != 1 {
		t.Fatalf("prepared=%+v receiver mutations=%d, want durable prior plus one mutation", prepared, deployer.mutations)
	}
	h.afterTLSApply = nil
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err != nil {
		t.Fatalf("crash retry handled=%v err=%v", handled, err)
	}
	if deployer.mutations != 1 {
		t.Fatalf("crash retry repeated receiver mutation: %d", deployer.mutations)
	}
	if !connector.EqualTLSPosture(completed.Receipt.Previous, prepared.Previous) ||
		connector.EqualTLSPosture(completed.Receipt.Previous, intent.Desired) {
		t.Fatalf("retry completion lost original rollback posture: %+v", completed.Receipt)
	}
}

func TestTLSPostureRetryAfterDurableCompletionNeverReappliesAfterRollback(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	sealedPayload := sealTestIntent(t, key, intent)
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSPostureDestination,
		IdempotencyKey: sealedTestKey, Payload: sealedPayload,
	}
	deployer := &scriptedTLSDeployer{}
	var prepared *TLSFindingPrepared
	var completed *TLSFindingCompleted
	crashAfterCompletion := true
	h := &outboxHandler{
		deployer: deployer, integrityKey: key,
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		lookupPrepared: func(context.Context, string, pqcMigrationTLSPosturePayload) (connector.TLSPosture, bool, error) {
			if prepared == nil {
				return connector.TLSPosture{}, false, nil
			}
			return clonePosture(prepared.Previous), true, nil
		},
		lookupCompleted: func(context.Context, string, pqcMigrationTLSPosturePayload, []byte) (TLSFindingCompleted, bool, error) {
			if completed == nil {
				return TLSFindingCompleted{}, false, nil
			}
			return *completed, true, nil
		},
		appendEvent: func(_ context.Context, _ string, eventType string, payload any) error {
			switch eventType {
			case EventTLSFindingPrepared:
				value := payload.(TLSFindingPrepared)
				prepared = &value
			case EventTLSFindingCompleted:
				value := payload.(TLSFindingCompleted)
				completed = &value
				if crashAfterCompletion {
					return errors.New("completion persisted but local acknowledgement crashed")
				}
			}
			return nil
		},
	}
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err == nil {
		t.Fatalf("completion crash handled=%v err=%v", handled, err)
	}
	if completed == nil || prepared == nil || deployer.mutations != 1 {
		t.Fatalf("prepared=%+v completed=%+v mutations=%d", prepared, completed, deployer.mutations)
	}
	// Model the operator's exact rollback occurring after the durable completion
	// became visible but before the original outbox claim was acknowledged.
	deployer.current = clonePosture(prepared.Previous)
	crashAfterCompletion = false
	if handled, err := h.DeliverLicensed(context.Background(), message); !handled || err != nil {
		t.Fatalf("post-rollback delivery retry handled=%v err=%v", handled, err)
	}
	if deployer.mutations != 1 || !connector.EqualTLSPosture(deployer.current, prepared.Previous) {
		t.Fatalf("delivery retry undid rollback: mutations=%d current=%+v", deployer.mutations, deployer.current)
	}
}

func TestRecoveredTLSCompletionIsBoundToExactSealedIntent(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	sealedPayload := sealTestIntent(t, key, intent)
	eventIntent := intent
	eventIntent.TargetConfig = nil
	eventIntent.SealedOutboxPayload = append(json.RawMessage(nil), sealedPayload...)
	candidate := TLSFindingCompleted{
		Intent: eventIntent,
		Receipt: connector.TLSPostureReceipt{
			RunID: intent.RunID, FindingID: intent.AssetID, FindingKind: intent.FindingKind,
			TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: intent.Connector,
			Previous: connector.TLSPosture{
				MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
				KeyExchangeGroups: []string{"secp256r1"},
			},
			Observed: intent.Desired, Applied: true,
		},
	}
	if err := validateCompletedTLSFinding(intent, sealedPayload, candidate); err != nil {
		t.Fatalf("valid recovered completion: %v", err)
	}
	candidate.Intent.SealedOutboxPayload = append(json.RawMessage(nil), sealedPayload...)
	candidate.Intent.SealedOutboxPayload[len(candidate.Intent.SealedOutboxPayload)-1] ^= 1
	if err := validateCompletedTLSFinding(intent, sealedPayload, candidate); err == nil {
		t.Fatal("completion bound to different ciphertext was accepted")
	}
	candidate.Intent.SealedOutboxPayload = append(json.RawMessage(nil), sealedPayload...)
	candidate.Receipt.TargetRevision = "substituted-revision"
	if err := validateCompletedTLSFinding(intent, sealedPayload, candidate); err == nil {
		t.Fatal("completion bound to different target revision was accepted")
	}
}

func TestTLSRolloutTargetPreflightRejectsUnsupportedAndIncompleteTargets(t *testing.T) {
	target := store.DeploymentTarget{
		ID: "target-a", Name: "edge-listener", Type: "nginx", RevisionID: "revision-a", Enabled: true,
	}
	if err := validateTLSRolloutTarget(target, &unsupportedTLSDeployer{}); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported target preflight error = %v", err)
	}
	target.Type = "envoy"
	target.RevisionID = ""
	if err := validateTLSRolloutTarget(target, &scriptedTLSDeployer{}); err == nil || !strings.Contains(err.Error(), "disabled or incomplete") {
		t.Fatalf("incomplete target preflight error = %v", err)
	}
	if err := validateTLSRolloutTarget(store.DeploymentTarget{}, nil); err == nil {
		t.Fatal("nil TLS posture deployer passed preflight")
	}
}

func TestTLSRollbackRejectsTargetWithQueuedForwardFinding(t *testing.T) {
	started := map[string]projections.LicensedCryptoMigrationTLSPosture{
		"protocol-a": {RunID: sealedTestRun, AssetID: "protocol-a", TargetID: "target-a"},
		"cipher-b":   {RunID: sealedTestRun, AssetID: "cipher-b", TargetID: "target-a"},
	}
	completed := map[string]TLSFindingCompleted{
		"protocol-a": {Intent: started["protocol-a"]},
	}
	failed := map[string]bool{}
	rolledBack := map[string]bool{}
	if err := validateTLSRollbackTargetReady("target-a", started, completed, failed, rolledBack); err == nil || !strings.Contains(err.Error(), "unresolved queued") {
		t.Fatalf("partial target rollback readiness error = %v", err)
	}
	failed["cipher-b"] = true
	if err := validateTLSRollbackTargetReady("target-a", started, completed, failed, rolledBack); err != nil {
		t.Fatalf("terminally resolved target rejected rollback: %v", err)
	}
}

func TestTLSPostureTerminalFailureIsRedactedAndClearsQueuedState(t *testing.T) {
	key := testIntegrityKey(t)
	intent := testTLSIntent()
	sealedPayload := sealTestIntent(t, key, intent)
	message := orchestrator.Message{
		TenantID: sealedTestTenant, Destination: licensedCryptoMigrationTLSPostureDestination,
		IdempotencyKey: sealedTestKey, Payload: sealedPayload,
	}
	progress := NewProgressProjection(nil)
	started := projections.LicensedCryptoMigrationStarted{
		RunID: intent.RunID, AssetIDs: []string{intent.AssetID}, TargetAlgorithm: TargetMLDSA65,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: ProtocolACME, Queued: 1,
		TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{intent},
	}
	startedData, err := json.Marshal(started)
	if err != nil {
		t.Fatal(err)
	}
	if err := progress.Apply(context.Background(), events.Event{
		Type: projections.EventLicensedCryptoMigrationStarted, TenantID: sealedTestTenant, Data: startedData,
	}); err != nil {
		t.Fatal(err)
	}
	prepared := TLSFindingPrepared{
		RunID: intent.RunID, AssetID: intent.AssetID, FindingKind: intent.FindingKind,
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: intent.Connector,
		Previous: connector.TLSPosture{
			MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
			KeyExchangeGroups: []string{"secp256r1"},
		},
	}
	preparedData, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := progress.Apply(context.Background(), events.Event{
		Type: EventTLSFindingPrepared, TenantID: sealedTestTenant, Data: preparedData,
	}); err != nil {
		t.Fatal(err)
	}

	var failureData []byte
	h := &outboxHandler{
		integrityKey: key,
		appendEvent: func(ctx context.Context, tenantID, eventType string, payload any) error {
			if eventType != EventTLSFindingFailed || tenantID != sealedTestTenant {
				t.Fatalf("terminal event = %s tenant=%s", eventType, tenantID)
			}
			failureData, err = json.Marshal(payload)
			if err != nil {
				return err
			}
			return progress.Apply(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: failureData})
		},
	}
	cause := errors.New("receiver said password=super-secret and redirect=https://attacker.test")
	if handled, err := h.DeliverLicensedTerminalFailure(context.Background(), message, cause); !handled || err != nil {
		t.Fatalf("terminal handled=%v err=%v", handled, err)
	}
	for _, forbidden := range []string{"super-secret", "attacker.test", "must-not-leak", "envoy.test"} {
		if bytes.Contains(failureData, []byte(forbidden)) {
			t.Fatalf("terminal failure event leaked %q: %s", forbidden, failureData)
		}
	}
	items := progress.Snapshot(sealedTestTenant, sealedTestRun)
	if len(items) != 1 || items[0].Status != TLSFindingFailed || items[0].Failure == "" {
		t.Fatalf("terminal progress = %+v, want one failed finding", items)
	}
	if items[0].Previous == nil || !connector.EqualTLSPosture(*items[0].Previous, prepared.Previous) {
		t.Fatalf("terminal progress lost durable pre-mutation posture: %+v", items[0])
	}
	if items[0].Status == TLSFindingQueued {
		t.Fatal("terminal retry exhaustion left finding unresolved/queued")
	}
}
