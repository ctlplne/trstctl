// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Full restore must obtain a durable target fence before it mutates signer
// files. A target whose PostgreSQL admission cannot be established is unsafe
// even when its backup artifact is otherwise valid.
func TestFullRestoreRefusesBeforeFilesWhenTargetAdmissionUnavailable(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	if _, err := os.Stat(target.CA.CertFile); !os.IsNotExist(err) {
		t.Fatalf("target CA file exists before restore: %v", err)
	}
	target.Postgres.DSN = "postgres://127.0.0.1:1/trstctl?connect_timeout=1"
	if _, err := RunFullRestore(t.Context(), target, info.Directory); err == nil {
		t.Fatal("full restore accepted unavailable target admission")
	}
	if _, err := os.Stat(target.CA.CertFile); !os.IsNotExist(err) {
		t.Fatalf("restore changed signer files before target admission: %v", err)
	}
}

// CR-045: a committed full-restore marker fences both source backup entry
// points before either publishes an event file or a full artifact directory.
func TestBackupEntryPointsRefuseCommittedRestoreMarkerBeforeArtifactWrite(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	st, err := store.Open(t.Context(), info.Config.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a1",
		ArtifactSHA256: strings.Repeat("a", 64), EventCut: 1, DeploymentID: "backup-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	}()
	file := filepath.Join(t.TempDir(), "event-only.jsonl")
	if _, err := RunBackup(t.Context(), info.Config, file); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("event backup under marker=%v, want restore refusal", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("event backup wrote artifact under marker: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "full")
	if _, err := RunFullBackup(t.Context(), info.Config, dir); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("full backup under marker=%v, want restore refusal", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("full backup created artifact directory under marker: %v", err)
	}
}

// CR-045: library callers cannot use the independent PostgreSQL importer to
// bypass a full-restore marker held by a different operation.
func TestDirectPostgresStateImporterRefusesMarkerBeforeArtifactRead(t *testing.T) {
	st := newServerTestStore(t)
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a2",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 1, DeploymentID: "import-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	artifact := strings.NewReader("invalid artifact")
	if _, err := backup.RestorePostgresStateWithKey(t.Context(), st, artifact, nil, backup.PostgresStateIdentity{}); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("direct import under marker=%v, want restore refusal", err)
	}
	if artifact.Len() != len("invalid artifact") {
		t.Fatal("direct importer read artifact before restore admission")
	}
}

// CR-045: the configured event-log object must enforce target admission even
// when a library caller bypasses RunRestore and invokes raw history restore.
func TestConfiguredEventLogRawRestoreRequiresFullRestoreOwner(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	read := false
	source := func(func(events.BackupHistoryRecord) error) error { read = true; return nil }
	if _, err := log.RestoreBackupHistory(t.Context(), 0, strings.Repeat("d", 64), source); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("unmarked raw history restore=%v, want exact full-restore owner refusal", err)
	}
	if read {
		t.Fatal("raw history source was read without a full-restore owner")
	}
	if _, err := log.RestoreAuthorizedBackupHistory(t.Context(), 0, strings.Repeat("d", 64), nil, source); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("unmarked authenticated history restore=%v, want exact full-restore owner refusal", err)
	}
	if read {
		t.Fatal("authenticated history source was read without a full-restore owner")
	}
	var unresolved int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND activity_kind='maintenance' AND lane='raw-history-restore' AND phase='started'`,
		store.RestoreControlTenantID).Scan(&unresolved); err != nil {
		t.Fatal(err)
	}
	if unresolved != 0 {
		t.Fatalf("owner refusal left %d unresolved raw-history starts", unresolved)
	}
}

func TestConfiguredEventLogRawRestoreOwnerRequiresAuthenticatedArtifact(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	marker := store.RestoreMarker{OperationID: "49900000-0000-4000-8000-0000000000b1",
		ArtifactSHA256: strings.Repeat("c", 64), EventHistorySHA256: strings.Repeat("d", 64),
		EventCut: 0, DeploymentID: "raw-history-owner-target"}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	read := false
	source := func(func(events.BackupHistoryRecord) error) error { read = true; return nil }
	if err := st.WithFullRestoreOwner(t.Context(), marker, func(ownerCtx context.Context) error {
		if _, err := log.RestoreAuthorizedBackupHistory(ownerCtx, 0, strings.Repeat("e", 64), nil, source); !errors.Is(err, store.ErrRestoreInProgress) {
			t.Fatalf("different raw event artifact borrowed owner: %v", err)
		}
		if read {
			t.Fatal("different raw event artifact reached its source")
		}
		if _, err := log.RestoreBackupHistory(ownerCtx, 0, strings.Repeat("d", 64), source); !errors.Is(err, events.ErrBackupRestoreAuthorizationRequired) {
			t.Fatalf("raw restore with owner but no artifact authorization=%v", err)
		}
		if _, err := log.RestoreAuthorizedBackupHistory(ownerCtx, 0, strings.Repeat("d", 64), nil, source); !errors.Is(err, events.ErrBackupRestoreAuthorizationRequired) {
			t.Fatalf("raw restore with owner and missing grant=%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if read {
		t.Fatal("raw history source was read without authenticated artifact authorization")
	}
}

func TestEventOnlyRestoreRequiresPairedStateBeforeHistoryMutation(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = serverTestPostgresDSN(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	artifact := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(artifact, []byte("fixture backup input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunRestore(t.Context(), cfg, artifact); !errors.Is(err, ErrEventOnlyRestoreRequiresPairedState) {
		t.Fatalf("event-only restore without independent PostgreSQL state=%v", err)
	}
	var unresolved int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND activity_kind='maintenance' AND lane='event-only-restore' AND phase='started'`,
		store.RestoreControlTenantID).Scan(&unresolved); err != nil || unresolved != 0 {
		t.Fatalf("event-only refusal left %d unresolved starts: %v", unresolved, err)
	}
}

func TestConfiguredEventLogRawRestoreRefusesMarkerBeforeSourceRead(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas = 1
	cfg.NATS.AllowSingleReplica = true
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a3",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 1, DeploymentID: "raw-history-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	read := false
	_, err = log.RestoreBackupHistory(t.Context(), 0, strings.Repeat("d", 64),
		func(func(events.BackupHistoryRecord) error) error { read = true; return nil })
	if !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("configured raw history restore under marker=%v, want refusal", err)
	}
	if read {
		t.Fatal("raw history source was read before restore admission")
	}
	// The authenticated path spools its source before calling the common raw
	// writer. Its admission must cover that preflight as well.
	source := func(func(events.BackupHistoryRecord) error) error { return nil }
	historyDigest, err := events.BackupHistoryDigest(t.Context(), 0, source)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := crypto.BackupRestoreAuthorization([]byte(strings.Repeat("k", 32)), crypto.BackupRestoreIntent{
		EventCutSequence: 0, ArtifactSHA256: strings.Repeat("d", 64), HistorySHA256: historyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Destroy()
	read = false
	_, err = log.RestoreAuthorizedBackupHistory(t.Context(), 0, strings.Repeat("d", 64), grant,
		func(func(events.BackupHistoryRecord) error) error { read = true; return nil })
	if !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("configured authenticated history restore under marker=%v, want refusal", err)
	}
	if read {
		t.Fatal("authenticated history source was read before restore admission")
	}
}

// CR-045: the common normalized event ingress must fence both live Append and
// federation Import before either can publish into a restoring deployment.
func TestConfiguredEventLogAppendAndImportRefuseRestoreMarker(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a4",
		ArtifactSHA256: strings.Repeat("e", 64), EventCut: 1, DeploymentID: "append-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	const tenant = "49900000-0000-4000-8000-0000000000a5"
	event := events.Event{TenantID: tenant, Type: "tenant.registered", Data: []byte(`{"name":"restore ingress fixture"}`)}
	if _, err := log.Append(t.Context(), event); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("Append under restore marker=%v, want refusal", err)
	}
	event.ID, event.Time = "restore-import-fixture", time.Now().UTC()
	if _, err := log.Import(t.Context(), event); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("Import under restore marker=%v, want refusal", err)
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != 0 {
		t.Errorf("event ingress under restore marker advanced head=%d, err=%v", head, err)
	}
}

// A tenant rewrap freezes every new event producer for that tenant, including
// federation imports, until the rewritten history and key state are complete.
func TestConfiguredEventLogAppendAndImportRefuseTenantRewrapGate(t *testing.T) {
	st := newServerRewrapStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	log, protection, err := openConfiguredEventSourceFixture(t, cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	const tenant = "49900000-0000-4000-8000-0000000000ba"
	if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant,
		Name: "rewrap ingress fixture", EventSeq: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplicationSecretTenantEpoch(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	operationID, err := st.BeginTenantApplicationSecretRewrap(t.Context(), tenant, "migrate")
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{TenantID: tenant, Type: projections.EventTenantRegistered,
		Data: []byte(`{"name":"rewrap ingress fixture"}`)}
	if _, err := log.Append(t.Context(), event); !errors.Is(err, store.ErrApplicationSecretRewrapInProgress) {
		t.Errorf("Append under tenant rewrap=%v, want refusal", err)
	}
	event.ID, event.Time = "rewrap-import-fixture", time.Now().UTC()
	if _, err := log.Import(t.Context(), event); !errors.Is(err, store.ErrApplicationSecretRewrapInProgress) {
		t.Errorf("Import under tenant rewrap=%v, want refusal", err)
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != 0 {
		t.Errorf("event ingress under tenant rewrap advanced head=%d, err=%v", head, err)
	}
	if err := st.CompleteTenantApplicationSecretRewrap(t.Context(), tenant, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), event); err != nil {
		t.Fatalf("Append after tenant rewrap completion: %v", err)
	}
}

// A request can own restore admission while its command appends an event. One
// admission connection must not wait on another connection from the same
// bounded pool before the command can finish.
func TestNestedRequestAndEventIngressUseOneRestoreSession(t *testing.T) {
	st := newServerTestStore(t, store.WithPoolSizes(store.PoolSizes{Restore: 1}))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000bb"
	err := st.WithRestoreActivity(ctx, tenant, "49900000-0000-4000-8000-0000000000bc",
		"request", "nested-append", func(outer context.Context) error {
			return st.WithRestoreEventIngress(outer, tenant, "49900000-0000-4000-8000-0000000000bd", "tenant.registered",
				func(context.Context) error { return nil })
		})
	if err != nil {
		t.Fatalf("nested event ingress failed: %v", err)
	}
	var started int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND phase='started'`, tenant).Scan(&started); err != nil || started != 0 {
		t.Fatalf("nested admission left %d started tokens: %v", started, err)
	}
}

// After a completed key rewrap, a direct projector without a canonical event
// source must refuse a caller's cached event before changing read state.
func TestDirectProjectionAfterRewrapRequiresCanonicalSource(t *testing.T) {
	st := newServerRewrapStore(t)
	const tenant = "49900000-0000-4000-8000-0000000000be"
	if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant,
		Name: "original", EventSeq: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplicationSecretTenantEpoch(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	operationID, err := st.BeginTenantApplicationSecretRewrap(t.Context(), tenant, "migrate")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteTenantApplicationSecretRewrap(t.Context(), tenant, operationID); err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "49900000-0000-4000-8000-0000000000bf", TenantID: tenant,
		Type: projections.EventTenantRegistered, Time: time.Now().UTC(), Sequence: 2,
		Data: []byte(`{"name":"stale"}`)}
	if err := projections.New(st).Apply(t.Context(), event); err == nil {
		t.Fatal("bare direct projector accepted an unverified event after rewrap")
	}
	got, err := st.GetTenant(t.Context(), tenant)
	if err != nil || got.Name != "original" {
		t.Fatalf("direct apply changed tenant before canonical refusal: name=%q err=%v", got.Name, err)
	}
}

func TestCallerOwnedApplyTxAfterRewrapRequiresCanonicalSource(t *testing.T) {
	st := newServerRewrapStore(t)
	const tenant = "49900000-0000-4000-8000-0000000000c1"
	if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant,
		Name: "original", EventSeq: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	apply := func(event events.Event) error {
		return st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			return projections.New(st).ApplyTx(t.Context(), tx, event)
		})
	}
	if err := apply(events.Event{ID: "49900000-0000-4000-8000-0000000000c3", TenantID: tenant,
		Type: projections.EventOwnerCreated, Time: time.Now().UTC(), Sequence: 2,
		Data: []byte(`{"id":"49900000-0000-4000-8000-0000000000c4","kind":"service","name":"control"}`)}); err != nil {
		t.Fatalf("control ApplyTx before rewrap: %v", err)
	}
	if _, err := st.ApplicationSecretTenantEpoch(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	operationID, err := st.BeginTenantApplicationSecretRewrap(t.Context(), tenant, "migrate")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteTenantApplicationSecretRewrap(t.Context(), tenant, operationID); err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "49900000-0000-4000-8000-0000000000c2", TenantID: tenant,
		Type: projections.EventOwnerCreated, Time: time.Now().UTC(), Sequence: 3,
		Data: []byte(`{"id":"49900000-0000-4000-8000-0000000000c5","kind":"service","name":"stale"}`)}
	err = apply(event)
	if err == nil {
		t.Fatal("caller-owned ApplyTx accepted an unverified event after rewrap")
	}
}

func TestDirectProjectionAfterRewrapMatchesPinnedCanonicalEvent(t *testing.T) {
	st := newServerRewrapStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	log, protection, err := openConfiguredEventSourceFixture(t, cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close(); _ = protection.Close() }()
	const tenant = "49900000-0000-4000-8000-0000000000c6"
	if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant,
		Name: "canonical fixture", EventSeq: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplicationSecretTenantEpoch(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(t.Context(), events.Event{ID: "49900000-0000-4000-8000-0000000000c7",
		TenantID: tenant, Type: projections.EventOwnerCreated,
		Data: []byte(`{"id":"49900000-0000-4000-8000-0000000000c8","kind":"service","name":"current","email":"current@example.invalid"}`)})
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := st.BeginTenantApplicationSecretRewrap(t.Context(), tenant, "migrate")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteTenantApplicationSecretRewrap(t.Context(), tenant, operationID); err != nil {
		t.Fatal(err)
	}
	proj := projections.New(st, projections.WithCanonicalEventSource(log))
	stale := event
	stale.Data = []byte(`{"id":"49900000-0000-4000-8000-0000000000c8","kind":"service","name":"stale","email":"current@example.invalid"}`)
	if err := proj.Apply(t.Context(), stale); err == nil {
		t.Fatal("direct projector accepted changed event data with canonical ID")
	}
	if err := proj.Apply(t.Context(), event); err != nil {
		t.Fatalf("direct projector rejected current canonical event: %v", err)
	}
}

// CR-045: a direct projector or caller-owned projection transaction cannot
// apply an event while the destination's full-restore marker is committed.
func TestDirectProjectionEntryPointsRefuseRestoreMarker(t *testing.T) {
	st := newServerTestStore(t)
	const tenant = "49900000-0000-4000-8000-0000000000a6"
	if err := st.UpsertTenant(t.Context(), store.Tenant{
		TenantID: tenant, Name: "projection fixture", EventSeq: 1, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a7",
		ArtifactSHA256: strings.Repeat("f", 64), EventCut: 1, DeploymentID: "projection-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	proj := projections.New(st)
	event := events.Event{ID: "projection-registered-fixture", TenantID: tenant,
		Type: projections.EventTenantRegistered, Time: time.Now().UTC(), Sequence: 2,
		Data: []byte(`{"name":"must not project"}`)}
	if err := proj.Apply(t.Context(), event); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("direct Projector.Apply under marker=%v, want refusal", err)
	}
	event = events.Event{ID: "projection-transaction-fixture", TenantID: tenant,
		Type: audit.EventTypeArchiveDownloaded, SchemaVersion: audit.ArchiveDownloadedSchemaVersion,
		Time: time.Now().UTC(), Sequence: 2, Data: []byte(`{}`)}
	err := st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		return proj.ApplyTx(t.Context(), tx, event)
	})
	if !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("direct Projector.ApplyTx under marker=%v, want refusal", err)
	}
}

type restoreMarkerAttachedProjection struct{ called bool }

func (*restoreMarkerAttachedProjection) Name() string                { return "restore-marker-attached-fixture" }
func (*restoreMarkerAttachedProjection) Reset(context.Context) error { return nil }
func (p *restoreMarkerAttachedProjection) Apply(_ context.Context, _ events.Event) error {
	p.called = true
	return nil
}

// CR-045: an attached projection's public direct-apply seam is a writer too.
func TestDirectAttachedProjectionRefusesRestoreMarker(t *testing.T) {
	st := newServerTestStore(t)
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000a8",
		ArtifactSHA256: strings.Repeat("a", 64), EventCut: 1, DeploymentID: "attached-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	attached := &restoreMarkerAttachedProjection{}
	proj := projections.New(st, projections.WithEventProjection(attached))
	event := events.Event{ID: "attached-fixture", TenantID: "49900000-0000-4000-8000-0000000000a9",
		Type: audit.EventTypeArchiveDownloaded, SchemaVersion: audit.ArchiveDownloadedSchemaVersion,
		Time: time.Now().UTC(), Sequence: 2, Data: []byte(`{}`)}
	if err := proj.ApplyEventProjections(t.Context(), event); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("direct attached projection under marker=%v, want refusal", err)
	}
	if attached.called {
		t.Fatal("attached projection applied during full restore")
	}
}

// CR-045: direct catch-up and snapshot fallback are maintenance writers even
// when their current source happens to be empty.
func TestDirectCatchUpAndSnapshotFallbackRefuseRestoreMarker(t *testing.T) {
	st := newServerTestStore(t)
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-0000000000b2",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 1, DeploymentID: "snapshot-fenced-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	proj := projections.New(st)
	if err := proj.ProjectCatchUp(t.Context(), log); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("direct catch-up under marker=%v, want refusal", err)
	}
	if _, err := proj.RestoreFromSnapshot(t.Context(), log); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Errorf("direct snapshot fallback under marker=%v, want refusal", err)
	}
}

func TestBuildRefusesCommittedFullRestoreMarkerBeforeStartupWrites(t *testing.T) {
	st := newServerTestStore(t)
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000051",
		ArtifactSHA256: strings.Repeat("a", 64), EventCut: 1, DeploymentID: "startup-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`, store.RestoreControlTenantID)
	})
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	srv, err := Build(t.Context(), Deps{Store: st, Log: log})
	if srv != nil {
		_ = srv.Shutdown(context.Background())
	}
	if !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("Build under committed restore marker=%v, want restore refusal", err)
	}
}

func TestRunStoreStartupRefusesRestoreMarkerBeforeMigrations(t *testing.T) {
	dsn, drop, err := createEphemeralDatabase(t.Context(), serverTestPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	st, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000061",
		ArtifactSHA256: strings.Repeat("b", 64), EventCut: 1, DeploymentID: "startup-migration-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	st.Close()
	cfg := &config.Config{}
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = dsn
	cfg.Migrate.Auto = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opened, stop, err := openMigratedStore(t.Context(), cfg, logger, nil)
	if opened != nil {
		opened.Close()
	}
	if stop != nil {
		_ = stop()
	}
	if !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("server store startup under restore marker=%v, want refusal", err)
	}
	probe, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var migrated bool
	if err := probe.SystemPool().QueryRow(t.Context(), `SELECT to_regclass('public.tenants') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("startup ran ordinary migrations under committed restore marker")
	}
}

func TestStandaloneRebuildRefusesRestoreMarkerBeforeMigrations(t *testing.T) {
	dsn, drop, err := createEphemeralDatabase(t.Context(), serverTestPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	st, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000081",
		ArtifactSHA256: strings.Repeat("c", 64), EventCut: 1, DeploymentID: "maintenance-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	st.Close()
	cfg := &config.Config{}
	cfg.Postgres.Mode, cfg.Postgres.DSN = config.PostgresExternal, dsn
	cfg.NATS.Mode, cfg.NATS.URL = config.NATSExternal, "nats://127.0.0.1:1"
	if _, err := RunRebuild(t.Context(), cfg); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("rebuild under full-restore marker=%v, want admission refusal", err)
	}
	probe, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var migrated bool
	if err := probe.SystemPool().QueryRow(t.Context(), `SELECT to_regclass('public.tenants') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("standalone rebuild migrated database under a restore marker")
	}
}

func TestEventOnlyRestoreRefusesFullRestoreMarkerBeforeMigrations(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	st, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000091",
		ArtifactSHA256: strings.Repeat("d", 64), EventCut: 1, DeploymentID: "event-restore-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := RunRestore(t.Context(), target, filepath.Join(info.Directory, "events.jsonl")); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("event-only restore under full-restore marker=%v, want admission refusal", err)
	}
	probe, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var migrated bool
	if err := probe.SystemPool().QueryRow(t.Context(), `SELECT to_regclass('public.tenants') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("event-only restore migrated database under a full-restore marker")
	}
}

func TestFullRestoreEventIngressRequiresExactMarkerBeforeMigration(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	st, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BootstrapRestoreAdmission(t.Context()); err != nil {
		t.Fatal(err)
	}
	marker := store.RestoreMarker{
		OperationID:    "49900000-0000-4000-8000-000000000101",
		ArtifactSHA256: strings.Repeat("e", 64), EventCut: 1, DeploymentID: "raw-event-target",
	}
	if err := st.BeginFullRestore(t.Context(), marker); err != nil {
		t.Fatal(err)
	}
	st.Close()
	wrong := marker
	wrong.ArtifactSHA256 = strings.Repeat("f", 64)
	if _, err := restoreEventLog(t.Context(), target, filepath.Join(info.Directory, "events.jsonl"),
		true, false, nil, &wrong); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("full restore event ingress under different artifact marker=%v", err)
	}
	probe, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var migrated bool
	if err := probe.SystemPool().QueryRow(t.Context(), `SELECT to_regclass('public.tenants') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("full restore event ingress migrated target before exact owner admission")
	}
}

func TestFullRestoreSuccessClearsTargetMarker(t *testing.T) {
	vh85SeedHook = vh85Seed(true)
	t.Cleanup(func() { vh85SeedHook = nil })
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	if _, err := RunFullRestore(t.Context(), target, info.Directory); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var count int
	if err := st.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM trstctl_recovery.restore_markers WHERE tenant_id=$1`,
		store.RestoreControlTenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("successful full restore left %d target restore marker(s)", count)
	}
}
