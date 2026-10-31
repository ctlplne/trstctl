// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

// Activation is a source fixture; the shipped signer runs as an actual child
// process in evaluation mode. RunFullBackup is the actual operator entry point.
// This is not independent production authorization or whole-restore proof.
func TestEventProtectionFullBackupProtectsIndependentTenantSQL(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour)
	tenant, dir := info.Tenant, info.Directory
	raw, err := os.ReadFile(filepath.Join(dir, "postgres-state.jsonl")) // #nosec G304 -- exact artifact in this test's owned backup directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.VerifyPostgresState(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("protected-sql-subject@example.invalid")) {
		t.Error("actual full backup retains enabled tenant receiver subject as plaintext")
	}
	if !bytes.Contains(raw, []byte("legacy-sql-neighbor@example.invalid")) {
		t.Error("never-enabled neighbor receiver changed")
	}
	protected := false
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 64<<20)
	for scan.Scan() {
		var row struct {
			Table      string          `json:"table"`
			TenantID   string          `json:"tenant_id"`
			Protection json.RawMessage `json:"protection"`
		}
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row.Table == "api_tokens" && row.TenantID == tenant && len(row.Protection) > 0 {
			protected = true
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Error("actual full backup has no protected API-token frame for enabled tenant")
	}
}

type protectedSQLBackupFixture struct {
	Config                                                             *config.Config
	Directory, Tenant, Neighbor, Registration, KeyID, CustodyDirectory string
}

func configureProtectedSQLManifestFixture(t *testing.T, cfg *config.Config) {
	t.Helper()
	// Existing manifest identity: explicit local fixture signer, independently
	// pinned public key. CA and audit keys still use the shipped child process.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pem, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(pem)
	root := t.TempDir()
	cfg.Backup.ManifestSigningKeyFile = filepath.Join(root, "manifest-private.pem")
	pub := filepath.Join(root, "manifest-public.pem")
	if err := os.WriteFile(cfg.Backup.ManifestSigningKeyFile, pem, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, crypto.MarshalPublicKeyPEM(crypto.SignerFromDigestSigner(key).Public().DER), 0o400); err != nil {
		t.Fatal(err)
	}
	cfg.Backup.TrustedManifestKeyFiles = []string{pub}
}

func eventProtectionPostgresBackupFixture(t *testing.T, retention time.Duration, protected ...bool) protectedSQLBackupFixture {
	enabled := len(protected) == 0 || protected[0]
	t.Helper()
	sourceDSN, drop, err := createEphemeralDatabase(t.Context(), serverTestPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	if sourceDSN == "" || sourceDSN == serverTestPostgresDSN(t) {
		t.Fatal("source fixture did not allocate an isolated database")
	}
	st, err := store.Open(t.Context(), sourceDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg := eventProtectionRuntimeConfigFixture(t)
	custodyDirectory := cfg.Privacy.EventProtection.KeyDirectory
	if !enabled {
		cfg.Privacy.EventProtection.KeyDirectory = ""
	}
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = sourceDSN
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas = 1
	cfg.NATS.AllowSingleReplica = true
	installSiblingSignerBinary(t)
	socketDir, err := os.MkdirTemp("", "epg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	cfg.Signer.Socket = filepath.Join(socketDir, "s.sock")
	cfg.Signer.AllowInsecureDevNonLinux = goruntime.GOOS != "linux"
	cfg.CA.PublicCertFile = filepath.Join(filepath.Dir(cfg.CA.CertFile), "ca-public.crt")
	cfg.Backup.AllowUnencrypted = true // explicit disposable-lab override
	configureProtectedSQLManifestFixture(t, cfg)
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	kek.Destroy()
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	signerStopped := false
	t.Cleanup(func() {
		if !signerStopped {
			signer.Close()
		}
	})
	provisioner := &Server{signAuthz: signer.tokenProvider}
	if err := provisioner.provisionCA(t.Context(), signer.signer.Client(), "Protected artifact fixture", cfg.CA.CertFile, cfg.CA.PublicCertFile); err != nil {
		t.Fatal(err)
	}
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "b13c5ce3-efbd-4c58-9406-80ae1a520795"
	const neighbor = "b9e9d906-0ed7-4248-827e-944f509f23df"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Protected SQL backup"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: neighbor, Data: []byte(`{"name":"Legacy SQL neighbor"}`)}); err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenant, registration.ID, retention)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		wire, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
			t.Fatal(err)
		}
	}
	if err := projections.New(st, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	serverStopped := false
	t.Cleanup(func() {
		if !serverStopped {
			_ = srv.Shutdown(t.Context())
		}
	})
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Protected owner", "protected-artifact@example.invalid"); err != nil {
		t.Fatal(err)
	}
	// Independent receiver fixtures: no live bearer credentials are minted.
	for _, row := range []struct{ tenant, id, subject, hash string }{
		{tenant, "1c7d242e-e338-4790-a1f6-613ad57970db", "protected-sql-subject@example.invalid", "protected-artifact-fixture-hash"},
		{neighbor, "3a225d1b-891e-4f20-9aac-c0b10992e706", "legacy-sql-neighbor@example.invalid", "neighbor-artifact-fixture-hash"},
	} {
		if err := st.WithTenant(t.Context(), row.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO api_tokens (id,tenant_id,token_hash,subject,scopes) VALUES ($1,$2,$3,$4,'{}')`, row.id, row.tenant, row.hash, row.subject)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// An actual first-writer reservation can precede its CA event. It is an
	// independent crash receiver fixture, not a generated/issued CA key.
	if err := st.ClaimCASignerHandle(t.Context(), tenant, "5204466b-c12c-40b1-a008-918993c9a843", "protected-backup-claim"); err != nil {
		t.Fatal(err)
	}
	// The operator backup starts its own child signer against the retained
	// custody. Stop the fixture server and original child before that handoff.
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	serverStopped = true
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	signer.Close()
	signerStopped = true
	dir := filepath.Join(cfg.Backup.Directory, "protected-sql")
	if _, err := RunFullBackup(t.Context(), cfg, dir); err != nil {
		t.Fatal(err)
	}

	st.Close()
	return protectedSQLBackupFixture{Config: cfg, Directory: dir, Tenant: tenant, Neighbor: neighbor, Registration: registration.ID, KeyID: request.KeyID, CustodyDirectory: custodyDirectory}
}

func TestEventProtectionFullRestoreHonorsCurrentErasureAndPreservesNeighborSQL(t *testing.T) {
	eventProtectionErasedSQLRestore(t, false)
}
func TestEventProtectionLegacySQLRestoreHonorsPreactivationCurrentErasure(t *testing.T) {
	eventProtectionErasedSQLRestore(t, true)
}
func eventProtectionErasedSQLRestore(t *testing.T, legacy bool) {
	info := eventProtectionPostgresBackupFixture(t, time.Nanosecond, !legacy)
	cfg := info.Config
	if legacy {
		cfg.Privacy.EventProtection.KeyDirectory = info.CustodyDirectory
	}
	original, err := os.ReadFile(filepath.Join(info.Directory, "postgres-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := crypto.SHA256Hex(original)
	if legacy && !bytes.Contains(original, []byte("protected-sql-subject@example.invalid")) {
		t.Fatal("legacy fixture did not retain its original plaintext bytes")
	}
	st, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			signer.Close()
		}
	}()
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(); _ = log.Close() }()
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	serverStopped := false
	defer func() {
		if !serverStopped {
			_ = srv.Shutdown(t.Context())
		}
	}()
	if legacy {
		request, err := eventprivacy.NewRequested(info.Tenant, info.Registration, time.Nanosecond)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		requested, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: info.Tenant, Data: wire})
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(st, runtime.projectionOptions()...).Apply(t.Context(), requested); err != nil {
			t.Fatal(err)
		}
		if err := srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: info.Tenant, RegistrationIdentity: info.Registration}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventKeyAssertNoTenantSQLResidue(t, st, info.Tenant)
	ref := eventprotect.KeyRef{TenantID: info.Tenant, ID: info.KeyID}
	receipt, erased, err := runtime.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !erased || receipt == "" {
		t.Fatalf("actual offboard did not remove independent material: %v", err)
	}
	keyFile := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, info.Tenant, info.KeyID+".key")
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("independent key material still exists")
	}
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	serverStopped = true
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	signer.Close()
	stopped = true
	target := protectedSQLRestoreTarget(t, cfg)
	summary, err := RunFullRestore(t.Context(), target, info.Directory)
	if err != nil {
		t.Fatalf("actual full restore from pre-removal artifact failed: %v", err)
	}
	if summary.OmittedRecords < 1 || summary.AppliedRecords+summary.OmittedRecords != summary.Records {
		t.Fatalf("restore lost authenticated or applied row counts: %+v", summary)
	}
	restored, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	eventKeyAssertNoTenantSQLResidue(t, restored, info.Tenant)
	var subject string
	if err := restored.WithTenant(t.Context(), info.Neighbor, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT subject FROM api_tokens WHERE tenant_id=$1 AND id=$2`, info.Neighbor, "3a225d1b-891e-4f20-9aac-c0b10992e706").Scan(&subject)
	}); err != nil || subject != "legacy-sql-neighbor@example.invalid" {
		t.Fatalf("independent neighbor SQL not restored: %v", err)
	}
	if summary.RedactedRecords != 1 {
		t.Fatalf("erased restore lost the exact signer denial replacement: %+v", summary)
	}
	var state string
	var owner *string
	if err := restored.WithTenant(t.Context(), "00000000-0000-0000-0000-000000000003", func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT state,owner_tenant_id::text FROM ca_signer_handle_claims WHERE tenant_id=$1 AND handle_sha256=$2`, "00000000-0000-0000-0000-000000000003", crypto.SHA256Hex([]byte("protected-backup-claim"))).Scan(&state, &owner)
	}); err != nil || state != "retired" || owner != nil {
		t.Fatalf("erased restore did not retain the scrubbed handle denial: %s %v", state, err)
	}
	assertProtectedSQLHandleDenial(t, restored, info.Neighbor)
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restore recreated destroyed independent key material")
	}
	current, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: cfg.Privacy.EventProtection.KeyDirectory, BackupRoots: []string{info.Directory}, Locker: restored, VerificationKeys: key.JWKS()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = current.Close() }()
	afterReceipt, afterErased, err := current.DestructionReceipt(t.Context(), ref)
	if err != nil || !afterErased || afterReceipt != receipt {
		t.Fatalf("restore changed original current destruction evidence: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(info.Directory, "postgres-state.jsonl"))
	if err != nil || crypto.SHA256Hex(after) != originalDigest {
		t.Fatal("restore rewrote retained backup ciphertext")
	}
}

func protectedSQLRestoreTarget(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	target := *cfg
	targetDSN, drop, err := createEphemeralDatabase(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	if targetDSN == "" || targetDSN == cfg.Postgres.DSN {
		t.Fatal("restore did not allocate an isolated database")
	}
	target.Postgres.DSN = targetDSN
	target.NATS.URL = startBackupTestNATS(t).ClientURL()
	root := t.TempDir()
	target.Postgres.DataDir = filepath.Join(root, "postgres")
	target.NATS.StoreDir = filepath.Join(root, "events")
	target.Signer.KeyStoreDir = filepath.Join(root, "signer")
	target.Signer.AuthSecretFile = filepath.Join(root, "sign-auth.bin")
	socketDir, err := os.MkdirTemp("", "eps-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	target.Signer.Socket = filepath.Join(socketDir, "s.sock")
	target.CA.CertFile = filepath.Join(root, "ca.crt")
	target.CA.PublicCertFile = filepath.Join(root, "ca-public.crt")
	target.Audit.SigningKeyFile = filepath.Join(root, "legacy-audit.pem")
	target.Audit.ArchiveDir = filepath.Join(root, "archive")
	target.Backup.Directory = filepath.Join(root, "backups")
	// The operator restores its deployment KEK separately; the tenant custodian
	// is deliberately the ORIGINAL current directory and is never in the backup.
	target.Secrets.KEKFile = filepath.Join(root, "deployment-kek.bin")
	material, err := secretfile.Load(cfg.Secrets.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := os.WriteFile(target.Secrets.KEKFile, material, 0o400)
	secret.Wipe(material)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	return &target
}

func assertProtectedSQLHandleDenial(t *testing.T, st *store.Store, tenant string) {
	t.Helper()
	if err := st.ClaimCASignerHandle(t.Context(), tenant, "15b05adb-3e30-489c-b417-78d64d18fc94", "protected-backup-claim"); !errors.Is(err, store.ErrCASignerHandleClaimed) {
		t.Fatalf("restored signer handle became reclaimable: %v", err)
	}
}

func TestEventProtectionFullRestorePreservesActiveProtectedSQL(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour)
	target := protectedSQLRestoreTarget(t, info.Config)
	summary, err := RunFullRestore(t.Context(), target, info.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if summary.OmittedRecords != 0 || summary.RedactedRecords != 0 || summary.AppliedRecords != summary.Records {
		t.Fatalf("active restore lost exact rows: %+v", summary)
	}
	restored, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	for _, row := range []struct{ tenant, id, subject string }{
		{info.Tenant, "1c7d242e-e338-4790-a1f6-613ad57970db", "protected-sql-subject@example.invalid"},
		{info.Neighbor, "3a225d1b-891e-4f20-9aac-c0b10992e706", "legacy-sql-neighbor@example.invalid"},
	} {
		var got string
		if err := restored.WithTenant(t.Context(), row.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT subject FROM api_tokens WHERE tenant_id=$1 AND id=$2`, row.tenant, row.id).Scan(&got)
		}); err != nil || got != row.subject {
			t.Fatalf("active/neighbor SQL round trip failed: %v", err)
		}
	}
	var owners int
	if err := restored.WithTenant(t.Context(), info.Tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM owners WHERE tenant_id=$1 AND email=$2`, info.Tenant, "protected-artifact@example.invalid").Scan(&owners)
	}); err != nil || owners != 1 {
		t.Fatalf("protected source owner was not independently rebuilt: %d %v", owners, err)
	}
	assertProtectedSQLHandleDenial(t, restored, info.Neighbor)
}
