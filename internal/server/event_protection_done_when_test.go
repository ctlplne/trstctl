// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

// A233 Done-when, on the served path: a tenant opts in through the public
// route; its sensitive owner fields are written through the API and backed up;
// it is offboarded (the Provider plane's offboard command) and the bounded
// worker destroys its key after the retention window with a signed record.
// Then an operator rebuild and a restore of the pre-destruction backup both
// show its sensitive fields erased, its signed audit export still verifies
// offline, and the neighbors (one protected under its own key, one never
// enabled) keep their readable data and verifiable audit.
func TestEventProtectionDoneWhenOffboardedTenantErasedAfterRebuildAndRestore(t *testing.T) {
	stack := newDoneWhenStack(t)
	cfg := stack.cfg
	const (
		shredded  = "5f0f3a8e-8a6e-4c7a-9a43-6c1b9a0f7d21"
		protected = "6a2c1d9b-3e4f-4b8a-8d7c-2f5e9b1a0c43"
		legacy    = "7b3d2eac-4f5a-4c9b-9e8d-3a6f0c2b1d54"
	)
	srv, log, runtime, key := stack.open(t)
	registrations := map[string]string{}
	for _, tenant := range []string{shredded, protected, legacy} {
		registered, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"done-when ` + tenant[:4] + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
		registrations[tenant] = registered.ID
		if err := projections.New(stack.st, runtime.projectionOptions()...).Apply(t.Context(), registered); err != nil {
			t.Fatal(err)
		}
	}
	scopes := []string{string(authz.PrivacyRead), string(authz.PrivacyWrite), string(authz.OwnersRead), string(authz.OwnersWrite), string(authz.AuditRead)}
	tokens := map[string]string{}
	for _, tenant := range []string{shredded, protected, legacy} {
		tokens[tenant] = seedServedAPIToken(t, t.Context(), stack.st, tenant, "operator-"+tenant[:4]+"@example.invalid", scopes)
	}
	call := doneWhenCaller(srv)

	// Opt in through the public route: the shredded tenant with a short
	// retention, the protected neighbor with its own key and a long one.
	for tenant, retention := range map[string]string{shredded: "1s", protected: "720h0m0s"} {
		body := `{"registration_identity":"` + registrations[tenant] + `","retention":"` + retention + `"}`
		if code, out := call(http.MethodPost, "/api/v1/privacy/event-protection", tokens[tenant], body, "opt-in-"+tenant[:4]); code != http.StatusAccepted {
			t.Fatalf("enable %s HTTP=%d %s", tenant, code, out)
		}
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{shredded, protected} {
		code, out := call(http.MethodGet, "/api/v1/privacy/event-protection", tokens[tenant], "", "")
		if code != http.StatusOK || !bytes.Contains(out, []byte(`"state":"active"`)) {
			t.Fatalf("%s not active after the worker: HTTP=%d %s", tenant, code, out)
		}
	}
	if code, out := call(http.MethodGet, "/api/v1/privacy/event-protection", tokens[legacy], "", ""); code != http.StatusOK || !bytes.Contains(out, []byte(`"state":"not_enabled"`)) {
		t.Fatalf("legacy neighbor status HTTP=%d %s", code, out)
	}
	owners := map[string]store.Owner{}
	for _, tenant := range []string{shredded, protected, legacy} {
		email := "owner-" + tenant[:4] + "@example.invalid"
		code, out := call(http.MethodPost, "/api/v1/owners", tokens[tenant], `{"kind":"team","name":"Owner `+tenant[:4]+`","email":"`+email+`"}`, "owner-"+tenant[:4])
		var owner store.Owner
		if code != http.StatusCreated || json.Unmarshal(out, &owner) != nil || owner.ID == "" {
			t.Fatalf("create owner for %s HTTP=%d %s", tenant, code, out)
		}
		owner.Email = email
		owners[tenant] = owner
	}
	// The shredded tenant's signed audit export, taken while its key is live.
	code, out := call(http.MethodGet, "/api/v1/audit/export?limit=10000", tokens[shredded], "", "")
	var exported struct {
		Bundle string `json:"bundle"`
	}
	if code != http.StatusOK || json.Unmarshal(out, &exported) != nil || exported.Bundle == "" {
		t.Fatalf("audit export HTTP=%d %s", code, out)
	}
	before, err := audit.VerifyBundle(exported.Bundle, key.JWKS())
	if err != nil || before.Count == 0 {
		t.Fatalf("audit export did not verify while the key was live: %v", err)
	}
	privateEvent := doneWhenOwnerEvent(t, log, shredded)
	keyRef := doneWhenKeyRef(t, runtime, shredded)
	stack.close(t, srv, log, runtime)

	dir := filepath.Join(cfg.Backup.Directory, "done-when")
	if _, err := RunFullBackup(t.Context(), cfg, dir); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(dir, "postgres-state.jsonl")) // #nosec G304 -- the test's own backup artifact (CWE-22)
	if err != nil || bytes.Contains(artifact, []byte(owners[shredded].Email)) {
		t.Fatal("the backup carries the opted-in tenant's owner email in plaintext")
	}

	// Offboard, then let the bounded worker destroy the key after its window.
	srv, log, runtime, key = stack.open(t)
	call = doneWhenCaller(srv)
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: shredded, RegistrationIdentity: registrations[shredded]}); err != nil {
		t.Fatal(err)
	}
	receipt := ""
	for deadline := time.Now().Add(30 * time.Second); receipt == ""; {
		if err := srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		got, erased, err := runtime.custody.DestructionReceipt(t.Context(), keyRef)
		if err != nil {
			t.Fatal(err)
		}
		if erased {
			receipt = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker did not destroy the offboarded tenant's key after its retention window")
		}
		time.Sleep(250 * time.Millisecond)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil || claims.Request.Ref != keyRef || claims.RemovedAt.IsZero() {
		t.Fatalf("destruction record does not verify for the tenant key: %v", err)
	}
	keyFile := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, shredded, keyRef.ID+".key")
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("destroyed key material is still on disk")
	}
	eventKeyAssertNoTenantSQLResidue(t, stack.st, shredded)
	doneWhenAssertErased(t, log, privateEvent)
	// Audit: the export taken before destruction still verifies offline, and
	// each neighbor's live chain exports and verifies after it.
	if after, err := audit.VerifyBundle(exported.Bundle, key.JWKS()); err != nil || after.ChainHead != before.ChainHead {
		t.Fatalf("pre-destruction audit export no longer verifies: %v", err)
	}
	for _, tenant := range []string{protected, legacy} {
		code, out := call(http.MethodGet, "/api/v1/audit/export?limit=10000", tokens[tenant], "", "")
		var bundle struct {
			Bundle string `json:"bundle"`
		}
		if code != http.StatusOK || json.Unmarshal(out, &bundle) != nil {
			t.Fatalf("neighbor audit export HTTP=%d %s", code, out)
		}
		if verified, err := audit.VerifyBundle(bundle.Bundle, key.JWKS()); err != nil || verified.Count == 0 {
			t.Fatalf("neighbor %s audit no longer verifies: %v", tenant, err)
		}
		if code, out := call(http.MethodGet, "/api/v1/owners/"+owners[tenant].ID, tokens[tenant], "", ""); code != http.StatusOK || !bytes.Contains(out, []byte(owners[tenant].Email)) {
			t.Fatalf("neighbor %s owner unreadable after the destruction: HTTP=%d %s", tenant, code, out)
		}
	}
	stack.close(t, srv, log, runtime)

	// Operator rebuild from the retained event log.
	if _, err := RunRebuild(t.Context(), cfg); err != nil {
		t.Fatalf("operator rebuild: %v", err)
	}
	rebuilt := stack.store(t)
	doneWhenAssertNeighbors(t, rebuilt, owners, protected, legacy)
	eventKeyAssertNoTenantSQLResidue(t, rebuilt, shredded)
	rebuiltLog, rebuiltRuntime, err := openConfiguredEventSource(t.Context(), cfg, rebuilt, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	doneWhenAssertErased(t, rebuiltLog, privateEvent)
	_ = rebuiltLog.Close()
	_ = rebuiltRuntime.Close()

	// Restore the pre-destruction backup into a fresh deployment.
	target := protectedSQLRestoreTarget(t, cfg)
	if _, err := RunFullRestore(t.Context(), target, dir); err != nil {
		t.Fatalf("restore of the pre-destruction backup: %v", err)
	}
	restored, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	eventKeyAssertNoTenantSQLResidue(t, restored, shredded)
	doneWhenAssertNeighbors(t, restored, owners, protected, legacy)
	restoredLog, restoredRuntime, err := openConfiguredEventSource(t.Context(), target, restored, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restoredRuntime.Close(); _ = restoredLog.Close() }()
	doneWhenAssertErased(t, restoredLog, privateEvent)
	if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restore recreated destroyed key material")
	}
}

type doneWhenStack struct {
	cfg    *config.Config
	st     *store.Store // the open phase's store; Server.Shutdown closes it
	signer runSigner
}

// newDoneWhenStack is a disposable deployment: an isolated database, external
// NATS, the shipped child signer and a key directory outside every backup root.
func newDoneWhenStack(t *testing.T) *doneWhenStack {
	t.Helper()
	dsn, drop, err := createEphemeralDatabase(t.Context(), serverTestPostgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(drop)
	st, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = st.Migrate(t.Context())
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode, cfg.Postgres.DSN = config.PostgresExternal, dsn
	cfg.NATS.Mode, cfg.NATS.URL = config.NATSExternal, startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	installSiblingSignerBinary(t)
	socketDir, err := os.MkdirTemp("", "edw-")
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
	signer, _, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	provisioner := &Server{signAuthz: signer.tokenProvider}
	if err := provisioner.provisionCA(t.Context(), signer.signer.Client(), "Done-when fixture", cfg.CA.CertFile, cfg.CA.PublicCertFile); err != nil {
		t.Fatal(err)
	}
	signer.Close()
	return &doneWhenStack{cfg: cfg}
}

// store opens a fresh store on the deployment database for an offline check.
func (s *doneWhenStack) store(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), s.cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

// open starts the signer, event source, protection runtime and server.
func (s *doneWhenStack) open(t *testing.T) (*Server, *events.Log, *eventProtectionRuntime, *jose.SigningKey) {
	t.Helper()
	s.st = s.store(t)
	signer, key, err := openAuditSigningRuntime(t.Context(), s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.signer = signer
	log, runtime, err := openConfiguredEventSource(t.Context(), s.cfg, s.st, key, true, nil)
	if err != nil {
		signer.Close()
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: s.st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		_ = runtime.Close()
		_ = log.Close()
		signer.Close()
		t.Fatal(err)
	}
	return srv, log, runtime, key
}

// close stops everything open holds, in order, before an offline operation.
func (s *doneWhenStack) close(t *testing.T, srv *Server, log *events.Log, runtime *eventProtectionRuntime) {
	t.Helper()
	err := errors.Join(srv.Shutdown(t.Context()), log.Close(), runtime.Close())
	s.signer.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func doneWhenCaller(srv *Server) func(method, path, token, body, idempotency string) (int, []byte) {
	return func(method, path, token, body, idempotency string) (int, []byte) {
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		if idempotency != "" {
			request.Header.Set("Idempotency-Key", idempotency)
		}
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes()
	}
}

// doneWhenOwnerEvent is the tenant's protected owner.created source event.
func doneWhenOwnerEvent(t *testing.T, log *events.Log, tenant string) events.EnvelopeMetadata {
	t.Helper()
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var found []events.EnvelopeMetadata
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), tenant, 1, head, []string{"owner.created"}, func(meta events.EnvelopeMetadata) error {
		found = append(found, meta)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].DeclaredKeyID == "" {
		t.Fatalf("expected one protected owner.created event, got %+v", found)
	}
	return found[0]
}

func doneWhenKeyRef(t *testing.T, runtime *eventProtectionRuntime, tenant string) eventprotect.KeyRef {
	t.Helper()
	life, err := runtime.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation == nil {
		t.Fatalf("no activated lifetime for %s: %v", tenant, err)
	}
	return life.Activation.Body.Creation.Ref
}

// doneWhenAssertErased reads the retained event through current custody: the
// envelope stays, its sensitive fields read back erased.
func doneWhenAssertErased(t *testing.T, log *events.Log, meta events.EnvelopeMetadata) {
	t.Helper()
	event, found, err := log.EventByID(t.Context(), meta.ID)
	if err != nil || !found || !event.SensitiveErased || len(event.Data) != 0 || event.Sequence != meta.Sequence {
		t.Fatalf("protected source event is not erased: found=%v erased=%v err=%v", found, event.SensitiveErased, err)
	}
}

func doneWhenAssertNeighbors(t *testing.T, st *store.Store, owners map[string]store.Owner, tenants ...string) {
	t.Helper()
	for _, tenant := range tenants {
		got, err := st.GetOwner(context.Background(), tenant, owners[tenant].ID)
		if err != nil || got.Email != owners[tenant].Email {
			t.Fatalf("neighbor %s owner lost or changed: %+v %v", tenant, got, err)
		}
	}
	var neighbors int
	if err := st.WithTenant(context.Background(), tenants[0], func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM owners WHERE tenant_id=$1`, tenants[0]).Scan(&neighbors)
	}); err != nil || neighbors == 0 {
		t.Fatalf("protected neighbor has no owners after recovery: %v", err)
	}
}
