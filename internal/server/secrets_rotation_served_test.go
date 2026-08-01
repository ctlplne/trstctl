// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedStaticSecretRotationPostgresCutoverAndRollback is the SEC-05 proof:
// the served API drives rotation.Engine for a real PostgreSQL static credential.
// The happy path creates a new scoped login, publishes it to the consumer pointer,
// verifies login, and drops the old login. The failure path forces verification to
// fail, rolls the pointer back to the old credential, and revokes the staged login.
func TestServedStaticSecretRotationPostgresCutoverAndRollback(t *testing.T) {
	ctx := context.Background()
	dsn, stop := startRotationPostgres(t)
	defer stop()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS sec05_smoke(id int primary key); INSERT INTO sec05_smoke(id) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}

	oldRef, oldSecret := createRotationPostgresCredential(t, ctx, dsn, "sec05_old")
	rollbackRef, rollbackSecret := createRotationPostgresCredential(t, ctx, dsn, "sec05_rollback_old")
	publisher := rotation.NewMemoryCredentialPublisher()
	publisher.Put("db/reporting", oldRef, oldSecret)
	publisher.Put("db/rollback", rollbackRef, rollbackSecret)

	okRotator, err := rotation.NewPostgresRotator(rotation.PostgresConfig{
		DSN: []byte(dsn), Database: "postgres", Schema: "public", UsernamePrefix: "sec05", Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	rollbackRotator, err := rotation.NewPostgresRotator(rotation.PostgresConfig{
		DSN: []byte(dsn), Database: "postgres", Schema: "public", UsernamePrefix: "sec05_bad", Publisher: publisher,
		VerifyQuery: "SELECT missing FROM sec05_smoke",
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{
				"postgresql":          okRotator,
				"postgresql-rollback": rollbackRotator,
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "postgresql", "key": "db/reporting", "old_ref": oldRef})
	if status != http.StatusOK {
		t.Fatalf("rotate static secret: status %d body %s", status, body)
	}
	var rotated secretRotationValue
	if err := json.Unmarshal(body, &rotated); err != nil {
		t.Fatalf("decode rotation response: %v (%s)", err, body)
	}
	if !rotated.Completed || rotated.NewRef == "" || rotated.OldRef != oldRef {
		t.Fatalf("rotation report = %+v, want completed with new ref", rotated)
	}
	activeRef, activeSecret, err := publisher.ReadCredential(ctx, "db/reporting")
	if err != nil {
		t.Fatal(err)
	}
	if activeRef != rotated.NewRef {
		t.Fatalf("active ref = %q, want new ref %q", activeRef, rotated.NewRef)
	}
	assertPostgresCredentialWorks(t, ctx, activeSecret, "sec05_smoke")
	assertPostgresCredentialRevoked(t, ctx, oldSecret)
	if h.logContains(t, string(activeSecret)) || h.logContains(t, string(oldSecret)) {
		t.Fatal("rotation event log leaked PostgreSQL credential material")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "postgresql-rollback", "key": "db/rollback", "old_ref": rollbackRef})
	if status != http.StatusConflict {
		t.Fatalf("rollback rotation: status %d body %s", status, body)
	}
	var rolled secretRotationValue
	if err := json.Unmarshal(body, &rolled); err != nil {
		t.Fatalf("decode rollback response: %v (%s)", err, body)
	}
	if !rolled.RollbackAttempted || !rolled.RolledBack || rolled.RollbackFailed || rolled.FailedPhase != "verify" {
		t.Fatalf("rollback report = %+v, want successful rollback from verify", rolled)
	}
	activeRef, activeSecret, err = publisher.ReadCredential(ctx, "db/rollback")
	if err != nil {
		t.Fatal(err)
	}
	if activeRef != rollbackRef {
		t.Fatalf("rollback active ref = %q, want old ref %q", activeRef, rollbackRef)
	}
	assertPostgresCredentialWorks(t, ctx, activeSecret, "sec05_smoke")
	assertPostgresRoleAbsent(t, ctx, dsn, rolled.NewRef)
}

func TestServedScheduledSecretRotationRunsDueDualPhase(t *testing.T) {
	ctx := context.Background()
	dsn, stop := startRotationPostgres(t)
	defer stop()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS cap_secr_06_smoke(id int primary key); INSERT INTO cap_secr_06_smoke(id) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}

	oldRef, oldSecret := createRotationPostgresCredential(t, ctx, dsn, "capsecr06_old")
	publisher := rotation.NewMemoryCredentialPublisher()
	publisher.Put("db/reporting", oldRef, oldSecret)
	rotator, err := rotation.NewPostgresRotator(rotation.PostgresConfig{
		DSN: []byte(dsn), Database: "postgres", Schema: "public", UsernamePrefix: "capsecr06", Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretRotators = map[string]rotation.Rotator{"postgresql": rotator}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	dueAt := time.Now().Add(-time.Minute).UTC()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", tok,
		map[string]any{
			"name": "reporting-hourly", "provider": "postgresql", "key": "db/reporting",
			"old_ref": oldRef, "interval_seconds": 3600, "enabled": true,
			"next_run_at": dueAt.Format(time.RFC3339Nano),
		})
	if status != http.StatusCreated {
		t.Fatalf("create rotation schedule: status %d body %s", status, body)
	}
	var scheduled secretRotationScheduleValue
	if err := json.Unmarshal(body, &scheduled); err != nil {
		t.Fatalf("decode schedule: %v (%s)", err, body)
	}
	if scheduled.ID == "" || scheduled.NextRunAt.After(time.Now()) {
		t.Fatalf("schedule = %+v, want due schedule", scheduled)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules/run-due", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("run due scheduled rotations: status %d body %s", status, body)
	}
	var due secretRotationDueRunValue
	if err := json.Unmarshal(body, &due); err != nil {
		t.Fatalf("decode due run: %v (%s)", err, body)
	}
	if due.Ran != 1 || len(due.Runs) != 1 {
		t.Fatalf("due run = %+v, want exactly one run", due)
	}
	run := due.Runs[0]
	if run.ScheduleID != scheduled.ID || run.Status != "completed" || !run.Rotation.Completed || run.Rotation.NewRef == "" {
		t.Fatalf("scheduled run = %+v, want completed dual-phase rotation for schedule %s", run, scheduled.ID)
	}
	activeRef, activeSecret, err := publisher.ReadCredential(ctx, "db/reporting")
	if err != nil {
		t.Fatal(err)
	}
	if activeRef != run.Rotation.NewRef {
		t.Fatalf("active ref = %q, want scheduled new ref %q", activeRef, run.Rotation.NewRef)
	}
	assertPostgresCredentialWorks(t, ctx, activeSecret, "cap_secr_06_smoke")
	assertPostgresCredentialRevoked(t, ctx, oldSecret)

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotation-schedules", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list rotation schedules: status %d body %s", status, body)
	}
	var list struct {
		Items []secretRotationScheduleValue `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode schedule list: %v (%s)", err, body)
	}
	if len(list.Items) != 1 || list.Items[0].OldRef != run.Rotation.NewRef || list.Items[0].LastRunStatus != "completed" || !list.Items[0].NextRunAt.After(time.Now()) {
		t.Fatalf("schedule projection after run = %+v, want old_ref advanced and next run in future", list.Items)
	}
	if !h.hasEvent(t, "secret.rotation_schedule.upserted") || !h.hasEvent(t, "secret.rotation_schedule.ran") {
		t.Fatal("scheduled rotation did not emit schedule/run events")
	}
	if h.logContains(t, string(activeSecret)) || h.logContains(t, string(oldSecret)) {
		t.Fatal("scheduled rotation event log leaked PostgreSQL credential material")
	}
}

// TestServedSecretRotationCoversConnectorAndDynamicBackendsTRACE008 proves F37 is
// served beyond the native/static path: the same /api/v1/secrets/rotations endpoint
// rotates a connector-backed stored secret with rollback, and rotates a dynamic
// lease by issuing a replacement credential, delivering it to a configured connector,
// and revoking the old backend lease. Responses and event payloads stay metadata-only.
func TestServedSecretRotationCoversConnectorAndDynamicBackendsTRACE008(t *testing.T) {
	connector := newRotationCapturePusher()
	dynamicBackend := newRotationDynamicBackend()
	dynamicProvider := dynsecret.NewProvider("postgresql", dynamicBackend)

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.DynamicSecretProviders = []dynsecret.Provider{dynamicProvider}
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/connector", "value": "connector-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create connector source secret: status %d body %s", status, body)
	}
	connector.put("rotation/connector", []byte("connector-v1"))

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "connector:ci", "key": "rotation/connector", "old_ref": "version:1"})
	if status != http.StatusOK {
		t.Fatalf("connector rotation: status %d body %s", status, body)
	}
	var connectorRotated secretRotationValue
	if err := json.Unmarshal(body, &connectorRotated); err != nil {
		t.Fatalf("decode connector rotation: %v (%s)", err, body)
	}
	if !connectorRotated.Completed || connectorRotated.NewRef != "version:2" {
		t.Fatalf("connector rotation = %+v, want completed version:2", connectorRotated)
	}
	connectorValue := connector.value("rotation/connector")
	if connectorValue == "" || connectorValue == "connector-v1" {
		t.Fatalf("connector target value = %q, want a rotated value", connectorValue)
	}
	if strings.Contains(string(body), connectorValue) || h.logContains(t, connectorValue) || h.logContains(t, "connector-v1") {
		t.Fatal("connector rotation leaked secret material in response or event log")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "rotation/rollback", "value": "connector-rollback-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create rollback source secret: status %d body %s", status, body)
	}
	connector.put("rotation/rollback", []byte("connector-rollback-v1"))
	connector.failNext("rotation/rollback")
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{"provider": "connector:ci", "key": "rotation/rollback", "old_ref": "version:1"})
	if status != http.StatusConflict {
		t.Fatalf("connector rollback rotation: status %d body %s", status, body)
	}
	var connectorRolledBack secretRotationValue
	if err := json.Unmarshal(body, &connectorRolledBack); err != nil {
		t.Fatalf("decode connector rollback: %v (%s)", err, body)
	}
	if !connectorRolledBack.RollbackAttempted || !connectorRolledBack.RolledBack || connectorRolledBack.RollbackFailed || connectorRolledBack.FailedPhase != "cutover" {
		t.Fatalf("connector rollback = %+v, want successful rollback from cutover", connectorRolledBack)
	}
	if got := connector.value("rotation/rollback"); got != "connector-rollback-v1" {
		t.Fatalf("connector rollback target value = %q, want old value restored", got)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases", tok,
		map[string]any{"provider": "postgresql", "role": "readonly", "ttl_seconds": 600})
	if status != http.StatusCreated {
		t.Fatalf("issue initial dynamic lease: status %d body %s", status, body)
	}
	var initialLease dynamicLeaseValue
	if err := json.Unmarshal(body, &initialLease); err != nil {
		t.Fatalf("decode initial dynamic lease: %v (%s)", err, body)
	}
	if initialLease.ID == "" || initialLease.Credential == "" {
		t.Fatalf("initial lease = %+v, want one-time credential", initialLease)
	}
	connector.put("dynamic/readonly", []byte(initialLease.Credential))

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok,
		map[string]any{
			"provider":    "dynamic-lease:postgresql",
			"key":         "readonly",
			"old_ref":     initialLease.ID,
			"target":      "ci",
			"remote_key":  "dynamic/readonly",
			"ttl_seconds": 600,
		})
	if status != http.StatusOK {
		t.Fatalf("dynamic lease rotation: status %d body %s", status, body)
	}
	var dynamicRotated secretRotationValue
	if err := json.Unmarshal(body, &dynamicRotated); err != nil {
		t.Fatalf("decode dynamic rotation: %v (%s)", err, body)
	}
	if !dynamicRotated.Completed || dynamicRotated.NewRef == "" || dynamicRotated.NewRef == initialLease.ID {
		t.Fatalf("dynamic rotation = %+v, want completed replacement lease", dynamicRotated)
	}
	dynamicValue := connector.value("dynamic/readonly")
	if dynamicValue == "" || dynamicValue == initialLease.Credential {
		t.Fatalf("dynamic connector value = %q, want replacement credential", dynamicValue)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+initialLease.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get rotated old dynamic lease: status %d body %s", status, body)
	}
	var oldLease dynamicLeaseValue
	if err := json.Unmarshal(body, &oldLease); err != nil {
		t.Fatalf("decode rotated old dynamic lease: %v (%s)", err, body)
	}
	if oldLease.State != "revoked" || dynamicBackend.revokedCount() == 0 {
		t.Fatalf("old dynamic lease state=%q backend revoked count=%d, want revoked with backend revoke", oldLease.State, dynamicBackend.revokedCount())
	}
	if strings.Contains(string(body), dynamicValue) || h.logContains(t, dynamicValue) || h.logContains(t, initialLease.Credential) {
		t.Fatal("dynamic rotation leaked credential material in response or event log")
	}
	if !h.hasEvent(t, "secret.rotation.completed") || !h.hasEvent(t, "rotation.rolled_back") || !h.hasEvent(t, "dynsecret.lease.revoked") {
		t.Fatal("rotation audit evidence missing for connector/dynamic backends")
	}
}

type secretRotationValue struct {
	Key               string `json:"key"`
	OldRef            string `json:"old_ref"`
	NewRef            string `json:"new_ref"`
	Completed         bool   `json:"completed"`
	RolledBack        bool   `json:"rolled_back"`
	RollbackAttempted bool   `json:"rollback_attempted"`
	RollbackFailed    bool   `json:"rollback_failed"`
	FailedPhase       string `json:"failed_phase,omitempty"`
	Error             string `json:"error,omitempty"`
}

type secretRotationScheduleValue struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Key             string    `json:"key"`
	OldRef          string    `json:"old_ref"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	NextRunAt       time.Time `json:"next_run_at"`
	LastRunStatus   string    `json:"last_run_status"`
}

type secretRotationDueRunValue struct {
	Ran  int                              `json:"ran"`
	Runs []secretRotationScheduleRunValue `json:"runs"`
}

type secretRotationScheduleRunValue struct {
	ScheduleID string              `json:"schedule_id"`
	Status     string              `json:"status"`
	Rotation   secretRotationValue `json:"rotation"`
}

type dynamicLeaseValue struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Credential string `json:"credential,omitempty"`
}

type rotationCapturePusher struct {
	mu       sync.Mutex
	values   map[string][]byte
	failOnce map[string]bool
}

func newRotationCapturePusher() *rotationCapturePusher {
	return &rotationCapturePusher{values: map[string][]byte{}, failOnce: map[string]bool{}}
}

func (p *rotationCapturePusher) Push(_ context.Context, key string, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failOnce[key] {
		delete(p.failOnce, key)
		return errors.New("connector rejected rotated secret")
	}
	p.values[key] = append([]byte(nil), value...)
	return nil
}

func (p *rotationCapturePusher) put(key string, value []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.values[key] = append([]byte(nil), value...)
}

func (p *rotationCapturePusher) failNext(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failOnce[key] = true
}

func (p *rotationCapturePusher) value(key string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return string(p.values[key])
}

type rotationDynamicBackend struct {
	mu          sync.Mutex
	issued      int
	revokedRefs map[string]bool
}

func newRotationDynamicBackend() *rotationDynamicBackend {
	return &rotationDynamicBackend{revokedRefs: map[string]bool{}}
}

func (b *rotationDynamicBackend) Create(_ context.Context, role string) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.issued++
	ref := fmt.Sprintf("lease-%s-%d", role, b.issued)
	return ref, []byte(fmt.Sprintf("dynamic-secret-%d", b.issued)), nil
}

func (b *rotationDynamicBackend) Revoke(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revokedRefs[ref] = true
	return nil
}

func (b *rotationDynamicBackend) revokedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.revokedRefs)
}

func startRotationPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freeRotationPort(t)
	dir, err := os.MkdirTemp("/private/tmp", "trstctl-rotation-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := dir + "/bin"
	runtime := dir + "/runtime"
	data := dir + "/data"
	for _, p := range []string{bin, runtime, data} {
		if err := os.MkdirAll(p, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

func freeRotationPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func createRotationPostgresCredential(t *testing.T, ctx context.Context, adminDSN, username string) (string, []byte) {
	t.Helper()
	password := username + "_pass"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE ROLE "+rotationTestPGIdent(username)+" LOGIN PASSWORD "+rotationTestPGLiteral(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT CONNECT ON DATABASE postgres TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+rotationTestPGIdent(username)); err != nil {
		t.Fatal(err)
	}
	u := strings.Replace(adminDSN, "postgres:postgres@", username+":"+password+"@", 1)
	return username, []byte(u)
}

func assertPostgresCredentialWorks(t *testing.T, ctx context.Context, dsn []byte, smokeTable string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, string(dsn))
	if err != nil {
		t.Fatalf("credential did not log in: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var got int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.`+rotationTestPGIdent(smokeTable)).Scan(&got); err != nil {
		t.Fatalf("credential cannot read smoke table: %v", err)
	}
	if got != 1 {
		t.Fatalf("smoke count = %d, want 1", got)
	}
}

func assertPostgresCredentialRevoked(t *testing.T, ctx context.Context, dsn []byte) {
	t.Helper()
	if len(dsn) == 0 {
		t.Fatal("no credential supplied to revoked-login assertion")
	}
	conn, err := pgx.Connect(ctx, string(dsn))
	if err == nil {
		_ = conn.Close(ctx)
		t.Fatal("revoked PostgreSQL credential still logs in")
	}
}

func assertPostgresRoleAbsent(t *testing.T, ctx context.Context, adminDSN, role string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("staged rollback role %q still exists", role)
	}
}

func rotationTestPGIdent(v string) string {
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func rotationTestPGLiteral(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}
