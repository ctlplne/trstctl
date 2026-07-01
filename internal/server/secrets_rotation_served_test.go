package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/rotation"
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
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin))
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
