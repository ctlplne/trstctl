// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto/secret"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// CR-596: run with a disposable MySQL 8.4 administrator DSN and a disposable
// database. The actual server general log, not a mocked SQL call, must contain
// no generated lease password even when statement recording is enabled.
func TestCR596MySQLGeneralLogNeverRecordsLeasePassword(t *testing.T) {
	testCR596GeneralLogNeverRecordsLeasePassword(t, "TRSTCTL_CR596_MYSQL_DSN")
}

func TestCR596MariaDBGeneralLogNeverRecordsLeasePassword(t *testing.T) {
	testCR596GeneralLogNeverRecordsLeasePassword(t, "TRSTCTL_CR596_MARIADB_DSN")
}

func testCR596GeneralLogNeverRecordsLeasePassword(t *testing.T, envName string) {
	t.Helper()
	dsn := os.Getenv(envName)
	if dsn == "" {
		t.Skip("set " + envName + " to an isolated MySQL or MariaDB test database")
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	adminConfig, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	var priorLog int
	var priorOutput string
	if err := db.QueryRowContext(ctx, `SELECT @@GLOBAL.general_log, @@GLOBAL.log_output`).Scan(&priorLog, &priorOutput); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `SET GLOBAL general_log = ?`, priorLog)
		_, _ = db.ExecContext(context.Background(), `SET GLOBAL log_output = ?`, priorOutput)
	})
	if _, err := db.ExecContext(ctx, `SET GLOBAL log_output = 'TABLE'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `SET GLOBAL general_log = ON`); err != nil {
		t.Fatal(err)
	}
	backend, err := NewMySQLBackend(db, MySQLConfig{Database: "cr596", Addr: adminConfig.Addr,
		AccountHost: "%", AllowWildcardAccountHost: true, UsernamePrefix: "trstctl_cr596"})
	if err != nil {
		t.Fatal(err)
	}
	ref, credential, err := backend.CreateCredential(ctx, GenerateRequest{Role: "readonly"})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	defer func() { _ = backend.Revoke(context.Background(), ref) }()
	colon := bytes.IndexByte(credential, ':')
	end := bytes.Index(credential, []byte("@tcp("))
	if colon < 0 || end <= colon+1 {
		t.Fatal("MySQL lease credential has no password")
	}
	password := append([]byte(nil), credential[colon+1:end]...)
	defer secret.Wipe(password)
	if _, err := db.ExecContext(ctx, `SET GLOBAL general_log = OFF`); err != nil {
		t.Fatal(err)
	}
	var leaked int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM mysql.general_log WHERE LOCATE(?, argument) > 0 AND command_type IN ('Query', 'Execute')`,
		password).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("MySQL general log contains the issued lease password in %d statements", leaked)
	}
	workload, err := sql.Open("mysql", string(credential))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = workload.Close() }()
	if err := workload.PingContext(ctx); err != nil {
		t.Fatalf("the server-generated password cannot log in: %v", err)
	}
}

func TestCR596PostgresStatementLogNeverRecordsLeasePassword(t *testing.T) {
	ctx := context.Background()
	port := freeDynsecretPort(t)
	root, err := os.MkdirTemp(dynsecretShortTempRoot(), "trstctl-cr596-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	for _, subdir := range []string{"bin", "runtime", "data", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, subdir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(filepath.Join(root, "runtime")).DataPath(filepath.Join(root, "data")).
		BinariesPath(filepath.Join(root, "bin")).StartParameters(map[string]string{
		"logging_collector": "on", "log_destination": "stderr", "log_directory": filepath.Join(root, "logs"),
		"log_filename": "cr596.log", "log_statement": "all", "log_parameter_max_length": "-1",
	})) // #nosec G115 -- port is returned by a TCP listener and bounded to 16 bits (CWE-190)
	if err := db.Start(); err != nil {
		t.Fatalf("start isolated PostgreSQL statement-log fixture: %v", err)
	}
	t.Cleanup(func() { _ = db.Stop() })
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	password := []byte("Cr596PostgresCanary7qX2")
	defer secret.Wipe(password)
	if err := createPostgresRole(ctx, conn, "trstctl_cr596_pg", password, "infinity"); err != nil {
		t.Fatal(err)
	}
	rotated := []byte("Cr596PostgresRotated9rT4")
	defer secret.Wipe(rotated)
	if err := setPostgresRolePassword(ctx, conn, "trstctl_cr596_pg", rotated); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "logs", "cr596.log")
	var log []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log, err = os.ReadFile(logPath) // #nosec G304 -- fixed log filename inside this test's exclusively created temporary directory (CWE-22)
		if err == nil && bytes.Contains(log, []byte("trstctl.dynamic_secret_password")) && bytes.Contains(log, []byte("ALTER ROLE")) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil || !bytes.Contains(log, []byte("trstctl.dynamic_secret_password")) || !bytes.Contains(log, []byte("ALTER ROLE")) {
		t.Fatalf("PostgreSQL statement log did not capture create and rotate paths: %v", err)
	}
	for _, candidate := range [][]byte{password, rotated} {
		if bytes.Contains(log, candidate) || bytes.Contains(log, []byte(hex.EncodeToString(candidate))) {
			t.Fatal("PostgreSQL statement log contains a create/rotate password or its bound bytea hex")
		}
	}
}
