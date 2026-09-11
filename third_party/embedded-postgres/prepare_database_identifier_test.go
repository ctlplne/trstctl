//go:build unix

// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestCreateDatabaseKeepsExactIdentifier(t *testing.T) {
	archive := os.Getenv("TRSTCTL_TEST_PG_ARCHIVE")
	if archive == "" {
		t.Skip("set TRSTCTL_TEST_PG_ARCHIVE to a verified native PostgreSQL archive for the real database replay")
	}
	base := t.TempDir()
	binaries := filepath.Join(base, "binaries")
	if err := decompressTarXz(defaultTarReader, archive, binaries); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(base, "data")
	out, err := exec.Command(filepath.Join(binaries, "bin", "initdb"), "-D", data, "-U", "closeout_review", "-A", "trust", "--no-locale").CombinedOutput()
	if err != nil {
		t.Fatalf("private initdb: %v\n%s", err, out)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(base, "postgres.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(filepath.Join(binaries, "bin", "postgres"), "-D", data, "-h", "127.0.0.1,::1", "-p", fmt.Sprint(port), "-k", "", "-c", "fsync=off")
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned foreground PostgreSQL pid=%d port=%d data=%s", cmd.Process.Pid, port, data)
	t.Cleanup(func() {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Errorf("stop owned postgres: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("owned postgres exit: %v", err)
			} else {
				t.Log("owned PostgreSQL stopped and reaped")
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("owned postgres required forced termination")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var conn *pgx.Conn
	for ctx.Err() == nil {
		conn, err = pgx.Connect(ctx, fmt.Sprintf("host=127.0.0.1 port=%d user=closeout_review dbname=postgres sslmode=disable", port))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var version string
	if err := conn.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("real server version=%s", version)
	for _, name := range []string{"hv2_024_plain", `hv2_024_quote"inside`, `hv2_024_comment"--`} {
		t.Run(name, func(t *testing.T) {
			createErr := defaultCreateDatabase(uint32(port), "closeout_review", "fixture-only", name)
			var exact bool
			if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)", name).Scan(&exact); err != nil {
				t.Fatal(err)
			}
			var altered bool
			if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)", "hv2_024_comment").Scan(&altered); err != nil {
				t.Fatal(err)
			}
			t.Logf("actual helper requested=%q error=%v exact_name_exists=%v altered_name_exists=%v", name, createErr, exact, altered)
			if createErr != nil || !exact || altered {
				t.Errorf("helper did not create exactly its requested identifier")
			}
		})
	}
}
