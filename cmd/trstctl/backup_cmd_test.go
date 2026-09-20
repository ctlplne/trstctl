// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_BackupRequiresExternalDatastores: trstctl --backup against the default
// (embedded) NATS fails fast, like serving does — a real backup targets the
// external event store an operator actually backs up, so a bundled-mode backup is
// rejected before it writes anything.
func TestRun_BackupRequiresExternalDatastores(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.jsonl")
	err := run(context.Background(), []string{"--backup=" + path}, emptyEnv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trstctl --backup with embedded NATS should fail fast (external datastores required)")
	}
}

func TestDRScriptsInvokeFullBackupRestoreFlags(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	fake := filepath.Join(dir, "trstctl-fake")
	if err := os.WriteFile(fake, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$TRSTCTL_FAKE_LOG\"\n"), 0o700); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write fake trstctl: %v", err)
	}

	backupDir := filepath.Join(dir, "artifact")
	for _, script := range []string{
		filepath.Join("..", "..", "scripts", "dr", "full-backup.sh"),
		filepath.Join("..", "..", "scripts", "dr", "full-restore.sh"),
	} {
		cmd := exec.Command("bash", script, backupDir) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		cmd.Env = append(os.Environ(), "TRSTCTL_BIN="+fake, "TRSTCTL_FAKE_LOG="+logPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", script, err, out)
		}
	}
	calls, err := os.ReadFile(logPath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read fake trstctl log: %v", err)
	}
	got := string(calls)
	for _, want := range []string{"--full-backup-dir=" + backupDir, "--full-restore-dir=" + backupDir} {
		if !strings.Contains(got, want) {
			t.Fatalf("DR scripts invoked:\n%s\nmissing %q", got, want)
		}
	}
}

// TestRestoreRehearsalUsesFreshExternalDatastores locks the operational truth
// behind OPS-RESTORE-001. Full backup deliberately rejects bundled stores, so
// the required CI drill must create independent external PostgreSQL and NATS
// instances for source, restore target, and corrupted-control target.
func TestRestoreRehearsalUsesFreshExternalDatastores(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "ci", "restore-rehearsal.sh")
	raw, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`POSTGRES_IMAGE="trstctl-postgres-hardened:local"`,
		`docker build -f "$REPO_ROOT/deploy/docker/Dockerfile.postgres" -t "$POSTGRES_IMAGE" "$REPO_ROOT"`,
		`--user postgres`,
		`NATS_IMAGE="trstctl-nats-hardened:local"`,
		`docker build -f "$REPO_ROOT/deploy/docker/Dockerfile.nats" -t "$NATS_IMAGE" "$REPO_ROOT"`,
		`"postgres": {"mode": "external", "dsn":`,
		`"nats": {"mode": "external", "url":`,
		`start_infra "$A_PG" "$A_NATS"`,
		`start_infra "$B_PG" "$B_NATS"`,
		`start_infra "$C_PG" "$C_NATS"`,
		`install -m 0600 "$ROOT/a/secrets-kek.bin" "$ROOT/b/secrets-kek.bin"`,
		`install -m 0600 "$ROOT/a/secrets-kek.bin" "$ROOT/c/secrets-kek.bin"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("restore rehearsal no longer requires %q", want)
		}
	}
	dockerRoot, err := os.OpenRoot(filepath.Join("..", "..", "deploy", "docker"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dockerRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	natsDockerfile, err := dockerRoot.ReadFile("Dockerfile.nats")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`COPY go.mod go.sum ./`,
		`-mod=readonly -trimpath -buildvcs=false`,
		`-o /out/nats-server github.com/nats-io/nats-server/v2`,
		`COPY --from=build /out/nats-server /usr/local/bin/nats-server`,
		`ENTRYPOINT ["/usr/local/bin/nats-server"]`,
	} {
		if !strings.Contains(string(natsDockerfile), want) {
			t.Errorf("restore rehearsal NATS must use the shipped dependency graph: missing %q", want)
		}
	}
	postgresDockerfile, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", "Dockerfile.postgres")) // #nosec G304 -- test reads a fixed repository artifact (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`FROM postgres:16.15-alpine@sha256:`,
		`RUN rm -f /usr/local/bin/gosu`,
		`USER postgres`,
	} {
		if !strings.Contains(string(postgresDockerfile), want) {
			t.Errorf("restore rehearsal hardened PostgreSQL build no longer requires %q", want)
		}
	}
}
