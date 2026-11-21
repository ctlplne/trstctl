// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dockerFixtureOutput(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	command.WaitDelay = time.Second
	out, err := command.CombinedOutput()
	if cause := ctx.Err(); cause != nil {
		return out, cause
	}
	return out, err
}

func dockerFixtureTimedOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	out, err := dockerFixtureOutput(ctx, args...)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("docker %s exceeded its %s operation deadline: %v; the daemon may be unresponsive", strings.Join(args, " "), timeout, err)
	}
	return out, err
}

func dockerFixtureCleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = dockerFixtureOutput(ctx, args...)
}

func TestDockerFixtureCommandHonorsCancellation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(dir, "docker")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TRSTCTL_DOCKER_FIXTURE_HELPER", "1")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = dockerFixtureOutput(ctx, "-test.run=^TestDockerFixtureCommandHelper$")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unresponsive process did not report its deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("unresponsive process exceeded cancellation bound: %s", elapsed)
	}
}

func TestDockerFixtureCommandHelper(t *testing.T) {
	if os.Getenv("TRSTCTL_DOCKER_FIXTURE_HELPER") != "1" {
		return
	}
	// The parent must terminate this child before the sleep completes.
	time.Sleep(5 * time.Second)
}

func TestDockerFixtureCommandRefusesExpiredContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dockerFixtureOutput(ctx, "version"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Docker operation was not refused: %v", err)
	}
}
