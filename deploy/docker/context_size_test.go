// SPDX-License-Identifier: MPL-2.0

package docker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func contextSize(t *testing.T, directory string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "../../scripts/ci/docker-context-size.sh", directory) // #nosec G204 -- fixed repository script; the test-owned directory is a separate argv value, never shell code (CWE-78).
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func sparseContext(t *testing.T, size int64) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "payload with spaces")) // #nosec G304 -- fixed filename below this test's private t.TempDir (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDockerContextSizeCountsSparseContentAndArchiveOverhead(t *testing.T) {
	const contentBytes = 63 * 1024 * 1024
	out, err := contextSize(t, sparseContext(t, contentBytes))
	if err != nil {
		t.Fatalf("below-limit context rejected: %v: %s", err, out)
	}
	kib, err := strconv.ParseInt(out, 10, 64)
	if err != nil || kib*1024 <= contentBytes || kib > 64*1024 {
		t.Fatalf("size %q must include sparse file data plus archive headers within64MiB", out)
	}
}

func TestDockerContextSizeRejectsOversizedSparseContent(t *testing.T) {
	out, err := contextSize(t, sparseContext(t, 64*1024*1024))
	if err == nil || !strings.Contains(out, "limit is 67108864 bytes") {
		t.Fatalf("64MiB data plus archive headers must exceed the unchanged ceiling: %v: %s", err, out)
	}
}

func TestDockerContextSizeIgnoresInheritedTarOptions(t *testing.T) {
	const contentBytes = 63 * 1024 * 1024
	dir := sparseContext(t, contentBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "../../scripts/ci/docker-context-size.sh", dir) // #nosec G204 -- fixed repository script; the test-owned directory is a separate argv value, never shell code (CWE-78).
	cmd.Env = append(os.Environ(), "TAR_OPTIONS=--exclude=*", "TAR_READER_OPTIONS=invalid-option", "TAR_WRITER_OPTIONS=gzip:compression-level=9")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ambient tar options changed the fixed measurement: %v: %s", err, out)
	}
	kib, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || kib*1024 <= contentBytes || kib > 64*1024 {
		t.Fatalf("ambient options omitted or compressed context content: %q", out)
	}
}

func TestDockerContextSizeRejectsMissingSource(t *testing.T) {
	out, err := contextSize(t, filepath.Join(t.TempDir(), "absent"))
	if err == nil || !strings.Contains(out, "expected one exported context directory") {
		t.Fatalf("missing context accepted: %v: %s", err, out)
	}
}

func TestDockerContextSizePropagatesArchiveFailure(t *testing.T) {
	dir := t.TempDir()
	// This component exceeds the portable ustar name field; the producer must
	// fail. wc succeeding on its captured prefix must never turn that into PASS.
	if err := os.WriteFile(filepath.Join(dir, strings.Repeat("x", 101)), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := contextSize(t, dir)
	if err == nil {
		t.Fatalf("unsupported archive entry silently accepted: %s", out)
	}
}
