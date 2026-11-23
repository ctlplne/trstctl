// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package hostsource_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
)

func TestCR418HostGlobStaysInsideRootAndSkipsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	good := filepath.Join(root, "tls.conf")
	if err := os.WriteFile(good, []byte("ssl_protocols TLSv1.3;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(outside, "private.conf")
	if err := os.WriteFile(private, []byte("ssl_protocols TLSv1.0;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, filepath.Join(root, "linked.conf")); err != nil {
		t.Fatal(err)
	}
	internalLink := filepath.Join(root, "internal-link.conf")
	if err := os.Symlink(good, internalLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "stalled.conf")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type outcome struct {
		findings []cbom.Finding
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		findings, err := hostsource.New(good, private, filepath.Join(root, "*.conf"), internalLink, fifo, filepath.Join(fifo, "*.conf")).
			WithAllowedRoots(root).WithPackageDatabases().Scan(ctx)
		done <- outcome{findings, err}
	}()
	select {
	case got := <-done:
		var partial *cbom.PartialScanError
		if !errors.As(got.err, &partial) || partial.Failures < 2 {
			t.Fatalf("unsafe selectors error=%v; want visible partial failures", got.err)
		}
		for _, finding := range got.findings {
			if finding.Protocol != "TLSv1.3" || finding.Location != good {
				t.Fatalf("escaped or special-file finding: %+v", finding)
			}
		}
	case <-ctx.Done():
		t.Fatal("host scan blocked on a FIFO")
	}
}

func TestCR418PinnedRootRefusesDirectoryReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "approved")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tls.conf")
	if err := os.WriteFile(path, []byte("ssl_protocols TLSv1.3;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := hostsource.New(path).WithAllowedRoots(root).
		WithPinnedRoots(map[string]os.FileInfo{canonicalRoot: info})
	if findings, err := source.Scan(context.Background()); err != nil || len(findings) != 1 {
		t.Fatalf("pinned root before replacement findings=%v err=%v", findings, err)
	}
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "tls.conf"), []byte("ssl_protocols TLSv1.0;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	findings, err := source.Scan(context.Background())
	var partial *cbom.PartialScanError
	if !errors.As(err, &partial) || len(findings) != 0 {
		t.Fatalf("replaced root yielded findings=%v err=%v; want fail-closed partial", findings, err)
	}
}
