// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package sshdiscovery_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"trstctl.com/trstctl/internal/agent/sshdiscovery"
)

func TestDiscoverSkipsFIFOAndSymlinkInUserGlob(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.pub")
	write(t, valid, edPub+"\n")
	userDir := filepath.Join(root, "user")
	if err := os.Mkdir(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(userDir, "blocked.pub")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(valid, filepath.Join(userDir, "linked.pub")); err != nil {
		t.Fatal(err)
	}
	src := sshdiscovery.New(sshdiscovery.Config{UserKeyGlobs: []string{filepath.Join(userDir, "*.pub")}})
	done := make(chan int, 1)
	go func() {
		found, _ := src.Discover(context.Background())
		done <- len(found)
	}()
	select {
	case count := <-done:
		if count != 0 {
			t.Fatalf("user-controlled FIFO/symlink produced %d inventory rows", count)
		}
	case <-time.After(500 * time.Millisecond):
		// Wake a vulnerable FIFO reader so this failed regression does not leak
		// a blocked goroutine into the next test.
		writer, err := os.OpenFile(fifo, os.O_WRONLY|unix.O_NONBLOCK, 0) // #nosec G304 -- test-owned FIFO fixture opened only to unblock a failed regression
		if err == nil {
			_ = writer.Close()
		}
		t.Fatal("SSH discovery blocked on a user-controlled FIFO")
	}
}

func TestDiscoverSkipsOversizedRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.pub")
	file, err := os.Create(path) // #nosec G304 -- test fixture in an owned temp directory
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(edPub + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(2 << 20); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	findings, err := sshdiscovery.New(sshdiscovery.Config{UserKeyGlobs: []string{path}}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("oversized regular file produced %d inventory rows", len(findings))
	}
}

func TestDiscoverHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sshdiscovery.New(sshdiscovery.Config{}).Discover(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover error = %v, want canceled context", err)
	}
}

func TestTrustPostureHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sshdiscovery.New(sshdiscovery.Config{SSHDConfigPaths: []string{filepath.Join(t.TempDir(), "sshd_config")}}).TrustPostureContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TrustPostureContext error = %v, want canceled context", err)
	}
}
