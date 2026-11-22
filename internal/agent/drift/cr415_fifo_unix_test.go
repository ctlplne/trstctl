// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package drift_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/safefile"
)

func TestCR415FIFORefusedWithoutBlockingWorker(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "watched-fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := drift.ApprovedRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = drift.DetectConfined(ctx, roots, []drift.Watched{{Path: path, Class: "certificate", Fingerprint: "digest"}})
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("FIFO read = %v, want nonblocking regular-file refusal", err)
	}
}
