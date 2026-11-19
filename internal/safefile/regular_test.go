// SPDX-License-Identifier: BUSL-1.1

package safefile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/safefile"
)

func TestReadRegularFileChecksContainmentSizeAndCancellation(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	const filename = "fixture.txt"
	if err := os.WriteFile(filepath.Join(directory, filename), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := safefile.ReadRegularFile(t.Context(), root, filename, 7); err != nil || string(data) != "fixture" {
		t.Fatalf("read the exact size limit: %v", err)
	}
	if data, err := safefile.ReadRegularFile(t.Context(), root, filename, 6); !errors.Is(err, safefile.ErrFileLimit) || data != nil {
		t.Fatalf("read exceeded the limit: %v", err)
	}
	if _, err := safefile.ReadRegularFile(t.Context(), root, "../fixture.txt", 7); err == nil {
		t.Fatal("read accepted a name outside the opened root")
	}
	if _, err := safefile.ReadRegularFile(t.Context(), root, ".", 7); !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("read accepted a directory: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if data, err := safefile.ReadRegularFile(ctx, root, filename, 7); !errors.Is(err, context.Canceled) || data != nil {
		t.Fatalf("read ignored cancellation: %v", err)
	}
}
