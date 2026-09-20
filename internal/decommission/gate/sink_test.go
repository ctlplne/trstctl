// SPDX-License-Identifier: BUSL-1.1

package gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/eventspec"
)

// FileSink resumes its sequence from the refusal log already on disk, so a
// restart must not renumber refusal events from 1.
func TestFileSink_ResumesSequenceFromExistingLog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	first, err := NewRefusalSink(dir)
	if err != nil {
		t.Fatalf("NewRefusalSink: %v", err)
	}
	for i := range 2 {
		ev, err := first.Append(ctx, eventspec.Event{Type: "vdec.refused", TenantID: testTenant})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if want := uint64(i + 1); ev.Sequence != want {
			t.Fatalf("append %d sequence = %d, want %d", i, ev.Sequence, want)
		}
	}

	// A fresh sink over the same dir replays the log rather than restarting.
	second, err := NewRefusalSink(dir)
	if err != nil {
		t.Fatalf("NewRefusalSink reopen: %v", err)
	}
	ev, err := second.Append(ctx, eventspec.Event{Type: "vdec.refused", TenantID: testTenant})
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if ev.Sequence != 3 {
		t.Fatalf("sequence after reopen = %d, want 3", ev.Sequence)
	}
}

// An absent log is not an error: the first refusal starts the stream at 1.
func TestFileSink_MissingLogStartsAtOne(t *testing.T) {
	ctx := context.Background()
	sink, err := NewFileSink(filepath.Join(t.TempDir(), "nested", refusalLogFile))
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	ev, err := sink.Append(ctx, eventspec.Event{Type: "vdec.refused", TenantID: testTenant})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if ev.Sequence != 1 {
		t.Fatalf("sequence = %d, want 1", ev.Sequence)
	}
}

// The replay read goes through a directory handle, so a symlink standing in for
// the refusal log cannot redirect it outside the floor dir.
func TestFileSink_RefusesSymlinkedRefusalLog(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	if err := os.WriteFile(outside, []byte("{}\n{}\n"), 0o600); err != nil {
		t.Fatalf("write outside log: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, refusalLogFile)); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := NewRefusalSink(dir); err == nil {
		t.Fatal("NewRefusalSink accepted a symlinked refusal log, want error")
	}
}
