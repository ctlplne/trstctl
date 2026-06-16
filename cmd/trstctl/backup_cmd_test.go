package main

import (
	"context"
	"io"
	"path/filepath"
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
