package main

import (
	"context"
	"io"
	"testing"
)

// TestRun_MigrateStatusRequiresExternalDatastore: trstctl --migrate-status
// against the default (bundled) Postgres fails fast — migrations are an
// operation against the external datastore an operator manages, so the bundled
// single-node path is rejected rather than touching an embedded store.
func TestRun_MigrateStatusRequiresExternalDatastore(t *testing.T) {
	err := run(context.Background(), []string{"--migrate-status"}, emptyEnv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trstctl --migrate-status with bundled Postgres should fail fast (external datastore required)")
	}
}

// TestRun_MigrateRequiresExternalDatastore: likewise, applying migrations
// explicitly requires the external Postgres.
func TestRun_MigrateRequiresExternalDatastore(t *testing.T) {
	err := run(context.Background(), []string{"--migrate"}, emptyEnv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trstctl --migrate with bundled Postgres should fail fast (external datastore required)")
	}
}
