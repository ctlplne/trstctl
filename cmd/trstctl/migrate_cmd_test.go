// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"io"
	"strings"
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

// TestRun_UpgradePreflightRequiresExternalDatastore: the preflight reads the
// external datastore an operator manages, so the bundled path is rejected.
func TestRun_UpgradePreflightRequiresExternalDatastore(t *testing.T) {
	err := run(context.Background(), []string{"--upgrade-preflight"}, emptyEnv, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("trstctl --upgrade-preflight with bundled Postgres should fail fast (external datastore required)")
	}
}

// TestRun_UpgradePreflightFormatIsTextOrJSON: the preflight prints text for an
// operator or JSON for a pipeline (A246-L1); any other format is refused
// before anything is read.
func TestRun_UpgradePreflightFormatIsTextOrJSON(t *testing.T) {
	err := run(context.Background(), []string{"--upgrade-preflight", "--upgrade-preflight-format", "yaml"}, emptyEnv, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "text or json") {
		t.Fatalf("an unknown preflight format = %v, want it refused", err)
	}
	err = run(context.Background(), []string{"--upgrade-preflight", "--upgrade-preflight-format", "json"}, emptyEnv, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), "text or json") {
		t.Fatalf("the json format = %v, want it accepted (and the bundled datastore refused)", err)
	}
}
