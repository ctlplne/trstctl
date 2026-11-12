// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// TestServedUpgradePreflightIsOneVerdictForPipelinesAndTheConsoleA246L1 is
// A246-L1. The upgrade preflight a pipeline runs (`trstctl --upgrade-preflight
// --upgrade-preflight-format json`) and the one the console reads
// (GET /api/v1/platform/upgrade-preflight, `trstctl-cli platform
// upgrade-preflight`) are the same verdict in the same JSON form: against a
// database at this binary's version, ready, nothing to apply, rolled back by
// running the previous binary, every list present.
func TestServedUpgradePreflightIsOneVerdictForPipelinesAndTheConsoleA246L1(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "A246-L1 upgrade preflight tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "access:read")
	now := time.Now()

	// What the binary's preflight writes for a pipeline.
	verdict, err := RunUpgradePreflight(t.Context(), &config.Config{Postgres: config.Postgres{Mode: config.PostgresExternal, DSN: serverTestPostgresDSN(t)}}, nil, now)
	if err != nil {
		t.Fatalf("run the preflight against the test database: %v", err)
	}
	// The JSON form a pipeline reads is the verdict's own encoding.
	var pipeline bytes.Buffer
	if err := json.NewEncoder(&pipeline).Encode(verdict); err != nil {
		t.Fatal(err)
	}
	type doc struct {
		Format        string            `json:"format"`
		Ready         bool              `json:"ready"`
		SchemaVersion int64             `json:"schema_version"`
		BinaryVersion int64             `json:"binary_version"`
		Pending       []json.RawMessage `json:"pending"`
		Blockers      []json.RawMessage `json:"blockers"`
		Rollback      struct {
			Method string `json:"method"`
		} `json:"rollback"`
	}
	read := func(stage string, raw []byte) doc {
		t.Helper()
		var d doc
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s: %v (%s)", stage, err, raw)
		}
		if d.Format != "trstctl.upgrade-preflight.v1" || !d.Ready || d.SchemaVersion == 0 || d.SchemaVersion != d.BinaryVersion ||
			d.Pending == nil || len(d.Pending) != 0 || d.Blockers == nil || len(d.Blockers) != 0 || d.Rollback.Method != "none" {
			t.Fatalf("%s: a database at this binary's version reads %+v (%s)", stage, d, raw)
		}
		return d
	}
	fromBinary := read("the binary's JSON form", pipeline.Bytes())

	// The console's route reads the same verdict from the running process.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/platform/upgrade-preflight", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/platform/upgrade-preflight: %d %s", status, raw)
	}
	fromAPI := read("the served route", raw)
	if fromAPI.SchemaVersion != fromBinary.SchemaVersion || fromAPI.BinaryVersion != fromBinary.BinaryVersion {
		t.Fatalf("the route reads schema %d/%d, the binary %d/%d", fromAPI.SchemaVersion, fromAPI.BinaryVersion, fromBinary.SchemaVersion, fromBinary.BinaryVersion)
	}

	// And the CLI prints it.
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", tok, "--tenant", h.tenant,
		"platform", "upgrade-preflight"}, cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl-cli platform upgrade-preflight: %s%s", stdout.String(), stderr.String())
	}
	read("the CLI", stdout.Bytes())
	t.Logf("A246L1_PREFLIGHT_OK schema=%d binary=%d", fromAPI.SchemaVersion, fromAPI.BinaryVersion)
}
