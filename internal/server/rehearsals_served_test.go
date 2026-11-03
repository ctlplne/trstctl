// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// A247: a run records the tool and connector versions, the candidate, the data
// set, the expected actions and what it observed; a mocked success is labeled
// mocked, never live; a run is a game day (incidents:game-day); a static
// preview diverges on configuration that does not resolve.
func TestServedRehearsalsRecordWhatTheyReplayedA247(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	author := seedScopedTokenSubject(t, h.store, h.tenant, "scenario-author", "incidents:read", "incidents:write", "connectors:write")
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "game-day-lead", "incidents:read", "incidents:game-day")

	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/connectors/targets", author, "a247-target", map[string]any{
		"name": "a247/staging-lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a247.internal", "partition": "Common", "environment": "staging"},
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create target = %d %s", code, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("target: %s", body)
	}

	scenario := map[string]any{
		"name": "An unreachable load balancer", "kind": "target_outage",
		"candidate": map[string]any{"kind": "target", "ref": target.ID},
		"data_set":  map[string]any{"kind": "scrubbed_failure", "failure": map[string]any{"source": "outbox_dead_letter", "ref": "dl-1", "code": "connect_timeout"}},
		"steps": []map[string]any{
			{"action": "deliver_to_unreachable_target", "target": target.ID, "expect": "retried_with_backoff"},
			{"action": "exhaust_retries", "target": target.ID, "expect": "dead_lettered_and_alerted"},
		},
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/rehearsals/scenarios", author, "a247-save", scenario)
	if code != http.StatusCreated {
		t.Fatalf("save scenario = %d %s", code, body)
	}
	var saved struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(body, &saved); err != nil || saved.ID == "" || saved.Revision != 1 {
		t.Fatalf("saved scenario: %s", body)
	}
	runs := "/api/v1/rehearsals/scenarios/" + saved.ID + "/runs"

	// A run is a game day: the author cannot start one.
	if code, body := secretsReqKey(t, h, http.MethodPost, runs, author, "a247-run-author", map[string]any{"mode": "mocked_rehearsal"}); code != http.StatusForbidden {
		t.Fatalf("a run without incidents:game-day = %d %s", code, body)
	}

	type run struct {
		ID                string            `json:"id"`
		Mode              string            `json:"mode"`
		Status            string            `json:"status"`
		Verdict           string            `json:"verdict"`
		Label             string            `json:"label"`
		ToolVersion       string            `json:"tool_version"`
		ConnectorVersions map[string]string `json:"connector_versions"`
		Candidate         map[string]string `json:"candidate"`
		DataSetDigest     string            `json:"data_set_digest"`
		Expected          []map[string]any  `json:"expected"`
		Observations      []struct {
			Step   int    `json:"step"`
			Effect string `json:"effect"`
			Source string `json:"source"`
		} `json:"observations"`
		Detail string `json:"detail"`
	}
	start := func(key, mode string) (int, run) {
		t.Helper()
		code, body := secretsReqKey(t, h, http.MethodPost, runs, lead, key, map[string]any{"mode": mode})
		var out run
		if code == http.StatusCreated {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("run %s: %s", mode, body)
			}
		}
		return code, out
	}

	code, mocked := start("a247-run-mocked", "mocked_rehearsal")
	if code != http.StatusCreated || mocked.Status != "completed" || mocked.Verdict != "matched" || mocked.Label != "mocked: matched" {
		t.Fatalf("mocked run = %d %+v", code, mocked)
	}
	if mocked.ToolVersion != buildinfo.Version() || mocked.ConnectorVersions["f5"] != buildinfo.Version() ||
		mocked.Candidate["ref"] != target.ID || !strings.HasPrefix(mocked.DataSetDigest, "sha256:") || len(mocked.Expected) != 2 {
		t.Fatalf("the run does not record what it replayed: %+v", mocked)
	}
	for _, o := range mocked.Observations {
		if o.Source != "mock" {
			t.Fatalf("a mocked run recorded a %s observation", o.Source)
		}
	}
	// The same key replays the same run.
	if _, again := start("a247-run-mocked", "mocked_rehearsal"); again.ID != mocked.ID {
		t.Fatalf("a retried run started another: %s vs %s", again.ID, mocked.ID)
	}

	code, preview := start("a247-run-preview", "static_preview")
	if code != http.StatusCreated || preview.Label != "preview: matched" {
		t.Fatalf("static preview against existing configuration = %d %+v", code, preview)
	}

	// Revised to act on a target that does not exist: the preview diverges.
	scenario["steps"] = []map[string]any{{"action": "deliver_to_unreachable_target", "target": "2a470000-0000-4000-8000-000000000001", "expect": "retried_with_backoff"}}
	if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/rehearsals/scenarios/"+saved.ID, author, "a247-revise", scenario); code != http.StatusOK || !strings.Contains(string(body), `"revision":2`) {
		t.Fatalf("revise = %d %s", code, body)
	}
	code, diverged := start("a247-run-preview-2", "static_preview")
	if code != http.StatusCreated || diverged.Label != "preview: diverged" || !strings.Contains(diverged.Detail, "does not exist") {
		t.Fatalf("static preview against a missing target = %d %+v", code, diverged)
	}

	// A sandbox replay reads each target's environment from its record; a
	// target that no longer exists has none, and the replay is refused.
	if code, _ := start("a247-run-sandbox", "sandbox_execution"); code != http.StatusUnprocessableEntity {
		t.Fatalf("sandbox execution against a missing target = %d; want 422", code)
	}

	// The CLI lists the scenario's runs, newest first, with their labels.
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", lead, "--tenant", h.tenant, "rehearsals", "runs", "list", saved.ID},
		cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl rehearsals runs list: %s%s", stdout.String(), stderr.String())
	}
	for _, want := range []string{"mocked: matched", "preview: matched", "preview: diverged"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the CLI's run list does not show %q: %s", want, stdout.String())
		}
	}
	if !h.hasEvent(t, "rehearsal.run.completed") {
		t.Fatal("no rehearsal.run.completed event was appended")
	}
}
