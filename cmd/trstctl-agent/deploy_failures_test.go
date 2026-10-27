// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

// A192: an operator on the relay reads its failure log with
// --show-deploy-failures; the log sits beside --key unless
// --deploy-failure-log names it, and a Windows service restart keeps the flag.
func TestDeployFailureLogIsReadableOnTheRelayAndKeptAcrossServiceRestarts(t *testing.T) {
	dir := t.TempDir()
	if got := deployFailureLogPath("", filepath.Join(dir, "agent.key")); got != filepath.Join(dir, deployFailureLogFile) {
		t.Fatalf("default failure log = %s", got)
	}
	path := deployFailureLogPath(filepath.Join(dir, "failures.jsonl"), filepath.Join(dir, "agent.key"))
	var out bytes.Buffer
	if err := printDeployFailures(&out, path); err != nil || !strings.Contains(out.String(), "no failed deploys") {
		t.Fatalf("empty log = %q, %v", out.String(), err)
	}
	failures, err := relay.OpenDeployFailureLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := failures.Record(relay.DeployFailure{
		At: time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC), JobID: 41, Attempt: 2, Connector: "f5", Target: "edge-f5",
		Step: relay.DeployStepConnector, Reason: "connector deploy failed against the target: 401",
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := printDeployFailures(&out, path); err != nil ||
		out.String() != "2026-10-27T09:30:00Z job 41 attempt 2: f5 deploy to edge-f5 failed at the connector step: connector deploy failed against the target: 401\n" {
		t.Fatalf("printed log = %q, %v", out.String(), err)
	}
	args := serviceArguments(agentOptions{relayClaim: true, deployFailureLog: path})
	kept := false
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--deploy-failure-log" && args[i+1] == path {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("Windows service restart would lose the deploy failure log path: %v", args)
	}
}
