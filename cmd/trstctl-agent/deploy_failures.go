// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

// deployFailureLogFile is the relay's failure log beside --key when
// --deploy-failure-log is not set (A192).
const deployFailureLogFile = "deploy-failures.jsonl"

// deployFailureLogPath is where this relay keeps its newest failed deploys.
func deployFailureLogPath(flagValue, keyPath string) string {
	if path := strings.TrimSpace(flagValue); path != "" {
		return path
	}
	return filepath.Join(filepath.Dir(keyPath), deployFailureLogFile)
}

// printDeployFailures writes the relay's failure log for an operator on this
// host: when, which job and attempt, which connector and target, the step that
// failed and the scrubbed reason, oldest first.
func printDeployFailures(w io.Writer, path string) error {
	entries, err := relay.ReadDeployFailures(path)
	if err != nil {
		return fmt.Errorf("read deploy failure log %s: %w", path, err)
	}
	if len(entries) == 0 {
		_, err := fmt.Fprintf(w, "no failed deploys are recorded in %s\n", path)
		return err
	}
	for _, e := range entries {
		what := "deploy"
		if e.Connector != "" {
			what = e.Connector + " deploy to " + e.Target
		}
		if _, err := fmt.Fprintf(w, "%s job %d attempt %d: %s failed at the %s step: %s\n",
			e.At.UTC().Format(time.RFC3339), e.JobID, e.Attempt, what, e.Step, e.Reason); err != nil {
			return err
		}
	}
	return nil
}
