// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestShippedGitHubActionPreservesAnExistingRunnerKey(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// Deliberately not a usable key or credential. The Action must refuse the
	// occupied slot before replacing bytes or attempting the unavailable origin.
	sentinel := []byte("A232 existing runner key slot; preserve its bytes\n")
	file, err := root.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(sentinel); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	event, err := root.OpenFile("push.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := event.Write([]byte(`{"repository":{"full_name":"acme/payments"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := event.Close(); err != nil {
		t.Fatal(err)
	}
	_, runErr := runShippedGitHubActionAUD47(t, shippedGitHubActionScriptAUD47(t), []string{
		"TRSTCTL_URL=http://127.0.0.1:1", "TRSTCTL_TOKEN=deliberately-unusable", "TRSTCTL_OUT_DIR=" + dir,
		"TRSTCTL_AUDIENCE=trstctl", "TRSTCTL_TTL_SECONDS=600", "GITHUB_RUN_ID=23201", "GITHUB_RUN_ATTEMPT=1",
		"GITHUB_JOB=issue", "GITHUB_ACTION=trstctl", "GITHUB_EVENT_NAME=push", "GITHUB_EVENT_PATH=" + filepath.Join(dir, "push.json"),
		"ACTIONS_ID_TOKEN_REQUEST_URL=http://127.0.0.1:1?request=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=deliberately-unusable",
		"GITHUB_OUTPUT=" + filepath.Join(dir, "github-output"),
	})
	if runErr == nil {
		t.Fatal("Action accepted a pre-existing runner key slot")
	}
	retained, err := root.Open("key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retained.Close() }()
	got, err := io.ReadAll(io.LimitReader(retained, 4096))
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("Action overwrote an existing runner key before its repeat request was refused")
	}
}
