// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The GitHub Action's contract with the served route (I3).
//
// The action is YAML the Go suite cannot execute, and the served test that
// proves the flow (internal/server github_action_served_test.go) sends the
// request itself. What CAN drift silently is the action file: a renamed field
// or moved route would break every consumer's workflow while both the server
// and its tests stayed green. These checks pin the action to the exact route,
// method name and field names the served contract uses — rename either side
// and this fails by name.
func TestGitHubActionMatchesTheServedContract(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../clients/github-action/action.yml")
	if err != nil {
		t.Fatalf("the published action is missing: %v", err)
	}
	action := string(raw)
	for _, want := range []string{
		// The route and method the served test drives.
		"/api/v1/workloads/attested-issuance",
		`--arg method "github_oidc"`,
		// The request fields, exactly as AttestedSVIDRequest names them.
		"payload_base64", "public_key_pem", "ttl_seconds",
		// The response field the certificate comes back in.
		"certificate_pem",
		// The OIDC acquisition: both request variables, and the audience.
		"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "audience=",
		// The failure that names its own fix.
		"permissions: id-token: write",
		// Idempotency: a re-run attempt must be a replay, not a second cert.
		"Idempotency-Key",
	} {
		if !strings.Contains(action, want) {
			t.Errorf("action.yml no longer carries %q; the action and the served route have drifted, "+
				"and every consumer's workflow breaks while the server's own tests stay green", want)
		}
	}
	// The private key must never travel. The only POST body is built by jq
	// from the public half; a key upload would defeat the action's whole
	// custody story.
	if strings.Contains(action, "key.pem\" | curl") || strings.Contains(action, "--data-binary @$TRSTCTL_OUT_DIR/key.pem") {
		t.Error("action.yml appears to send the private key; the key must never leave the runner")
	}

	readme, err := os.ReadFile("../clients/github-action/README.md")
	if err != nil {
		t.Fatalf("the action's README is missing: %v", err)
	}
	for _, want := range []string{
		// The sample workflow the acceptance names, with the permission that
		// makes it work and the scoped-token advice that makes it safe.
		"id-token: write", "certs:issue", "allowed_owners",
	} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README.md no longer documents %q; the sample workflow is the acceptance's own "+
				"wording and the scoped-token advice is what keeps the pipeline from becoming a CA admin", want)
		}
	}
}

func TestGitHubActionIsRerunStableForkClosedAndReleaseReadyAUD47(t *testing.T) {
	t.Parallel()
	actionRaw, err := os.ReadFile("../clients/github-action/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	action := string(actionRaw)
	if strings.Contains(action, "GITHUB_RUN_ATTEMPT") {
		t.Fatal("Action idempotency changes on a GitHub rerun; the same workflow run would mint again")
	}
	for _, want := range []string{"GITHUB_EVENT_PATH", "pull_request", ".head.repo.fork", "GITHUB_RUN_ID", "GITHUB_JOB", "GITHUB_ACTION"} {
		if !strings.Contains(action, want) {
			t.Errorf("action.yml missing AUD-47 trust/replay anchor %q", want)
		}
	}

	readmeRaw, err := os.ReadFile("../clients/github-action/README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeRaw)
	if strings.Contains(readme, "<owner>") || strings.Contains(readme, "@main") {
		t.Fatal("Action README still teaches a placeholder or mutable branch reference")
	}
	if !regexp.MustCompile(`uses: ctlplne/trstctl/clients/github-action@v[0-9]+\.[0-9]+\.[0-9]+`).MatchString(readme) {
		t.Fatal("Action README has no exact ctlplne/trstctl semantic-version reference")
	}

	workflow, err := os.ReadFile("../.github/workflows/github-action-conformance.yml")
	if err != nil {
		t.Fatalf("the real composite Action has no CI execution workflow: %v", err)
	}
	for _, want := range []string{"uses: ./clients/github-action", "id-token: write", "github-action-conformance"} {
		if !strings.Contains(string(workflow), want) {
			t.Errorf("GitHub Action conformance workflow missing %q", want)
		}
	}
	releaseRaw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"github-action-provenance", "trstctl-github-action-${GITHUB_REF_NAME}.tar.gz",
		"SHA256SUMS", "trstctl-github-action.intoto.jsonl", "--verify-tag",
	} {
		if !strings.Contains(string(releaseRaw), want) {
			t.Errorf("GitHub Action release supply chain missing %q", want)
		}
	}
}
