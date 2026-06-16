package projections_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/store"
)

// mintToken creates an API token for the tenant with the given scopes and
// returns the raw token to present.
func mintToken(t *testing.T, s *store.Store, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: tenantA, TokenHash: hash, Subject: "ci-bot", Scopes: scopes,
	}); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	return raw
}

func runCLI(t *testing.T, env cli.Env, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := cli.Run(context.Background(), args, env, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// TestCLICreateAndListAgainstRealAPI is the S7.1 end-to-end acceptance: the CLI
// drives the real API over HTTP, authenticating with a CI-style API token, and
// its scriptable output reflects the operation.
func TestCLICreateAndListAgainstRealAPI(t *testing.T) {
	srv, s := newGraphAPI(t)
	token := mintToken(t, s, "owners:write", "owners:read")
	env := cli.Env{Server: srv.URL, Token: token, HTTPClient: srv.Client()}

	// Create an owner from a JSON body on stdin.
	code, out, errOut := runCLI(t, env, `{"kind":"workload","name":"cli-svc"}`, "owners", "create", "-f", "-")
	if code != 0 {
		t.Fatalf("create exit = %d: %s", code, errOut)
	}
	if !strings.Contains(out, "cli-svc") {
		t.Errorf("create output missing the owner: %s", out)
	}

	// List owners — the created one is present in the scriptable output.
	code, out, errOut = runCLI(t, env, "", "owners", "list")
	if code != 0 {
		t.Fatalf("list exit = %d: %s", code, errOut)
	}
	if !strings.Contains(out, "cli-svc") {
		t.Errorf("list output missing the created owner: %s", out)
	}
}

// TestCLITokenScopeEnforced proves CI-friendly auth carries the token's scopes:
// a token without owners:write cannot create an owner, and the CLI exits
// non-zero.
func TestCLITokenScopeEnforced(t *testing.T) {
	srv, s := newGraphAPI(t)
	token := mintToken(t, s, "owners:read") // read-only
	env := cli.Env{Server: srv.URL, Token: token, HTTPClient: srv.Client()}

	code, _, errOut := runCLI(t, env, `{"kind":"workload","name":"nope"}`, "owners", "create", "-f", "-")
	if code == 0 {
		t.Error("create with a read-only token should fail")
	}
	if !strings.Contains(errOut, "403") {
		t.Errorf("expected a 403 in stderr, got: %s", errOut)
	}
}

// TestCLIUnknownTokenRejected: an unrecognized token is a 401.
func TestCLIUnknownTokenRejected(t *testing.T) {
	srv, _ := newGraphAPI(t)
	env := cli.Env{Server: srv.URL, Token: "trstctl_pat_bogus", HTTPClient: srv.Client()}
	code, _, _ := runCLI(t, env, "", "owners", "list")
	if code == 0 {
		t.Error("an unknown token should fail")
	}
}
