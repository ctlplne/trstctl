// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

// P6-L7: the move names the place the value is re-found in by the finding's
// origin. A finding trstctl collected from a provider itself has no export
// to look in, so it is refused with the reason; a third-party finding needs
// --export and a repository finding --repo; --repo and --export together
// are a usage error. Nothing is stored in any of these cases.
func TestSecretScanMoveNamesWhereTheValueIsP6L7(t *testing.T) {
	finding := map[string]string{
		"collected":  `{"id":"f-1","kind":"leaked_secret","metadata":{"rule_id":"slack-bot-token","file":"collected/deploys.json","line":3,"capability":"CAP-SCAN-04","provider":"slack","mode":"collected"}}`,
		"export":     `{"id":"f-1","kind":"leaked_secret","metadata":{"rule_id":"slack-bot-token","file":"deploys/2026-11-14.json","line":3,"capability":"CAP-SCAN-04","provider":"slack","mode":"artifact_path"}}`,
		"repository": `{"id":"f-1","kind":"leaked_secret","metadata":{"rule_id":"slack-bot-token","file":"app.env","line":2,"mode":"clone_url"}}`,
	}
	stored := 0
	serve := func(item string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery/findings" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"items":[` + item + `]}`))
				return
			}
			stored++
			http.Error(w, "unexpected", http.StatusTeapot)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	for name, tc := range map[string]struct {
		finding string
		args    []string
		code    int
		want    string
	}{
		"a collected finding":            {"collected", []string{"--export", t.TempDir()}, 1, "was collected from slack by trstctl"},
		"a third-party finding, --repo":  {"export", []string{"--repo", t.TempDir()}, 1, "name your copy of that export with --export"},
		"a repository finding, --export": {"repository", []string{"--export", t.TempDir()}, 1, "name your checkout with --repo"},
		"both places":                    {"repository", []string{"--repo", t.TempDir(), "--export", t.TempDir()}, 2, "Usage:"},
	} {
		srv := serve(finding[tc.finding])
		args := append([]string{"secrets", "scans", "move", "f-1"}, tc.args...)
		code, _, stderr := run(t, append(args, "--name", "deploys/slack-bot-token"), cli.Env{Server: srv.URL, Token: "operator-token", HTTPClient: srv.Client()}, "")
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Fatalf("%s: exit %d, stderr %q; want %d and %q", name, code, stderr, tc.code, tc.want)
		}
	}
	if stored != 0 {
		t.Fatalf("%d requests went past reading the finding", stored)
	}
}
