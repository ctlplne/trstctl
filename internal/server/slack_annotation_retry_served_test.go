// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
)

// A174-L4 Done-when: a retried Slack annotation never leaves two replies.
// Slack posts the reply and the answer is lost; the finding records the
// annotation unconfirmed and the outbox retries. With a token that can read
// the thread, the retry finds the reply and records already_present; with a
// token Slack refuses thread reads (missing_scope), the retry refuses rather
// than post again, naming the scope. Either way the thread holds exactly one
// reply.
func TestServedSlackAnnotationRetryNeverPostsTwiceA174L4(t *testing.T) {
	const token = "a174l4-annotation-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := scanannotatetest.New(token, "")
	t.Cleanup(stand.Close)
	t.Setenv("TRSTCTL_A174L4_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A174L4_TOKEN"),
		func(d *Deps) { d.SecretScanner = &a174MarkerScanner{} })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "connectors:write", string(authz.PrivateEgress))
	cidr := serviceNowSinkCIDR(t, stand.URL())

	type state struct {
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	annotation := func(source string) (string, state) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=leaked_secret&limit=100", tok, nil)
		var list struct {
			Items []struct {
				ID       string `json:"id"`
				Metadata struct {
					Source          string           `json:"source"`
					ProviderActions map[string]state `json:"provider_actions"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		for _, f := range list.Items {
			if f.Metadata.Source == source {
				return f.ID, f.Metadata.ProviderActions["annotate"]
			}
		}
		t.Fatalf("no finding for %s: %s", source, body)
		return "", state{}
	}
	retryDue := func() {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() - interval '1 second'
			WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
			t.Fatal(err)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain the retry: %v", err)
		}
	}
	for _, tc := range []struct {
		name, channel, ts, readRefusal, want string
	}{
		{"no-history-scope", "C0L4BLIND", "1730400100.000100", "missing_scope", "failed"},
		{"reads", "C0L4READ", "1730400000.000100", "", "already_present"},
	} {
		stand.SeedSlackMessage(tc.channel, tc.ts)
		export := filepath.Join(t.TempDir(), "slack")
		a174Write(t, filepath.Join(export, "channels.json"), `[{"id":"`+tc.channel+`","name":"deploys"}]`)
		a174Write(t, filepath.Join(export, "deploys", "2026-11-01.json"), `[{"type":"message","text":"token LEAK-A174-l4","ts":"`+tc.ts+`"}]`+"\n")
		source := "a174l4-" + tc.name
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", tok, source+"-ingest", map[string]any{
			"source": source, "artifact_path": export, "event": "a174l4",
			"annotation": map[string]any{"base_url": stand.URL(), "token_ref": "env:TRSTCTL_A174L4_TOKEN", "allow_private_endpoint": true, // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
				"private_egress_cidrs": []string{cidr}},
		}); status != http.StatusAccepted {
			t.Fatalf("%s ingest = %d %s", tc.name, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain the scan: %v", err)
		}
		findingID, _ := annotation(source)
		stand.SlackRefuseReads(tc.readRefusal)
		stand.SlackLoseNextAnswers(1)
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+findingID+"/annotate", tok, source+"-annotate",
			map[string]any{"reason": "a174l4"}); status != http.StatusAccepted {
			t.Fatalf("%s annotate = %d %s", tc.name, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain the annotation: %v", err)
		}
		_, lost := annotation(source)
		retryDue()
		if replies := stand.SlackReplies(tc.channel, tc.ts); len(replies) != 1 {
			t.Fatalf("%s thread has %d replies; want exactly one", tc.name, len(replies))
		}
		if lost.Status != "unconfirmed" {
			t.Fatalf("%s after the lost answer = %+v; want unconfirmed", tc.name, lost)
		}
		_, got := annotation(source)
		if got.Status != tc.want {
			t.Fatalf("%s after the retry = %+v; want %s", tc.name, got, tc.want)
		}
		if tc.want == "failed" && (!strings.Contains(got.Detail, "missing_scope") || !strings.Contains(got.Detail, "channels:history")) {
			t.Fatalf("%s refusal = %q; want the scope named", tc.name, got.Detail)
		}
	}
}
