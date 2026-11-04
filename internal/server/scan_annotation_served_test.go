// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
	"trstctl.com/trstctl/internal/secretscan"
)

// a174MarkerScanner stands in for the leak scanner: it reports every line
// of the artifact that carries the fixture marker, the way a scanner reports
// a rule match by file and line.
type a174MarkerScanner struct {
	mu    sync.Mutex
	paths []string
	// marker is the text a line must hold to be a finding; LEAK-A174 when
	// empty.
	marker string
	// rule is the finding's rule; generic-api-key when empty.
	rule string
}

func (s *a174MarkerScanner) Scan(_ context.Context, target string) (secretscan.Report, error) {
	s.mu.Lock()
	s.paths = append(s.paths, target)
	s.mu.Unlock()
	root := target
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		root = filepath.Dir(target)
	}
	report := secretscan.Report{Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive}
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G122 G304 -- test fixture under t.TempDir (CWE-22)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(data), "\n") {
			marker := s.marker
			if marker == "" {
				marker = "LEAK-A174"
			}
			if strings.Contains(line, marker) {
				rule := s.rule
				if rule == "" {
					rule = "generic-api-key"
				}
				report.Findings = append(report.Findings, secretscan.Finding{Scanner: "gitleaks", RuleID: rule,
					File: filepath.ToSlash(rel), Line: i + 1, Fingerprint: filepath.ToSlash(rel) + ":" + rule + ":" + string(rune('0'+i%10)),
					CredentialRef: rule + "@" + filepath.ToSlash(rel)})
			}
		}
		return nil
	})
	return report, err
}

func a174Write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A174 Done-when: provider-native annotations. Third-party scans of a Slack
// export, a Jira export, CI logs from GitHub and GitLab, and a container
// image's export record leaked_secret findings that carry the provider
// object each credential was seen in. Annotating a finding writes exactly
// one note at that provider (a thread reply, an issue comment, a commit
// status, an OCI referrer) naming the rule and the finding, never the
// secret; a replayed request converges; a source with auto annotation
// annotates without an operator; a refused token records the failure; a
// scan without an annotation connection is refused with the reason.
func TestServedThirdPartyFindingsAnnotatedAtTheProvider(t *testing.T) {
	const token = "a174-annotation-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := scanannotatetest.New(token, "")
	t.Cleanup(stand.Close)
	stand.SeedSlackMessage("C0DEPLOY", "1730300000.000100")
	stand.SeedJiraIssue("OPS-174")
	stand.SeedCommit("github", "acme/api", "a174a174a174a174")
	stand.SeedCommit("gitlab", "acme/api", "b174b174b174b174")
	image := stand.SeedImage("acme/api", []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`))

	root := t.TempDir()
	slackRoot := filepath.Join(root, "slack-export")
	a174Write(t, filepath.Join(slackRoot, "channels.json"), `[{"id":"C0DEPLOY","name":"deploys"}]`)
	a174Write(t, filepath.Join(slackRoot, "deploys", "2026-10-30.json"), `[
    {
        "type": "message",
        "text": "deploying now",
        "ts": "1730300000.000100"
    },
    {
        "type": "message",
        "text": "token LEAK-A174-slack",
        "ts": "1730300050.000200",
        "thread_ts": "1730300000.000100"
    }
]
`)
	jira := a174Write(t, filepath.Join(root, "jira", "issues.json"), `{
  "issues": [
    {"key": "OPS-173", "fields": {"summary": "rotate"}},
    {
      "key": "OPS-174",
      "fields": {"description": "password LEAK-A174-jira"}
    }
  ]
}
`)
	githubLog := a174Write(t, filepath.Join(root, "ci-github", "build.log"), "step 1\nstep 2\nexport TOKEN=LEAK-A174-github\n")
	gitlabLog := a174Write(t, filepath.Join(root, "ci-gitlab", "job.log"), "export TOKEN=LEAK-A174-gitlab\n")
	registry := a174Write(t, filepath.Join(root, "registry", "image-config.json"), `{"env":["PASSWORD=LEAK-A174-registry"]}`+"\n")
	noAnnotation := a174Write(t, filepath.Join(root, "ci-plain", "build.log"), "TOKEN=LEAK-A174-plain\n")

	t.Setenv("TRSTCTL_A174_TOKEN", token)
	t.Setenv("TRSTCTL_A174_WRONG", "not-the-token")
	scanner := &a174MarkerScanner{}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		allowOutboundEnvCredentialRefs("env:TRSTCTL_A174_TOKEN", "env:TRSTCTL_A174_WRONG"), func(d *Deps) { d.SecretScanner = scanner })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "connectors:write", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read")
	cidr := serviceNowSinkCIDR(t, stand.URL())
	connection := func(ref string, extra map[string]any) map[string]any {
		out := map[string]any{"base_url": stand.URL(), "token_ref": ref, "allow_private_endpoint": true, "private_egress_cidrs": []string{cidr}}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	ingest := func(provider, source, path string, annotation map[string]any) {
		t.Helper()
		body := map[string]any{"source": source, "artifact_path": path, "event": "a174"}
		if annotation != nil {
			body["annotation"] = annotation
		}
		if status, resp := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/"+provider+"/ingest", tok, "a174-"+source, body); status != http.StatusAccepted {
			t.Fatalf("%s ingest = %d %s", source, status, resp)
		}
	}
	ingest("slack", "acme-slack", slackRoot, connection("env:TRSTCTL_A174_TOKEN", nil))
	ingest("jira", "acme-jira", jira, connection("env:TRSTCTL_A174_TOKEN", nil))
	ingest("cicd_log", "acme-github-ci", githubLog, connection("env:TRSTCTL_A174_TOKEN", map[string]any{"system": "github", "repo": "acme/api", "commit_sha": "a174a174a174a174"}))
	ingest("cicd_log", "acme-gitlab-ci", gitlabLog, connection("env:TRSTCTL_A174_WRONG", map[string]any{"system": "gitlab", "repo": "acme/api", "commit_sha": "b174b174b174b174"}))
	ingest("container_registry", "acme-image", registry, connection("env:TRSTCTL_A174_TOKEN", map[string]any{"repository": "acme/api", "digest": image, "auto": true}))
	ingest("cicd_log", "acme-plain-ci", noAnnotation, nil)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", tok, "a174-bad", map[string]any{
		"source": "bad", "artifact_path": slackRoot, "annotation": connection("env:TRSTCTL_A174_TOKEN", map[string]any{"repo": "acme/api"})}); status != http.StatusBadRequest {
		t.Fatalf("slack annotation naming a repo = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain scans: %v", err)
	}

	type row struct {
		ID       string         `json:"id"`
		Kind     string         `json:"kind"`
		Metadata map[string]any `json:"metadata"`
	}
	findings := func() map[string]row {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=leaked_secret&limit=100", tok, nil)
		var list struct {
			Items []row `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		out := map[string]row{}
		for _, f := range list.Items {
			out[f.Metadata["source"].(string)] = f
		}
		return out
	}
	byScan := findings()
	object := func(source string) map[string]any {
		o, _ := byScan[source].Metadata["provider_object"].(map[string]any)
		return o
	}
	if o := object("acme-slack"); o["channel_id"] != "C0DEPLOY" || o["message_ts"] != "1730300050.000200" || o["thread_ts"] != "1730300000.000100" {
		t.Fatalf("slack object = %+v", o)
	}
	if o := object("acme-jira"); o["issue_key"] != "OPS-174" {
		t.Fatalf("jira object = %+v", o)
	}
	if o := object("acme-github-ci"); o["repo"] != "acme/api" || o["commit_sha"] != "a174a174a174a174" {
		t.Fatalf("ci object = %+v", o)
	}
	if o := object("acme-plain-ci"); len(o) != 0 {
		t.Fatalf("a scan without annotation recorded an object: %+v", o)
	}

	// The image source annotates on its own.
	if refs := stand.Referrers("acme/api", image); len(refs) != 1 || refs[0]["dev.trstctl.finding.id"] != byScan["acme-image"].ID {
		t.Fatalf("auto referrer = %+v", refs)
	}

	annotate := func(source, key, bearer string) (int, []byte) {
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+byScan[source].ID+"/annotate", bearer, key, map[string]any{"reason": "a174"})
	}
	if status, body := annotate("acme-slack", "a174-reader", reader); status != http.StatusForbidden {
		t.Fatalf("annotate without connectors:write = %d %s", status, body)
	}
	status, first := annotate("acme-slack", "a174-slack", tok)
	if status != http.StatusAccepted || !bytes.Contains(first, []byte(`"provider":"slack"`)) {
		t.Fatalf("slack annotate = %d %s", status, first)
	}
	if status, replay := annotate("acme-slack", "a174-slack", tok); status != http.StatusAccepted || !bytes.Equal(replay, first) {
		t.Fatalf("replay = %d %s", status, replay)
	}
	for _, source := range []string{"acme-jira", "acme-github-ci", "acme-gitlab-ci"} {
		if status, body := annotate(source, "a174-annotate-"+source, tok); status != http.StatusAccepted {
			t.Fatalf("%s annotate = %d %s", source, status, body)
		}
	}
	if status, body := annotate("acme-plain-ci", "a174-plain", tok); status != http.StatusConflict || !bytes.Contains(body, []byte("no annotation connection")) {
		t.Fatalf("annotate without a connection = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain annotations: %v", err)
	}

	notes := map[string][]string{
		"slack":  stand.SlackReplies("C0DEPLOY", "1730300000.000100"),
		"jira":   stand.JiraComments("OPS-174"),
		"github": nil,
	}
	for _, s := range stand.Statuses("github", "acme/api", "a174a174a174a174") {
		notes["github"] = append(notes["github"], s.State+" "+s.Context+" "+s.Description)
	}
	for provider, got := range notes {
		if len(got) != 1 || !strings.Contains(got[0], "generic-api-key") || strings.Contains(got[0], "LEAK-A174") {
			t.Fatalf("%s notes = %v", provider, got)
		}
	}
	if len(stand.Statuses("gitlab", "acme/api", "b174b174b174b174")) != 0 {
		t.Fatal("a refused token wrote a GitLab status")
	}
	byScan = findings()
	state := func(source string) map[string]any {
		actions, _ := byScan[source].Metadata["provider_actions"].(map[string]any)
		s, _ := actions["annotate"].(map[string]any)
		return s
	}
	for _, source := range []string{"acme-slack", "acme-jira", "acme-github-ci", "acme-image"} {
		if s := state(source); s["status"] != "confirmed" || s["provider_ref"] == "" || s["provider_ref"] == nil {
			t.Fatalf("%s annotate state = %+v", source, s)
		}
	}
	if s := state("acme-gitlab-ci"); s["status"] != "failed" || !strings.Contains(s["detail"].(string), "status 401") {
		t.Fatalf("refused token state = %+v", s)
	}
}
