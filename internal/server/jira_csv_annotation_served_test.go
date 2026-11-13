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

// A174-L3 Done-when: a third-party scan of a Jira CSV export locates a
// leaked secret to the issue whose row holds it — here on the second line
// of a description quoted over three lines — and annotating the finding
// writes exactly one comment on that issue, naming the rule and never the
// secret.
func TestServedJiraCSVExportFindingIsAnnotatedOnItsIssueA174L3(t *testing.T) {
	const token = "a174l3-annotation-token" // #nosec G101 -- fabricated fixture credential (CWE-798)
	stand := scanannotatetest.New(token, "")
	t.Cleanup(stand.Close)
	stand.SeedJiraIssue("OPS-173")
	stand.SeedJiraIssue("OPS-174")
	export := a174Write(t, filepath.Join(t.TempDir(), "jira", "Jira Export.csv"), "Summary,Issue key,Issue id,Description\n"+
		"rotate keys,OPS-173,10173,plain\n"+
		"leaked,OPS-174,10174,\"deploy notes\npassword LEAK-A174-csv\nrotate after\"\n")
	t.Setenv("TRSTCTL_A174L3_TOKEN", token)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A174L3_TOKEN"),
		func(d *Deps) { d.SecretScanner = &a174MarkerScanner{} })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "connectors:write", string(authz.PrivateEgress))
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/jira/ingest", tok, "a174l3-ingest", map[string]any{
		"source": "acme-jira-csv", "artifact_path": export, "event": "a174l3",
		"annotation": map[string]any{"base_url": stand.URL(), "token_ref": "env:TRSTCTL_A174L3_TOKEN", "allow_private_endpoint": true, // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())}},
	}); status != http.StatusAccepted {
		t.Fatalf("ingest = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain the scan: %v", err)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=leaked_secret&limit=100", tok, nil)
	var list struct {
		Items []struct {
			ID       string         `json:"id"`
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 {
		t.Fatalf("findings = %d %s", status, body)
	}
	finding := list.Items[0]
	if object, _ := finding.Metadata["provider_object"].(map[string]any); object["kind"] != "jira_issue" || object["issue_key"] != "OPS-174" {
		t.Fatalf("the CSV finding's object = %+v", finding.Metadata["provider_object"])
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+finding.ID+"/annotate", tok, "a174l3-annotate",
		map[string]any{"reason": "a174l3"}); status != http.StatusAccepted {
		t.Fatalf("annotate = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain the annotation: %v", err)
	}
	comments := stand.JiraComments("OPS-174")
	if len(comments) != 1 || !strings.Contains(comments[0], "generic-api-key") || strings.Contains(comments[0], "LEAK-A174") {
		t.Fatalf("OPS-174 comments = %v", comments)
	}
	if other := stand.JiraComments("OPS-173"); len(other) != 0 {
		t.Fatalf("the neighboring row's issue was annotated: %v", other)
	}
}
