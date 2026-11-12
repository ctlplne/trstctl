// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OD-4: a finding in a Teams export names its team, channel, message, the
// message it replies to and its poster with their address; a finding in a
// Confluence export names the content, its type and its space. Identifiers
// only, never content.
func TestLocateTeamsAndConfluenceExportsOD4(t *testing.T) {
	const team, channel, poster = "2f3a9d1e-6c41-4b0e-9a57-0c1d2e3f4a5b", "19:ops0general@thread.tacv2", "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "channel-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	messages := filepath.Join(root, "channel-1", "messages.json")
	content := `[
  {
    "id": "1001",
    "channelIdentity": {"teamId": "` + team + `", "channelId": "` + channel + `"},
    "from": {"user": {"id": "` + poster + `"}},
    "body": {"content": "deploying"}
  },
  {
    "id": "1002",
    "replyToId": "1001",
    "channelIdentity": {"teamId": "` + team + `", "channelId": "` + channel + `"},
    "from": {"user": {"id": "` + poster + `"}},
    "body": {"content": "the key is LEAKED-OD4"}
  }
]
`
	if err := os.WriteFile(messages, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "users.json"), []byte(`[{"id":"`+poster+`","mail":"dev@example.test"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := LocateThirdPartyObject("teams", root, "channel-1/messages.json", lineOf(t, messages, "LEAKED-OD4"))
	want := map[string]string{"kind": "teams_message", "team_id": team, "channel_id": channel, "message_id": "1002",
		"reply_to_id": "1001", "user": poster, "user_email": "dev@example.test"}
	if !ok || len(got) != len(want) {
		t.Fatalf("teams object = %+v, %v", got, ok)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("teams object %s = %q, want %q (%+v)", k, got[k], v, got)
		}
	}

	export := filepath.Join(root, "content.json")
	pages := `{
  "results": [
    {
      "id": "101",
      "type": "page",
      "title": "Runbook",
      "space": {"key": "ENG"},
      "body": {"storage": {"value": "<p>fine</p>"}}
    },
    {
      "id": "102",
      "type": "comment",
      "space": {"key": "ENG"},
      "body": {"storage": {"value": "<p>password LEAKED-OD4</p>"}}
    }
  ]
}
`
	if err := os.WriteFile(export, []byte(pages), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok = LocateThirdPartyObject("confluence", root, "content.json", lineOf(t, export, "LEAKED-OD4"))
	if !ok || got["kind"] != "confluence_content" || got["content_id"] != "102" || got["content_type"] != "comment" || got["space_key"] != "ENG" || len(got) != 4 {
		t.Fatalf("confluence object = %+v, %v", got, ok)
	}
	for _, v := range got {
		if strings.Contains(v, "LEAKED") || strings.Contains(v, "Runbook") {
			t.Fatalf("the located object carries content: %+v", got)
		}
	}
}

// OD-4: a Teams collection names its team, its channels and a token; a
// Confluence collection its CQL and a token; neither selector rides on
// another provider's collection, and neither is annotated.
func TestValidateTeamsAndConfluenceCollectionsOD4(t *testing.T) {
	const team, channel = "2f3a9d1e-6c41-4b0e-9a57-0c1d2e3f4a5b", "19:ops0general@thread.tacv2"
	ok := map[string]*CollectConfig{
		"teams":      {BaseURL: "https://graph.microsoft.com", TokenRef: "secret://graph", Team: team, Channels: []string{channel}, Since: "720h"},
		"confluence": {BaseURL: "https://example.atlassian.net/wiki", TokenRef: "secret://wiki", UsernameRef: "secret://wiki-user", CQL: "space = ENG"},
	}
	for provider, c := range ok {
		if err := ValidateCollect(provider, c); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
	}
	for name, tc := range map[string]struct {
		provider string
		c        CollectConfig
	}{
		"teams without a GUID team":    {"teams", CollectConfig{BaseURL: "https://graph.microsoft.com", TokenRef: "secret://g", Team: "ops", Channels: []string{channel}}},
		"teams with a Slack channel":   {"teams", CollectConfig{BaseURL: "https://graph.microsoft.com", TokenRef: "secret://g", Team: team, Channels: []string{"C0OPS"}}},
		"teams without a token":        {"teams", CollectConfig{BaseURL: "https://graph.microsoft.com", Team: team, Channels: []string{channel}}},
		"teams with a JQL":             {"teams", CollectConfig{BaseURL: "https://graph.microsoft.com", TokenRef: "secret://g", Team: team, Channels: []string{channel}, JQL: "x"}},
		"confluence without CQL":       {"confluence", CollectConfig{BaseURL: "https://example.atlassian.net/wiki", TokenRef: "secret://w"}},
		"confluence with channels":     {"confluence", CollectConfig{BaseURL: "https://example.atlassian.net/wiki", TokenRef: "secret://w", CQL: "space = ENG", Channels: []string{channel}}},
		"a team on a Slack scan":       {"slack", CollectConfig{BaseURL: "https://slack.com", TokenRef: "secret://s", Channels: []string{"C0OPS"}, Team: team}},
		"a CQL on a Jira scan":         {"jira", CollectConfig{BaseURL: "https://jira.example.test", TokenRef: "secret://j", JQL: "project = OPS", CQL: "space = ENG"}},
		"confluence over plain http":   {"confluence", CollectConfig{BaseURL: "http://wiki.example.test", TokenRef: "secret://w", CQL: "space = ENG"}},
		"teams with too many channels": {"teams", CollectConfig{BaseURL: "https://graph.microsoft.com", TokenRef: "secret://g", Team: team, Channels: make([]string, 101)}},
	} {
		c := tc.c
		if err := ValidateCollect(tc.provider, &c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	annotation := &AnnotationConfig{BaseURL: "https://graph.microsoft.com", TokenRef: "secret://g"}
	for _, provider := range []string{"teams", "confluence"} {
		if err := ValidateCollectedAnnotation(provider, annotation, ok[provider]); err == nil {
			t.Fatalf("a %s collection took an annotation", provider)
		}
		if err := ValidateAnnotation(provider, annotation); err == nil {
			t.Fatalf("a %s export took an annotation", provider)
		}
	}
	if NormalizeThirdPartyProvider("Microsoft-Teams") != ThirdPartyProviderTeams || ThirdPartyArtifactKind("confluence") != "confluence_export" {
		t.Fatal("provider names")
	}
}
