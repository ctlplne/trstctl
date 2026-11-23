// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedCR408RejectsRawThirdPartyConnectionReferences(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		bindOutboundEnvCredentialRefs("secret_third_party", []string{"https://jira.example.test"}, "env:TRSTCTL_CR408_TOKEN"))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	before := servedEventCount(t, h, projections.EventDiscoverySourceUpserted)
	for _, tc := range []struct {
		name, provider string
		request        map[string]any
	}{
		{"annotation token", "jira", map[string]any{"source": "raw-annotation-token", "artifact_path": t.TempDir(),
			"annotation": map[string]any{"base_url": "https://jira.example.test", "token_ref": "raw-reference-fixture"}}}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
		{"annotation username", "jira", map[string]any{"source": "raw-annotation-username", "artifact_path": t.TempDir(),
			"annotation": map[string]any{"base_url": "https://jira.example.test", "token_ref": "env:TRSTCTL_CR408_TOKEN", "username_ref": "raw-reference-fixture"}}}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
		{"native collection token", "jira", map[string]any{"source": "raw-collect-token",
			"collect": map[string]any{"base_url": "https://jira.example.test", "token_ref": "raw-reference-fixture", "jql": "project = SEC"}}}, // #nosec G101 -- fabricated invalid reference fixture, no credential value (CWE-798)
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/"+tc.provider+"/ingest", token,
				"cr408-"+tc.name, tc.request)
			if status != http.StatusBadRequest {
				t.Errorf("raw connection reference = %d %s, want 400", status, body)
			}
		})
	}
	if got := servedEventCount(t, h, projections.EventDiscoverySourceUpserted); got != before {
		t.Fatalf("rejected connection entered source event log: %d -> %d", before, got)
	}
}
