// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"regexp"
	"testing"
)

// A schema under an empty or malformed status key cannot describe an HTTP
// response. Checking only that the responses map is nonempty missed this bug.
func TestOpenAPIResponseStatusKeysAreUsable(t *testing.T) {
	valid := regexp.MustCompile(`^(default|[1-5]([0-9]{2}|XX))$`)
	for _, value := range []string{"", "20", "2000", "2xx", "600", "2X0", "HTTP 200"} {
		if valid.MatchString(value) {
			t.Fatalf("broken status fixture %q escaped the oracle", value)
		}
	}
	for _, value := range []string{"200", "201", "202", "204", "4XX", "default"} {
		if !valid.MatchString(value) {
			t.Fatalf("valid status fixture %q failed the oracle", value)
		}
	}
	paths := asMap(fetchSpec(t)["paths"])
	operations := 0
	for path, item := range paths {
		for method, raw := range asMap(item) {
			op := asMap(raw)
			responses, ok := op["responses"].(map[string]any)
			if !ok {
				continue
			}
			operations++
			for status := range responses {
				if !valid.MatchString(status) {
					t.Errorf("%s %s: unusable response-status key %q", method, path, status)
				}
			}
		}
	}
	if operations == 0 {
		t.Fatal("no operation responses were checked")
	}
}

func TestOpenAPIWorkloadSuccessStatusesMatchServedJourneys(t *testing.T) {
	paths := asMap(fetchSpec(t)["paths"])
	cases := []struct{ method, path, status, schema string }{
		{"get", "/api/v1/broker/agent-identities", "200", "BrokerAgentIdentityHistoryList"},
		{"get", "/api/v1/broker/agent-identities/{id}", "200", "BrokerAgentIdentityHistory"},
		{"post", "/api/v1/broker/agent-identities/preview", "200", "BrokerAgentIdentityPreview"},
		{"post", "/api/v1/broker/agent-identities", "201", "BrokerAgentIdentity"},
		{"post", "/api/v1/workloads/attested-issuance/preview", "200", "AttestedSVIDPreview"},
		{"post", "/api/v1/workloads/attested-issuance", "201", "AttestedSVID"},
		{"post", "/api/v1/ephemeral/preview", "200", "EphemeralCredentialPreview"},
		{"post", "/api/v1/ephemeral", "201", "EphemeralCredential"},
		{"post", "/api/v1/ephemeral", "202", "EphemeralCredential"},
		{"post", "/api/v1/ephemeral/{id}/approvals", "200", "EphemeralApproval"},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path+"/"+tc.status, func(t *testing.T) {
			op := asMap(asMap(paths[tc.path])[tc.method])
			response := asMap(asMap(op["responses"])[tc.status])
			media := asMap(asMap(response["content"])["application/json"])
			if got := asMap(media["schema"])["$ref"]; got != "#/components/schemas/"+tc.schema {
				t.Fatalf("HTTP %s schema = %v, want %s", tc.status, got, tc.schema)
			}
		})
	}
}
