// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentityApprovalActionCommandsRequireExactImmutableRequestBody(t *testing.T) {
	for _, tc := range []struct {
		action string
	}{
		{action: "issue"},
		{action: "revoke"},
		{action: "rotate"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			cmd, args, ok := matchCommand([]string{"identities", "approve", tc.action, "identity-1"})
			if !ok {
				t.Fatalf("identities approve %s did not resolve to a concrete command", tc.action)
			}
			if got := strings.Join(cmd.Name, " "); got != "identities approve "+tc.action {
				t.Fatalf("command = %q, want identities approve %s", got, tc.action)
			}
			if _, _, _, _, err := buildRequest(cmd, args, bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "needs a request body") {
				t.Fatalf("build request without exact body error = %v, want request-body refusal", err)
			}

			bodyJSON := `{"action":"` + tc.action + `","request_id":"019fec49-6641-7131-ae7f-17f7ea4b5e0e","intent_digest":"sha256:8ec59a9c"}`
			cmdArgs := append(args, "-f", "-")
			path, _, body, _, err := buildRequest(cmd, cmdArgs, strings.NewReader(bodyJSON))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if path != "/api/v1/identities/identity-1/approvals" {
				t.Fatalf("path = %q, want /api/v1/identities/identity-1/approvals", path)
			}
			var decoded struct {
				Action       string `json:"action"`
				RequestID    string `json:"request_id"`
				IntentDigest string `json:"intent_digest"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("decode request body %q: %v", strings.TrimSpace(string(body)), err)
			}
			if decoded.Action != tc.action {
				t.Fatalf("body action = %q, want %q", decoded.Action, tc.action)
			}
			if decoded.RequestID == "" || decoded.IntentDigest == "" {
				t.Fatalf("body did not preserve exact immutable request binding: %+v", decoded)
			}
		})
	}
}
