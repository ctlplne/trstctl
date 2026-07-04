// SPDX-License-Identifier: MPL-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentityApprovalActionCommandsPostFixedBodies(t *testing.T) {
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
			path, _, body, _, err := buildRequest(cmd, args, bytes.NewReader(nil))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if path != "/api/v1/identities/identity-1/approvals" {
				t.Fatalf("path = %q, want /api/v1/identities/identity-1/approvals", path)
			}
			var decoded struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("decode request body %q: %v", strings.TrimSpace(string(body)), err)
			}
			if decoded.Action != tc.action {
				t.Fatalf("body action = %q, want %q", decoded.Action, tc.action)
			}
		})
	}
}
