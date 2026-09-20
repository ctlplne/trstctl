// SPDX-License-Identifier: BUSL-1.1

package awssm

import (
	"encoding/json"
	"testing"
)

// AWS (and LocalStack) send Secrets Manager timestamps as epoch numbers on the
// JSON protocol; older fixtures send RFC 3339 strings. Both must parse.
func TestAWSTimestampAcceptsEpochNumbersAndStrings(t *testing.T) {
	var resp struct {
		SecretList []struct {
			Name            string       `json:"Name"`
			CreatedDate     awsTimestamp `json:"CreatedDate"`
			LastChangedDate awsTimestamp `json:"LastChangedDate"`
		} `json:"SecretList"`
	}
	raw := `{"SecretList":[{"Name":"demo/edge-gateway/tls","CreatedDate":1788732000.123,"LastChangedDate":1788732000},
	                       {"Name":"legacy","CreatedDate":"2026-09-06T22:00:00Z","LastChangedDate":null}]}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("parse list with epoch timestamps: %v", err)
	}
	if got := string(resp.SecretList[0].CreatedDate); got != "2026-09-06T22:00:00Z" {
		t.Fatalf("epoch CreatedDate = %q, want 2026-09-06T22:00:00Z", got)
	}
	if got := string(resp.SecretList[0].LastChangedDate); got != "2026-09-06T22:00:00Z" {
		t.Fatalf("epoch LastChangedDate = %q, want 2026-09-06T22:00:00Z", got)
	}
	if got := string(resp.SecretList[1].CreatedDate); got != "2026-09-06T22:00:00Z" {
		t.Fatalf("string CreatedDate = %q, want it kept verbatim", got)
	}
	if got := string(resp.SecretList[1].LastChangedDate); got != "" {
		t.Fatalf("null LastChangedDate = %q, want empty", got)
	}
	if err := json.Unmarshal([]byte(`{"SecretList":[{"Name":"x","CreatedDate":{"bad":true}}]}`), &resp); err == nil {
		t.Fatal("an object where a timestamp belongs must be rejected")
	}
}
