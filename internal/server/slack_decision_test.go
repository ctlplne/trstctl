// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestSlackDecisionsAreSignedForOneActionA277: a posted button's decision
// opens only unaltered, for the action it was posted for, before it expires,
// and only under the key that signed it.
func TestSlackDecisionsAreSignedForOneActionA277(t *testing.T) {
	key := []byte("a277-test-key")
	mac := func(domain, material []byte) ([]byte, error) {
		return crypto.HMACSHA256(key, append(append([]byte{}, domain...), material...)), nil
	}
	now := time.Date(2026, 11, 7, 23, 0, 0, 0, time.UTC)
	a := &slackAppServer{mac: mac, now: func() time.Time { return now }}
	d := slackDecision{Tenant: "t", Request: "r", Digest: strings.Repeat("a", 64), Action: "approve", Nonce: "n", Expires: now.Add(time.Hour).Unix()}
	value, err := a.signDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.openDecision(value, "approve"); err != nil || got != d {
		t.Fatalf("an unaltered decision: %+v %v", got, err)
	}
	if _, err := a.openDecision(value, "deny"); err != errSlackDecisionAltered {
		t.Fatalf("a decision for another action: %v", err)
	}
	parts := strings.Split(value, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["d"] = strings.Repeat("b", 64)
	altered, _ := json.Marshal(m)
	if _, err := a.openDecision(parts[0]+"."+base64.RawURLEncoding.EncodeToString(altered)+"."+parts[2], "approve"); err != errSlackDecisionAltered {
		t.Fatalf("an altered digest: %v", err)
	}
	other := &slackAppServer{mac: func(domain, material []byte) ([]byte, error) {
		return crypto.HMACSHA256([]byte("another key"), append(append([]byte{}, domain...), material...)), nil
	}, now: a.now}
	if _, err := other.openDecision(value, "approve"); err != errSlackDecisionAltered {
		t.Fatalf("a decision under another key: %v", err)
	}
	later := &slackAppServer{mac: mac, now: func() time.Time { return now.Add(2 * time.Hour) }}
	if _, err := later.openDecision(value, "approve"); err != errSlackDecisionExpired {
		t.Fatalf("an expired decision: %v", err)
	}
	for _, bad := range []string{"", "v1.x", "v0." + parts[1] + "." + parts[2], value + ".extra"} {
		if _, err := a.openDecision(bad, "approve"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := (&slackAppServer{now: a.now}).signDecision(d); err == nil {
		t.Fatal("signed without a key")
	}
}
