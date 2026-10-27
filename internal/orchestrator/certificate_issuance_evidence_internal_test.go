// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "testing"

// A179: a queued-command issuance key names its deciding transition's event;
// every other key names none.
func TestTransitionEventIDFromKey(t *testing.T) {
	for key, want := range map[string]string{
		"renew:8agboicaSJ7ouxsWhiWmUD":    "8agboicaSJ7ouxsWhiWmUD",
		"issue:4d6f2a":                    "4d6f2a",
		"renew:transition:operator-key-1": "",
		"issue:transition:k":              "",
		"renew:":                          "",
		"protocol-issue:acme-order":       "",
		"agentcsr:12:0:abcd":              "",
		"renew:a:b":                       "",
		"":                                "",
	} {
		if got := transitionEventIDFromKey(key); got != want {
			t.Errorf("transitionEventIDFromKey(%q) = %q, want %q", key, got, want)
		}
	}
}
