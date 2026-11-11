// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestStoredSecretRefNamesCoverEveryRedeemerSpellingA235L2: a secret://
// reference names the secret each redeemer would read — the integration
// resolver's trimmed remainder and the connector/relay parser's unescaped
// URL host and path without its ?version — so no spelling reaches a
// restricted secret unchecked; anything else names nothing.
func TestStoredSecretRefNamesCoverEveryRedeemerSpellingA235L2(t *testing.T) {
	for ref, want := range map[string][]string{
		"secret://pay/prod/token":           {"pay/prod/token"},
		"secret:///pay/prod/token/":         {"pay/prod/token"},
		" secret://pay/prod/token ":         {"pay/prod/token"},
		"secret://pay/prod/token?version=2": {"pay/prod/token?version=2", "pay/prod/token"},
		"secret://pay/prod%2Ftoken":         {"pay/prod%2Ftoken", "pay/prod/token"},
		"secret://pay/prod/%74oken":         {"pay/prod/%74oken", "pay/prod/token"},
		"secret://":                         nil,
		"file:/etc/trstctl/token":           nil,
		"env:TRSTCTL_TOKEN":                 nil,
		"pay/prod/token":                    nil,
	} {
		if got := storedSecretRefNames(ref); !slices.Equal(got, want) {
			t.Errorf("storedSecretRefNames(%q) = %q, want %q", ref, got, want)
		}
	}
}

// TestSecretReferencesInWalksEveryStringA235L2: every secret:// string in a
// document is found, at any depth and in any field, as the relay finds it.
func TestSecretReferencesInWalksEveryStringA235L2(t *testing.T) {
	got := secretReferencesIn(json.RawMessage(`{"token_ref":"secret://pay/prod/token","hosts":[{"credential_ref":" secret://pay/prod/ssh"},` +
		`{"address":"10.0.0.1"}],"note":"secret://pay/dev/x","port":22,"nested":{"deeper":["plain","secret://pay/prod/key"]}}`))
	slices.Sort(got)
	want := []string{" secret://pay/prod/ssh", "secret://pay/dev/x", "secret://pay/prod/key", "secret://pay/prod/token"}
	if !slices.Equal(got, want) {
		t.Fatalf("secretReferencesIn = %q, want %q", got, want)
	}
	if refs := secretReferencesIn(json.RawMessage(`not json`)); refs != nil {
		t.Fatalf("an unparsable document yielded %q", refs)
	}
}
