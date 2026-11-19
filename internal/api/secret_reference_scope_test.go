// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

func TestSecretReferenceScopeRejectsNoncanonicalStoredScheme(t *testing.T) {
	a := &API{}
	for _, ref := range []string{"Secret://fixture/team/token", "secret:fixture/team/token"} {
		if err := a.requireSecretReferencesRead(context.Background(), "", "credential_ref", ref); err == nil {
			t.Errorf("admission accepted a noncanonical stored credential reference %q", ref)
		}
	}
	raw := json.RawMessage(`{"provider":{"credential_ref":"Secret://fixture/team/token"},"note":"plain fixture"}`)
	if err := a.requireSecretReferencesReadIn(context.Background(), "", "config", raw); err == nil {
		t.Error("nested configuration accepted a noncanonical stored credential reference")
	}
}

// A235-L2: authorization checks the identity every redeemer uses. An invalid
// legacy alias preserves the existing environment denial and cannot redeem.
func TestStoredSecretRefNamesCoverEveryRedeemerSpellingA235L2(t *testing.T) {
	for ref, want := range map[string]struct {
		name    string
		invalid bool
	}{
		"secret://pay/prod/token":           {"pay/prod/token", false},
		"secret:///pay/prod/token/":         {"pay/prod/token", true},
		" secret://pay/prod/token ":         {"pay/prod/token", false},
		"secret://pay/prod/token?version=2": {"pay/prod/token", false},
		"secret://pay/prod%2Ftoken":         {"pay/prod/token", true},
		"secret://pay/prod/%74oken":         {"pay/prod/token", true},
		"secret://":                         {"", true},
		"file:/etc/trstctl/token":           {"", false},
		"env:TRSTCTL_TOKEN":                 {"", false},
		"pay/prod/token":                    {"", false},
	} {
		if name, err := storedSecretScopeName(ref); name != want.name || (err != nil) != want.invalid {
			t.Errorf("scope for %q = %q, %v, want name=%q invalid=%t", ref, name, err, want.name, want.invalid)
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
