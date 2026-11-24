// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

func TestCR803URIPrefixRequiresAuthorityAndWholePathSegments(t *testing.T) {
	for _, tc := range []struct {
		uri, prefix string
		want        bool
	}{
		{"spiffe://td.example/ns/prod", "spiffe://td.example/ns/prod", true},
		{"spiffe://td.example/ns/prod/sa/web", "spiffe://td.example/ns/prod", true},
		{"spiffe://td.example/ns/production/sa/admin", "spiffe://td.example/ns/prod", false},
		{"spiffe://td.example/ns/prod%2fsa/admin", "spiffe://td.example/ns/prod", false},
		{"spiffe://td.example/ns/prod/../admin", "spiffe://td.example/ns/prod", false},
		{"https://api.example.test/team/app", "https://api.example.test/team", true},
		{"https://api.example.test.evil.test/team/app", "https://api.example.test/team", false},
		{"https://api.example.test@evil.test/team/app", "https://api.example.test/team", false},
		{"https://user@api.example.test/team/app", "https://api.example.test/team", false},
		{"https://api.example.test:8443/team/app", "https://api.example.test/team", false},
		{"https://api.example.test/team/app?mode=admin", "https://api.example.test/team", false},
		{"https://api.example.test/team/app#admin", "https://api.example.test/team", false},
	} {
		if got := uriPrefixPermitted(tc.uri, []string{tc.prefix}); got != tc.want {
			t.Errorf("URI %q under %q: got %v, want %v", tc.uri, tc.prefix, got, tc.want)
		}
	}
}
