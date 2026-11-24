// SPDX-License-Identifier: BUSL-1.1

package profile_test

import (
	"testing"

	"trstctl.com/trstctl/internal/profile"
)

func TestCR803ProfileURIPrefixUsesSameBoundaryAsSigner(t *testing.T) {
	p := profile.CertificateProfile{AllowedURIPrefixes: []string{"spiffe://td.example/ns/prod"}}
	for _, tc := range []struct {
		uri  string
		want bool
	}{
		{"spiffe://td.example/ns/prod/sa/web", true},
		{"spiffe://td.example/ns/production/sa/admin", false},
		{"spiffe://td.example@evil.test/ns/prod/sa/admin", false},
	} {
		err := p.ValidateRequestMetadata(profile.Request{URIs: []string{tc.uri}})
		if (err == nil) != tc.want {
			t.Errorf("profile URI %q: allowed=%v, want %v (error %v)", tc.uri, err == nil, tc.want, err)
		}
	}
}

func TestCR803ProfileDefinitionRejectsMalformedURIPrefix(t *testing.T) {
	for _, prefix := range []string{
		"/ns/prod", "spiffe:/ns/prod", "spiffe://user@td.example/ns/prod",
		"spiffe://td.example/ns/prod?mode=admin", "spiffe://td.example/ns/prod#admin",
	} {
		p := profile.CertificateProfile{AllowedURIPrefixes: []string{prefix}}
		if err := p.ValidateDefinition(); err == nil {
			t.Errorf("malformed allowed_uri_prefixes value %q accepted", prefix)
		}
	}
}
