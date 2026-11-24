// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"
)

func TestCR192SSHHostPrincipalsNeedOperatorAuthorization(t *testing.T) {
	protocols := sshServedProtocols()
	protocols.SSHUserPrincipals = []string{"deploy"}
	h := newOperatingServedHarness(t, protocols)
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ci-issuer", []string{"certs:issue"})
	pub := sshTestPublicKey(t)
	for _, tc := range []struct {
		name, path, key string
		body            map[string]any
	}{
		{"raw arbitrary host", "/ssh/issue/host", "cr192-raw-host", map[string]any{
			"public_key": pub, "key_id": "ci-host", "principals": []string{"db1.prod.example.com"}, "ttl_seconds": 600,
		}},
		{"raw wildcard", "/ssh/issue/host", "cr192-raw-wildcard", map[string]any{
			"public_key": pub, "key_id": "ci-wildcard", "principals": []string{"*"}, "ttl_seconds": 600,
		}},
		{"product arbitrary host", "/api/v1/ssh/certificates", "cr192-product-host", map[string]any{
			"certificate_type": "host", "public_key": pub, "key_id": "ci-product",
			"principals": []string{"bastion.prod.example.com"}, "ttl_seconds": 600,
		}},
		{"product preview arbitrary host", "/api/v1/ssh/certificates/preview", "", map[string]any{
			"certificate_type": "host", "public_key": pub, "key_id": "ci-preview",
			"principals": []string{"bastion.prod.example.com"}, "ttl_seconds": 600,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := sshPost(t, h.ts, tc.path, token, tc.key, tc.body)
			if code == http.StatusOK || code == http.StatusCreated {
				t.Errorf("certs:issue holder obtained an unapproved SSH host principal: status=%d", code)
			}
		})
	}
}

func TestCR192SSHHostPrincipalsAllowOnlyConfiguredLiterals(t *testing.T) {
	protocols := sshServedProtocols()
	protocols.SSHHostPrincipals = []string{"edge-1.internal", "edge-2.internal"}
	h := newOperatingServedHarness(t, protocols)
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ci-issuer", []string{"certs:issue"})
	pub := sshTestPublicKey(t)
	for _, tc := range []struct {
		path, key string
		body      map[string]any
		want      int
	}{
		{"/ssh/issue/host", "cr192-approved-raw", map[string]any{
			"public_key": pub, "key_id": "approved-raw", "principals": []string{"edge-1.internal"}, "ttl_seconds": 600,
		}, http.StatusOK},
		{"/api/v1/ssh/certificates/preview", "", map[string]any{
			"certificate_type": "host", "public_key": pub, "key_id": "approved-preview",
			"principals": []string{"edge-2.internal"}, "ttl_seconds": 600,
		}, http.StatusOK},
		{"/api/v1/ssh/certificates", "cr192-approved-product", map[string]any{
			"certificate_type": "host", "public_key": pub, "key_id": "approved-product",
			"principals": []string{"edge-2.internal"}, "ttl_seconds": 600,
		}, http.StatusCreated},
		{"/api/v1/ssh/certificates", "cr192-mixed-principals", map[string]any{
			"certificate_type": "host", "public_key": pub, "key_id": "mixed",
			"principals": []string{"edge-1.internal", "unlisted.internal"}, "ttl_seconds": 600,
		}, http.StatusForbidden},
	} {
		code, _ := sshPost(t, h.ts, tc.path, token, tc.key, tc.body)
		if code != tc.want {
			t.Errorf("%s principals=%v: status=%d, want %d", tc.path, tc.body["principals"], code, tc.want)
		}
	}
	// A bad in-memory configuration cannot turn OpenSSH pattern syntax into an
	// approved literal even if it bypasses the file/environment validator.
	patternProtocols := sshServedProtocols()
	patternProtocols.SSHHostPrincipals = []string{"*"}
	patternHarness := newOperatingServedHarness(t, patternProtocols)
	patternToken := seedServedAPIToken(t, t.Context(), patternHarness.store, patternHarness.tenant,
		"ci-pattern-issuer", []string{"certs:issue"})
	code, _ := sshPost(t, patternHarness.ts, "/ssh/issue/host", patternToken, "cr192-bad-config", map[string]any{
		"public_key": pub, "key_id": "pattern", "principals": []string{"*"}, "ttl_seconds": 600,
	})
	if code != http.StatusForbidden {
		t.Errorf("pattern principal from invalid in-memory configuration = %d, want 403", code)
	}
}
