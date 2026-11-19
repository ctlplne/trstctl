// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

func TestWorkloadAttesterTrustValidatesGitHubPinDeclarations(t *testing.T) {
	// CR-384: only an immutable ID condition can make an OIDC source
	// self-authenticating or constrain it by a GitHub owner name.
	jwks := githubPinTestJWKS(t)
	for _, tc := range []struct {
		name  string
		extra map[string]any
		valid bool
	}{
		{"ordinary source without pins", nil, true},
		{"name-only condition", map[string]any{"allowed_owners": []string{"acme"}}, false},
		{"self-authenticating owner pin", map[string]any{"self_authenticating": true, "allowed_owner_ids": []string{"123"}}, true},
		{"self-authenticating repository pin", map[string]any{"self_authenticating": true, "allowed_repository_ids": []string{"456"}}, true},
		{"leading zero", map[string]any{"allowed_owner_ids": []string{"0123"}}, false},
		{"null array", map[string]any{"allowed_owner_ids": nil}, false},
		{"null item", map[string]any{"allowed_repository_ids": []any{nil}}, false},
		{"number item", map[string]any{"allowed_repository_ids": []int{456}}, false},
		{"another attestation method", map[string]any{"method": "k8s_sat", "allowed_owner_ids": []string{"123"}}, false},
		{"another method with empty pin list", map[string]any{"method": "k8s_sat", "allowed_repository_ids": []string{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"name": "workflow", "method": "github_oidc", "jwks": jwks}
			for key, value := range tc.extra {
				body[key] = value
			}
			r := githubPinTestRequest(t, body)
			_, err := decodeWorkloadAttesterTrustSourceRequest(r)
			if (err == nil) != tc.valid {
				t.Fatalf("validation succeeded = %t, want %t, error %v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestTrustMaterialRotationRejectsGitHubPinFields(t *testing.T) {
	// CR-384: pin replacement uses a full trust-source update.
	current := store.WorkloadAttesterTrustSource{Method: "github_oidc", JWKS: githubPinTestJWKS(t)}
	for _, field := range []string{"allowed_owner_ids", "allowed_repository_ids"} {
		t.Run(field, func(t *testing.T) {
			r := githubPinTestRequest(t, map[string]any{field: []string{"123"}, "reason": "refresh public keys"})
			if _, err := decodeWorkloadAttesterTrustSourceRotateRequest(r, current); err == nil {
				t.Fatal("accepted a pin field on the material-only rotation route")
			}
		})
	}
}

func githubPinTestJWKS(t *testing.T) json.RawMessage {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	jwk, err := crypto.PublicJWK(key.Public(), "test-issuer")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func githubPinTestRequest(t *testing.T, body map[string]any) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	return r
}
