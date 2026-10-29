// SPDX-License-Identifier: BUSL-1.1
package githuboidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func testIssuer(t *testing.T) (*githuboidc.Attestor, func(map[string]any) []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	key, err := crypto.PublicJWK(signer.Public(), "a232-test-issuer")
	if err != nil {
		t.Fatal(err)
	}
	attestor := &githuboidc.Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{key}}, Audience: "trstctl", AllowedOwners: map[string]bool{"acme": true}}
	sign := func(changes map[string]any) []byte {
		t.Helper()
		claims := map[string]any{"iss": githuboidc.DefaultIssuer, "aud": "trstctl", "sub": "repo:acme/payments:ref:refs/heads/main", "repository": "acme/payments", "repository_owner": "acme", "workflow": "deploy", "ref": "refs/heads/main", "job_workflow_ref": "acme/payments/.github/workflows/deploy.yml@refs/heads/main", "exp": time.Now().Add(time.Minute).Unix(), "run_id": "47001", "run_attempt": "1"}
		for name, value := range changes {
			if value == nil {
				delete(claims, name)
			} else {
				claims[name] = value
			}
		}
		// Synthetic proofs use an ephemeral test issuer; they are not credentials
		// trusted by GitHub or any deployment, and are never printed.
		token, err := crypto.SignJWT(signer, "a232-test-issuer", claims)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(token)
	}
	return attestor, sign
}

func TestSignedRunAndAttemptAreRetained(t *testing.T) {
	attestor, sign := testIssuer(t)
	for _, attempt := range []string{"1", "2", "18446744073709551615"} {
		token := sign(map[string]any{"run_attempt": attempt})
		result, err := attestor.Attest(context.Background(), token)
		secret.Wipe(token)
		if err != nil {
			t.Fatalf("valid signed attempt refused: %v", err)
		}
		if result.Claims["run_id"] != "47001" || result.Claims["run_attempt"] != attempt {
			t.Errorf("verified run/attempt were dropped: %+v", result.Claims)
		}
	}
}

func TestMissingOrNoncanonicalSignedAttemptIsRefused(t *testing.T) {
	attestor, sign := testIssuer(t)
	bad := []any{nil, "", "0", "-1", "+1", "01", "1.0", "1e3", " 1", "1 ", "18446744073709551616", strings.Repeat("1", 256), 1, true, map[string]any{"value": "1"}}
	for _, field := range []string{"run_id", "run_attempt"} {
		for index, value := range bad {
			token := sign(map[string]any{field: value})
			_, err := attestor.Attest(context.Background(), token)
			secret.Wipe(token)
			if err == nil {
				t.Errorf("accepted missing/noncanonical signed %s case%d", field, index)
			}
		}
	}
}
