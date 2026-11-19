// SPDX-License-Identifier: BUSL-1.1

package githuboidc

import (
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/githubidentity"
)

// CR-384: operators can match the verified numerical coordinates to their
// trust policy even when GitHub uses the classic subject format.
func TestGitHubOIDCRecordsVerifiedRepositoryIDs(t *testing.T) {
	attestor, token := repositoryClaimFixture(t)
	verified, err := attestor.Attest(t.Context(), token(func(claims map[string]any) {
		claims["repository_owner_id"] = "9007199254740993"
		claims["repository_id"] = "18446744073709551615"
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, coordinate := range []struct{ claim, want string }{
		{"repository_owner_id", "9007199254740993"},
		{"repository_id", "18446744073709551615"},
	} {
		if got := verified.Claims[coordinate.claim]; got != coordinate.want {
			t.Errorf("verified claim %s = %q, want %s", coordinate.claim, got, coordinate.want)
		}
		if !slices.Contains(verified.Selectors, "github:"+coordinate.claim+":"+coordinate.want) {
			t.Errorf("verified selectors omitted %s", coordinate.claim)
		}
	}
}

// CR-384: a claim that is present must have the canonical string form used by
// the policy and the audit trail.
func TestGitHubOIDCRejectsMalformedRepositoryIDs(t *testing.T) {
	attestor, token := repositoryClaimFixture(t)
	for _, claim := range []string{"repository_owner_id", "repository_id"} {
		for _, tc := range []struct {
			name  string
			value any
		}{
			{"null", nil},
			{"number", 123},
			{"empty", ""},
			{"zero", "0"},
			{"leading-zero", "0123"},
			{"space", " 123"},
			{"sign", "+123"},
			{"nondecimal", "12e3"},
			{"out-of-range", "18446744073709551616"},
		} {
			t.Run(claim+"/"+tc.name, func(t *testing.T) {
				proof := token(func(claims map[string]any) { claims[claim] = tc.value })
				if _, err := attestor.Attest(t.Context(), proof); err == nil {
					t.Fatal("token with a malformed repository coordinate was accepted")
				}
			})
		}
	}
}

// CR-384: a name condition needs immutable pin material before it can
// authorize GitHub attestation.
func TestGitHubOIDCNameConditionRequiresImmutablePin(t *testing.T) {
	attestor, token := repositoryClaimFixture(t)
	attestor.AllowedOwners = map[string]bool{"acme": true}
	if _, err := attestor.Attest(t.Context(), token(nil)); err == nil {
		t.Fatal("a name-only condition authorized attestation")
	}
}

func TestGitHubOIDCChecksEveryConfiguredRepositoryPin(t *testing.T) {
	attestor, token := repositoryClaimFixture(t)
	owners := map[string]bool{"123": true}
	repositories := map[string]bool{"456": true}
	for _, tc := range []struct {
		name                  string
		ownerPins, repoPins   map[string]bool
		ownerID, repositoryID string
		allowed               bool
	}{
		{"ordinary unpinned proof", nil, nil, "", "", true},
		{"owner pin", owners, nil, "123", "", true},
		{"different owner ID", owners, nil, "124", "456", false},
		{"missing owner ID", owners, nil, "", "456", false},
		{"repository pin", nil, repositories, "124", "456", true},
		{"different repository ID", nil, repositories, "123", "457", false},
		{"missing repository ID", nil, repositories, "123", "", false},
		{"both pin lists match", owners, repositories, "123", "456", true},
		{"only owner list matches", owners, repositories, "123", "457", false},
		{"only repository list matches", owners, repositories, "124", "456", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configured := *attestor
			configured.AllowedOwnerIDs = tc.ownerPins
			configured.AllowedRepositoryIDs = tc.repoPins
			proof := token(func(claims map[string]any) {
				if tc.ownerID != "" {
					claims[repositoryOwnerIDClaim] = tc.ownerID
				}
				if tc.repositoryID != "" {
					claims[repositoryIDClaim] = tc.repositoryID
				}
			})
			if _, err := configured.Attest(t.Context(), proof); (err == nil) != tc.allowed {
				t.Errorf("authorized = %t, want %t, verification error %v", err == nil, tc.allowed, err)
			}
		})
	}
}

func TestGitHubOIDCChecksPinsWithinExactIssuerForBothSubjectFormats(t *testing.T) {
	attestor, token := repositoryClaimFixture(t)
	if err := attestor.ConfigureRepositoryPins([]string{"ACME"}, []string{"123"}, []string{"456"}); err != nil {
		t.Fatal(err)
	}
	const enterpriseIssuer = "https://git.example.test/_services/token"
	const classic = "repo:acme/payments:ref:refs/heads/main"
	const immutable = "repo:acme@123/payments@456:ref:refs/heads/main"
	for _, tc := range []struct {
		name, issuer, signedIssuer, subject string
		repositoryID                        string
		allowed                             bool
	}{
		{"GitHub.com classic subject", "", DefaultIssuer, classic, "456", true},
		{"GitHub.com immutable subject", "", DefaultIssuer, immutable, "456", true},
		{"immutable subject with a different signed repository ID", "", DefaultIssuer, immutable, "789", false},
		{"immutable subject lacks a separate signed repository ID", "", DefaultIssuer, immutable, "", false},
		{"enterprise classic subject", enterpriseIssuer, enterpriseIssuer, classic, "456", true},
		{"identical pins in another issuer namespace", enterpriseIssuer, DefaultIssuer, classic, "456", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := *attestor
			verifier.Issuer = tc.issuer
			proof := token(func(claims map[string]any) {
				claims["iss"], claims["sub"], claims["repository_owner"] = tc.signedIssuer, tc.subject, "acme"
				claims[repositoryOwnerIDClaim] = "123"
				delete(claims, repositoryIDClaim)
				if tc.repositoryID != "" {
					claims[repositoryIDClaim] = tc.repositoryID
				}
			})
			got, err := verifier.Attest(t.Context(), proof)
			if (err == nil) != tc.allowed {
				t.Fatalf("accepted=%t, want %t, err=%v", err == nil, tc.allowed, err)
			}
			if tc.allowed && (got.Subject != tc.subject || got.Claims[repositoryIDClaim] != "456") {
				t.Fatal("verification changed the subject or lost the signed repository ID")
			}
		})
	}
}

func TestNormalizePinIDs(t *testing.T) {
	ids := []string{"9007199254740993", "123", "123"}
	got, err := githubidentity.NormalizeIDs(ids)
	if err != nil || !slices.Equal(got, []string{"123", "9007199254740993"}) {
		t.Fatalf("normalized pins = %v, error %v", got, err)
	}
	if ids[0] != "9007199254740993" {
		t.Fatal("normalization changed the caller's pin order")
	}
	if empty, err := githubidentity.NormalizeIDs([]string{}); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("explicit empty list = %#v, error %v", empty, err)
	}
	if omitted, err := githubidentity.NormalizeIDs(nil); err != nil || omitted != nil {
		t.Fatalf("omitted list = %#v, error %v", omitted, err)
	}
	if _, err := githubidentity.NormalizeIDs([]string{"0123"}); err == nil {
		t.Fatal("accepted a noncanonical configured ID")
	}
}

func repositoryClaimFixture(t *testing.T) (*Attestor, func(func(map[string]any)) []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "repository-claims")
	if err != nil {
		t.Fatal(err)
	}
	return &Attestor{JWKS: crypto.JWKS{Keys: []crypto.JWK{jwk}}, Audience: "trstctl"},
		func(mutate func(map[string]any)) []byte {
			return []byte(ghToken(t, signer, "repository-claims", mutate))
		}
}
