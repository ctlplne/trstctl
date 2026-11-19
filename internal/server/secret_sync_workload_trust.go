// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/githubidentity"
	"trstctl.com/trstctl/internal/store"
)

// workloadIdentityTrust resolves effective authority before any cache lookup.
// The verifier is used only in the bounded outbox worker on a cache miss.
func (p *configuredSyncPusher) workloadIdentityTrust(ctx context.Context, source store.SecretSyncWorkloadIdentitySource) (string, func([]byte) error, error) {
	trust, err := p.store.GetEffectiveWorkloadAttesterTrustSource(ctx, p.tenantID, source.TrustSourceID)
	if err != nil {
		return "", nil, err
	}
	if trust.AuthorityPending || !trust.Enabled || trust.RevokedAt != nil || trust.Audience != source.Audience || trust.RequiresImmutableGitHubPin() {
		return "", nil, cloudauth.ErrInvalidWorkloadProof
	}
	// The source update, trust rotation and trust update already scope the
	// cache. The canonical GitHub pin conditions also participate directly.
	cacheKey := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d",
		p.tenantID, source.ID, source.UpdatedAt.UnixNano(), trust.RotationVersion, trust.UpdatedAt.UnixNano())
	issuer := trust.Issuer
	var checkVerifiedClaims func([]byte) error
	if trust.Method == "github_oidc" {
		issuer = githubidentity.EffectiveIssuer(issuer)
		verifier := &githuboidc.Attestor{}
		if err := verifier.ConfigureRepositoryPins(trust.AllowedOwners, trust.AllowedOwnerIDs, trust.AllowedRepositoryIDs); err != nil {
			return "", nil, cloudauth.ErrInvalidWorkloadProof
		}
		conditions, err := json.Marshal(struct {
			Issuer                              string
			OwnerNames, OwnerIDs, RepositoryIDs map[string]bool
		}{issuer, verifier.AllowedOwners, verifier.AllowedOwnerIDs, verifier.AllowedRepositoryIDs})
		if err != nil {
			return "", nil, err
		}
		cacheKey += "\x00" + crypto.SHA256Hex(conditions)
		checkVerifiedClaims = verifier.CheckVerifiedRepositoryPins
	}
	return cacheKey, func(proof []byte) error {
		return cloudauth.ValidateOIDCProof(proof, trust.JWKS, issuer, source.Audience, source.Subject, time.Now().UTC(), checkVerifiedClaims)
	}, nil
}
