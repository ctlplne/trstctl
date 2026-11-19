// SPDX-License-Identifier: BUSL-1.1

package githuboidc

import (
	"encoding/json"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/githubidentity"
)

const (
	repositoryOwnerIDClaim = githubidentity.RepositoryOwnerIDClaim
	repositoryIDClaim      = githubidentity.RepositoryIDClaim
)

var errImmutablePinRequired = errors.New("github_oidc: an owner name condition requires an immutable owner or repository pin")

type repositoryClaims struct {
	RepositoryOwner string          `json:"repository_owner"`
	OwnerID         json.RawMessage `json:"repository_owner_id"`
	RepositoryID    json.RawMessage `json:"repository_id"`
}

type verifiedRepositoryIDs struct {
	owner      string
	repository string
}

// ConfigureRepositoryPins binds the verifier to reviewed owner and repository
// conditions in its configured issuer namespace.
func (a *Attestor) ConfigureRepositoryPins(owners, ownerIDs, repositoryIDs []string) error {
	canonicalOwners, err := githubidentity.NormalizeIDs(ownerIDs)
	if err != nil {
		return err
	}
	canonicalRepositories, err := githubidentity.NormalizeIDs(repositoryIDs)
	if err != nil {
		return err
	}
	names := make(map[string]bool, len(owners))
	for _, owner := range owners {
		if name := strings.TrimSpace(owner); name != "" {
			names[name] = true
		}
	}
	a.AllowedOwners = names
	a.AllowedOwnerIDs = pinMembership(canonicalOwners)
	a.AllowedRepositoryIDs = pinMembership(canonicalRepositories)
	return nil
}

func pinMembership(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// CheckVerifiedRepositoryPins applies the policy to authenticated claims. The
// caller must verify the signature, issuer, audience and applicable token
// bindings first. It does not retain the claims buffer.
func (a *Attestor) CheckVerifiedRepositoryPins(claimsJSON []byte) error {
	var claims repositoryClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return errors.New("github_oidc: invalid repository claims")
	}
	_, err := a.verifyRepositoryPins(claims)
	return err
}

func (a *Attestor) verifyRepositoryPins(claims repositoryClaims) (verifiedRepositoryIDs, error) {
	ownerID, err := parseRepositoryID(claims.OwnerID)
	if err != nil {
		return verifiedRepositoryIDs{}, errors.New("github_oidc: invalid repository_owner_id claim")
	}
	repositoryID, err := parseRepositoryID(claims.RepositoryID)
	if err != nil {
		return verifiedRepositoryIDs{}, errors.New("github_oidc: invalid repository_id claim")
	}
	if len(a.AllowedOwners) > 0 && len(a.AllowedOwnerIDs) == 0 && len(a.AllowedRepositoryIDs) == 0 {
		return verifiedRepositoryIDs{}, errImmutablePinRequired
	}
	if len(a.AllowedOwnerIDs) > 0 && (ownerID == "" || !a.AllowedOwnerIDs[ownerID]) {
		return verifiedRepositoryIDs{}, errors.New("github_oidc: signed repository owner ID did not match the configured pins")
	}
	if len(a.AllowedRepositoryIDs) > 0 && (repositoryID == "" || !a.AllowedRepositoryIDs[repositoryID]) {
		return verifiedRepositoryIDs{}, errors.New("github_oidc: signed repository ID did not match the configured pins")
	}
	if len(a.AllowedOwners) > 0 && !a.ownerAllowed(claims.RepositoryOwner) {
		return verifiedRepositoryIDs{}, errors.New("github_oidc: signed repository owner name did not match the configured condition")
	}
	return verifiedRepositoryIDs{owner: ownerID, repository: repositoryID}, nil
}

func parseRepositoryID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || !githubidentity.ValidID(id) {
		return "", errors.New("github_oidc: repository ID must be a canonical positive decimal string")
	}
	return id, nil
}

func (ids verifiedRepositoryIDs) addEvidence(verified *attest.Attestation) {
	for _, field := range []struct{ key, value string }{
		{repositoryOwnerIDClaim, ids.owner},
		{repositoryIDClaim, ids.repository},
	} {
		if field.value != "" {
			verified.Claims[field.key] = field.value
			verified.Selectors = append(verified.Selectors, "github:"+field.key+":"+field.value)
		}
	}
}
