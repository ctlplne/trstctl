// SPDX-License-Identifier: BUSL-1.1

package attest

import (
	"maps"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/githubidentity"
)

// WithoutGitHubRepositoryIDEvidence returns the historical authorization view.
// Existing command bindings and operator-selected SSH principal matching use
// this view, so GitHub's immutable repository IDs remain evidence only.
// The caller's evidence, including its map and selector order, stays intact.
func (a Attestation) WithoutGitHubRepositoryIDEvidence() Attestation {
	if a.Method != "github_oidc" {
		return a
	}
	a.Claims = maps.Clone(a.Claims)
	delete(a.Claims, githubidentity.RepositoryOwnerIDClaim)
	delete(a.Claims, githubidentity.RepositoryIDClaim)
	a.Selectors = slices.DeleteFunc(slices.Clone(a.Selectors), func(selector string) bool {
		return strings.HasPrefix(selector, "github:"+githubidentity.RepositoryOwnerIDClaim+":") ||
			strings.HasPrefix(selector, "github:"+githubidentity.RepositoryIDClaim+":")
	})
	return a
}
