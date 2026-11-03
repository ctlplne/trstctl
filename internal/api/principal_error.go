// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// principalRoles returns the distinct role names a principal holds, for audit
// attribution (the "under what authorization").
func principalRoles(p authz.Principal) []string {
	seen := map[string]bool{}
	var roles []string
	for _, g := range p.Grants {
		if g.Role.Name != "" && !seen[g.Role.Name] {
			seen[g.Role.Name] = true
			roles = append(roles, g.Role.Name)
		}
	}
	return roles
}

// apiError lets a handler choose the problem status for a domain failure.
type apiError struct {
	status int
	detail string
	ext    map[string]any
	// cause is the error a handler classified, kept so a transient datastore
	// condition under it still answers as retryable.
	cause error
}

func (e *apiError) Error() string { return e.detail }

// Unwrap exposes the classified cause.
func (e *apiError) Unwrap() error { return e.cause }

func errStatus(status int, detail string) *apiError {
	return &apiError{status: status, detail: detail}
}

// errStatusFrom is errStatus(status, err.Error()) that keeps err as the cause,
// so a transient condition under it still answers as itself: a busy datastore
// answers 503 with Retry-After on every route, whatever status the handler
// chose for its own errors.
func errStatusFrom(status int, err error) *apiError {
	out := errStatus(status, err.Error())
	out.cause = err
	return out
}
