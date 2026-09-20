// SPDX-License-Identifier: BUSL-1.1

package cloudcert

import "context"

// TokenProvider supplies a bearer token for a provider API (Azure AD, GCP). A
// production provider fetches and caches an OAuth token; tests use StaticToken.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

type staticToken string

// StaticToken returns a TokenProvider that always yields the given token.
func StaticToken(tok string) TokenProvider { return staticToken(tok) }

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
