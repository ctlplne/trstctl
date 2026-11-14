// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"time"

	"trstctl.com/trstctl/internal/events"
)

// EventTokenExchanged records one OAuth token exchange (RFC 8693, M4): which
// login method verified the subject token, the workload it named, and the
// JWT-SVID issued for it. Audit evidence only; no read model.
const EventTokenExchanged = "token.exchanged"

// TokenExchanged is the payload of token.exchanged. SubjectTokenDigest is a
// SHA-256 of the presented token, never the token.
type TokenExchanged struct {
	Method             string    `json:"method"`
	Principal          string    `json:"principal"`
	SPIFFEID           string    `json:"spiffe_id"`
	Audience           []string  `json:"audience"`
	Scopes             []string  `json:"scopes,omitempty"`
	JTI                string    `json:"jti"`
	ExpiresAt          time.Time `json:"expires_at"`
	SubjectTokenDigest string    `json:"subject_token_digest"`
	// IssuedTokenType is the RFC 8693 type issued: a JWT-SVID
	// (urn:ietf:params:oauth:token-type:jwt) or an RFC 9068 JWT access token
	// (…:access_token, M4-L3). Empty in exchanges recorded before M4-L3,
	// which issued JWT-SVIDs only.
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// Opaque is an access token issued as an opaque reference its resource
	// server introspects (M4-L3); the reference itself is never recorded.
	Opaque bool `json:"opaque,omitempty"`
}

func init() {
	knownSchemaVersions[EventTokenExchanged] = map[int]bool{1: true}
}

// applyTokenExchangedTx accepts the audit-only event.
func applyTokenExchangedTx(e events.Event) (bool, error) {
	if e.Type != EventTokenExchanged {
		return false, nil
	}
	var pl TokenExchanged
	return true, decode(e, &pl)
}
