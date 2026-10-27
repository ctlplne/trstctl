// SPDX-License-Identifier: BUSL-1.1

// Package present names how an agent presents its delegated credential to a
// relying service: on every request, in two headers.
package present

const (
	// CredentialHeader carries the standard base64 of the credential's DER.
	CredentialHeader = "X-Trstctl-Agent-Credential" // #nosec G101 -- a public header name, not a credential value (CWE-798)
	// CredentialIDHeader carries the ID trstctl issued the credential under.
	CredentialIDHeader = "X-Trstctl-Agent-Credential-Id" // #nosec G101 -- a public header name, not a credential value (CWE-798)
)
