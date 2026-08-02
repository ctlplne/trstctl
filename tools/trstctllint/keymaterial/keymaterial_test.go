// SPDX-License-Identifier: MPL-2.0

package keymaterial_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/keymaterial"
)

// TestKeyMaterial exercises AN-8. A package is in scope either by carrying the
// //trstctl:keymaterial marker, or by being a default-on secret primitive
// (internal/crypto/secret, internal/crypto/seal) whose enforcement cannot be
// turned off by removing the marker. In scope, any string-BACKED field, param,
// or result is flagged — including named string types, slices/arrays of string,
// maps with a string value, and pointers to any of those (ARCH-001). Out of
// scope (no marker, not default-on), ordinary string usage is ignored.
func TestKeyMaterial(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), keymaterial.Analyzer,
		"keyhandling", // marker present; string + named/slice/map/array/ptr evasions all flagged
		"cleankeys",   // marker present, []byte only: clean
		"plainpkg",    // no marker, not default-on: ignored
		"sealedcreds", // newly-covered credential package (R3.1): string secret flagged
		"trstctl.com/trstctl/internal/api",
		"trstctl.com/trstctl/internal/authmethod",
		"trstctl.com/trstctl/internal/connector/badkeycopy",
		"trstctl.com/trstctl/internal/kms/badcreds",
		// CRYPTO-003: every provider-credential surface named in the fix_spec is
		// fail-closed, not just kms/connector. These pin the dns, notify, and CA
		// scopes so a future narrowing of providerCredentialScope is caught.
		"trstctl.com/trstctl/internal/dns/badcreds",
		"trstctl.com/trstctl/internal/notify/badcreds",
		"trstctl.com/trstctl/internal/ca/badcreds",
		// internal/config is the operator-supplied INBOUND side of every provider
		// credential (and of the OIDC confidential-client secret). A
		// credential-named string field there is the same AN-8 leak as one in the
		// provider package that reads it, and it is minted earlier — at config
		// load — so it outlives every byte-backed hop downstream. The fixture also
		// pins that the ordinary string knobs beside it stay clean.
		"trstctl.com/trstctl/internal/config",
		"trstctl.com/trstctl/internal/signing",
		// Default-on secret primitive WITHOUT the marker: ARCH-004 fail-closed
		// proof — a forgotten marker does not disable the rule here.
		"trstctl.com/trstctl/internal/crypto/secret",
	)
}

func TestTokenStringRejectedAcrossAPIAndAuthSurfaces(t *testing.T) {
	dir, cleanup, err := analysistest.WriteFiles(map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"trstctl.com/trstctl/internal/api/access.go": `package api

type secretJSONBytes []byte

type badAPITokenCreateResponse struct {
	Token string // want "secret-bearing API/auth field must not use string"
}

type goodAPITokenCreateResponse struct {
	Token secretJSONBytes
}
`,
		"trstctl.com/trstctl/internal/auth/token.go": `package auth

type badTokenResponse struct {
	Token string // want "secret-bearing API/auth field must not use string"
}

type goodTokenResponse struct {
	Token []byte
}
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	analysistest.Run(t, dir, keymaterial.Analyzer,
		"trstctl.com/trstctl/internal/api",
		"trstctl.com/trstctl/internal/auth",
	)
}

func TestKeymaterialBearerTokenStringResidency(t *testing.T) {
	dir, cleanup, err := analysistest.WriteFiles(map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"trstctl.com/trstctl/internal/api/secrets_identity.go": `package api

import "encoding/hex"

func badShareTokenEncoding(tokenRaw []byte) []byte {
	token := []byte(hex.EncodeToString(tokenRaw)) // want "bearer-token code must not encode token bytes to string"
	return token
}
`,
		"trstctl.com/trstctl/internal/agent/enroll/tokens.go": `package enroll

import (
	"context"
	"encoding/base64"
)

type Authority struct{}

type enrollRequest struct {
	Token string ` + "`json:\"token,omitempty\"`" + ` // want "bearer-token field must not use string"
	CSR   string ` + "`json:\"csr\"`" + `
}

func (a *Authority) IssueBootstrapToken(ctx context.Context, tenantID, allowedIdentity string) (string, error) { // want "bearer-token function must not return string"
	return "", nil
}

func (a *Authority) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) { // want "bearer-token parameter must not use string"
	return nil, nil
}

func mintBootstrapToken(raw []byte) []byte {
	token := base64.RawURLEncoding.EncodeToString(raw) // want "bearer-token code must not encode token bytes to string"
	return []byte(token)
}
`,
		"trstctl.com/trstctl/internal/server/enroll.go": `package server

import "context"

type authority struct{}

func (authority) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	return nil, nil
}

type enrollAuthority struct {
	a authority
}

type enrollTokenRequest struct {
	Token []byte
}

func (e enrollAuthority) EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error) {
	req := enrollTokenRequest{Token: token}
	return e.a.EnrollBootstrap(ctx, string(req.Token), csrDER) // want "bearer-token code must not convert token bytes to string"
}
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	analysistest.Run(t, dir, keymaterial.Analyzer,
		"trstctl.com/trstctl/internal/api",
		"trstctl.com/trstctl/internal/agent/enroll",
		"trstctl.com/trstctl/internal/server",
	)
}

func TestKeymaterialSignerAuthorizationTokenStringResidency(t *testing.T) {
	dir, cleanup, err := analysistest.WriteFiles(map[string]string{
		"trstctl.com/trstctl/internal/signing/client.go": `package signing

const signerAuthMetadataKey = "trstctl-sign-auth-token-bin"

func badMetadataToken(signAuthToken []byte) []string {
	return []string{signerAuthMetadataKey, string(signAuthToken)} // want "signer authorization-token code must not convert token bytes to string"
}
`,
		"trstctl.com/trstctl/internal/server/signer_token_command.go": `package server

import (
	"encoding/base64"
	"strings"
)

func badCommandDecode(stdout []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdout))) // want "signer authorization-token command output must not be converted to string before decoding"
}
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	analysistest.Run(t, dir, keymaterial.Analyzer,
		"trstctl.com/trstctl/internal/signing",
		"trstctl.com/trstctl/internal/server",
	)
}
