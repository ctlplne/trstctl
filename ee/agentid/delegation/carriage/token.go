// SPDX-License-Identifier: LicenseRef-trstctl-EE

package carriage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// token.go is the signed-token carriage form (claim 27, third alternative): the bound
// values ride as confirmation-adjacent CLAIMS in a JWT-style token. It reuses the exact
// bindingClaim shape the workload-identity document uses, so the same bound values produce
// byte-identical claim bytes in both forms and one common decoder reads them identically.
//
// Two decode surfaces, both fail-closed on untrusted input:
//   - DecodeToken reads the CLAIMS of a JWT-shaped token WITHOUT verifying the signature.
//     This is the pure carriage round-trip (the RP verifies the credential signature
//     separately). It is what the common Decoder path uses.
//   - DecodeVerifiedToken verifies the token signature through internal/crypto (AN-3,
//     crypto.VerifyJWT) against a JWKS and THEN extracts the bound values, for a caller
//     that wants signature verification and carriage in one step.
//
// AN-3: the SIGNATURE (sign and verify) routes exclusively through internal/crypto
// (crypto.SignJWT / crypto.VerifyJWT). base64/json here are only structural framing for
// reading the claims segment; this file names no crypto/* package.

// tokenClaims is the JWT claims object: the AGID binding under its reserved claim plus the
// optional standard registered claims an issuer sets. Sibling claims a real issuer adds
// are tolerated on decode (the binding is read by name).
type tokenClaims struct {
	Subject  string       `json:"sub,omitempty"`
	Audience string       `json:"aud,omitempty"`
	Issuer   string       `json:"iss,omitempty"`
	Binding  bindingClaim `json:"agid_binding"`
}

// ErrMalformedToken is returned when a token is not a well-formed compact JWS (not three
// dot-separated segments, or a claims segment that is not valid base64url JSON).
var ErrMalformedToken = errors.New("carriage: malformed signed token")

// EncodeSignedToken mints a signed JWT-style token carrying bv as the AGID binding claim,
// signing through the internal/crypto boundary (AN-3, crypto.SignJWT) with the supplied
// DigestSigner (whose private key may live inside the isolated signer). subject/audience/
// issuer are optional standard claims. The returned compact JWS is the carriage form.
func EncodeSignedToken(signer crypto.DigestSigner, kid string, bv BoundValues, subject, audience, issuer string) (string, error) {
	claims := tokenClaims{
		Subject:  subject,
		Audience: audience,
		Issuer:   issuer,
		Binding:  bindingClaimOf(bv),
	}
	return crypto.SignJWT(signer, kid, claims)
}

// DecodeVerifiedToken verifies the token's signature through internal/crypto (AN-3,
// crypto.VerifyJWT) against jwks and returns the bound values from the verified claims. It
// fails closed: a token whose signature does not verify, or whose claims are malformed or
// carry no AGID binding claim, returns an error and no bound values.
func DecodeVerifiedToken(token string, jwks crypto.JWKS) (BoundValues, error) {
	claimsJSON, err := crypto.VerifyJWT(token, jwks)
	if err != nil {
		return BoundValues{}, err
	}
	return boundValuesFromClaims(claimsJSON)
}

// DecodeToken reads the CLAIMS segment of a JWT-shaped token and recovers the bound values
// WITHOUT verifying the signature. It is the pure carriage decode (signature verification
// is the relying party's separate step) and the surface the common Decoder uses. It fails
// closed on a token that is not three segments, whose claims segment is not valid
// base64url JSON, or that carries no AGID binding claim; it never panics on untrusted
// input.
func DecodeToken(token []byte) (BoundValues, error) {
	segs := bytes.Split(token, []byte("."))
	if len(segs) != 3 {
		return BoundValues{}, ErrMalformedToken
	}
	claimsSeg := segs[1]
	claimsJSON := make([]byte, base64.RawURLEncoding.DecodedLen(len(claimsSeg)))
	n, err := base64.RawURLEncoding.Decode(claimsJSON, claimsSeg)
	if err != nil {
		return BoundValues{}, ErrMalformedToken
	}
	return boundValuesFromClaims(claimsJSON[:n])
}

// boundValuesFromClaims extracts the AGID binding claim from a claims JSON blob (shared by
// the verified and unverified token decode paths). It tolerates sibling claims and fails
// closed on malformed JSON or an absent binding claim.
func boundValuesFromClaims(claimsJSON []byte) (BoundValues, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(claimsJSON, &envelope); err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	raw, ok := envelope[agidBindingClaim]
	if !ok {
		return BoundValues{}, ErrNoBindingClaim
	}
	var claim bindingClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	return claim.boundValues(), nil
}

// TokenDecoder adapts the signed-token form to the common Decoder surface. Its Decode
// reads the token CLAIMS (no signature check) so a relying party recovers the bound values
// through one interface across all three forms; the signature is verified separately (or
// via DecodeVerifiedToken).
type TokenDecoder struct{}

// Decode implements Decoder for a JWT-shaped token's bytes (claims only, no signature
// verification).
func (TokenDecoder) Decode(token []byte) (BoundValues, error) { return DecodeToken(token) }

// Kind implements Decoder.
func (TokenDecoder) Kind() string { return "signed-token" }
