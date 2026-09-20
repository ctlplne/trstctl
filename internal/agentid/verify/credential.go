// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// credential.go models the CREDENTIAL a caller presents and performs, offline,
// the two credential-level steps: recover the bound values from the presented
// carriage form (AGID-08 decoders), verify the signature against the trust root,
// and determine the validity WINDOW from the credential alone (AGID-claim-7). It
// constructs NO network client and issues NO query for a credential's revocation state: the trust
// root is caller-pinned, and validity is read from the credential's own bytes.

// Form names the carriage form a credential is presented in, so a relying party
// can select the matching trust-root material and the verifier can route to the
// right decoder + signature check. It mirrors carriage.Decoder.Kind().
type Form string

const (
	// FormX509 is the X.509 non-critical-extension carriage form: Bytes is a
	// DER-encoded certificate. Signature comes from the certificate chaining to the
	// trusted CA (TrustRoot.CACertDER).
	FormX509 Form = "x509"
	// FormWorkloadIdentity is the workload-identity-document form: Bytes is the
	// document JSON. The signature is a detached signature over the canonical bytes
	// the caller presents in Credential.Signature, verified against
	// TrustRoot.IssuerPublicDER.
	FormWorkloadIdentity Form = "workload-identity"
	// FormSignedToken is the signed-token (compact JWS) form: Bytes is the token. The
	// signature is verified in-band against TrustRoot.JWKSJSON (by kid) or, when a
	// detached signature is presented, against TrustRoot.IssuerPublicDER.
	FormSignedToken Form = "signed-token"
)

// Credential is a presented AGID credential: the carriage form, its serialized
// bytes, and (for the detached-signature forms) the signature material the caller
// received alongside it. The caller supplies everything; the verifier fetches
// nothing.
type Credential struct {
	// Form is the carriage form of Bytes.
	Form Form
	// Bytes is the serialized credential in its carriage form (a DER certificate, a
	// workload-identity document JSON, or a compact-JWS token).
	Bytes []byte

	// Signature is the detached signature over Bytes for the workload-identity form
	// (and, when the caller chooses detached verification, the signed-token form).
	// Ignored for the X.509 form (whose signature is the certificate's own, checked
	// by chaining to the CA) and for the in-band signed-token path (whose signature
	// is the token's third segment). It is a SHA-256 signature in the shape
	// crypto.VerifyMessage expects (ECDSA ASN.1 or RSA PKCS#1 v1.5).
	Signature []byte

	// ValidityWindow, when set, is the caller-supplied validity bound for a form that
	// does not carry its own (e.g. a bare workload-identity document the caller
	// already parsed). When the presented form carries its own window (an X.509
	// certificate's NotBefore/NotAfter, or a token's nbf/exp claims), that bound is
	// used and this is ignored. It lets the offline short-TTL check apply to every
	// form without a network fetch.
	ValidityWindow *Window
}

// Window is a validity window as inclusive Unix-second bounds, matching the
// taskenv/delegation Window semantics: a zero bound means "unbounded" on that
// side. It is the credential's own short-TTL lifetime (AGID-claim-7); the verifier
// reads it from the credential and checks it against the caller's clock with NO
// status query.
type Window struct {
	NotBefore int64
	NotAfter  int64
}

// within reports whether ts (Unix seconds) falls within the window (inclusive). A
// zero NotBefore/NotAfter is treated as "no bound" on that side, mirroring
// taskenv.withinNow so envelope expiry and credential validity share semantics.
func (w Window) within(ts int64) bool {
	if w.NotBefore != 0 && ts < w.NotBefore {
		return false
	}
	if w.NotAfter != 0 && ts > w.NotAfter {
		return false
	}
	return true
}

// zero reports whether the window imposes no bound at all.
func (w Window) zero() bool { return w.NotBefore == 0 && w.NotAfter == 0 }

// Credential-level errors, all fail-closed.
var (
	// ErrUnknownForm is returned when Credential.Form is not one of the three
	// carriage forms.
	ErrUnknownForm = errors.New("verify: unknown credential carriage form")
	// ErrNoTrustRoot is returned when no trust-root material matching the presented
	// form is configured, so the signature cannot be anchored. Fail-closed: an
	// unanchored credential is never trusted.
	ErrNoTrustRoot = errors.New("verify: no trust root configured for the presented carriage form")
	// ErrSignatureInvalid is returned when the credential's signature does not verify
	// against the trust root (a tampered or wrongly-signed credential).
	ErrSignatureInvalid = errors.New("verify: credential signature does not verify against the trust root")
	// ErrNoValidityWindow is returned when a short-TTL validity check is requested
	// but the credential carries no validity window and none was supplied. Fail-closed:
	// a credential with no determinable lifetime is not honored (a missing TTL is not
	// "valid forever").
	ErrNoValidityWindow = errors.New("verify: credential carries no determinable validity window")
	// ErrCredentialExpired is returned when the caller's clock falls outside the
	// credential's validity window (expired or not yet valid). Determined from the
	// credential alone -- no query for a credential's revocation state.
	ErrCredentialExpired = errors.New("verify: credential is expired or not yet valid")
)

// decodeAndVerify recovers the bound values from the presented form and verifies
// the credential signature against the trust root, entirely offline. It returns
// the bound values and the validity window read from the credential. It is
// fail-closed: an unknown form, a missing trust root, a decode failure, or a
// signature failure returns an error and no values.
//
// It constructs no network client. crypto.ParseJWKS parses caller-pinned bytes;
// crypto.VerifyJWT/VerifyMessage/VerifyLeafSignedByCA verify against caller-pinned
// keys; carriage.*Decoder decodes bytes. Nothing here dials, and no status
// endpoint is consulted.
func decodeAndVerify(cred Credential, root TrustRoot) (carriage.BoundValues, Window, error) {
	switch cred.Form {
	case FormX509:
		return decodeAndVerifyX509(cred, root)
	case FormWorkloadIdentity:
		return decodeAndVerifyWorkload(cred, root)
	case FormSignedToken:
		return decodeAndVerifyToken(cred, root)
	default:
		return carriage.BoundValues{}, Window{}, ErrUnknownForm
	}
}

// decodeAndVerifyX509 verifies the certificate chains to the pinned CA (offline,
// single-CA, no path fetch) and recovers the bound values from the AGID
// non-critical extension. The validity window is the certificate's own
// NotBefore/NotAfter.
func decodeAndVerifyX509(cred Credential, root TrustRoot) (carriage.BoundValues, Window, error) {
	if len(root.CACertDER) == 0 {
		return carriage.BoundValues{}, Window{}, ErrNoTrustRoot
	}
	// Signature: the credential certificate must be signed by the pinned CA. This is
	// the offline trust-root check -- no AIA/OCSP/CRL fetch.
	if err := crypto.VerifyLeafSignedByCA(cred.Bytes, root.CACertDER); err != nil {
		return carriage.BoundValues{}, Window{}, ErrSignatureInvalid
	}
	bv, err := carriage.DecodeCertificate(cred.Bytes)
	if err != nil {
		return carriage.BoundValues{}, Window{}, err
	}
	win := Window{}
	if nb, na, verr := crypto.CertValidity(cred.Bytes); verr == nil {
		win = Window{NotBefore: nb.Unix(), NotAfter: na.Unix()}
	}
	if win.zero() && cred.ValidityWindow != nil {
		win = *cred.ValidityWindow
	}
	return bv, win, nil
}

// decodeAndVerifyWorkload recovers the bound values from the workload-identity
// document and verifies the caller-presented detached signature over the document
// bytes against the pinned issuer key. The validity window is read from the
// document's standard nbf/exp claims when present, else from the caller-supplied
// ValidityWindow.
func decodeAndVerifyWorkload(cred Credential, root TrustRoot) (carriage.BoundValues, Window, error) {
	if len(root.IssuerPublicDER) == 0 {
		return carriage.BoundValues{}, Window{}, ErrNoTrustRoot
	}
	if len(cred.Signature) == 0 {
		return carriage.BoundValues{}, Window{}, ErrSignatureInvalid
	}
	if err := crypto.VerifyMessage(root.IssuerPublicDER, cred.Bytes, cred.Signature); err != nil {
		return carriage.BoundValues{}, Window{}, ErrSignatureInvalid
	}
	bv, err := carriage.DecodeWorkloadDoc(cred.Bytes)
	if err != nil {
		return carriage.BoundValues{}, Window{}, err
	}
	win := windowFromStandardClaims(cred.Bytes)
	if win.zero() && cred.ValidityWindow != nil {
		win = *cred.ValidityWindow
	}
	return bv, win, nil
}

// decodeAndVerifyToken verifies the signed-token signature and recovers the bound
// values. Two offline paths: an in-band JWS verified against the pinned static
// JWKS (crypto.VerifyJWT, by kid) or a detached signature over the token bytes
// verified against the pinned issuer key. The validity window is read from the
// token's standard nbf/exp claims when present, else from ValidityWindow.
func decodeAndVerifyToken(cred Credential, root TrustRoot) (carriage.BoundValues, Window, error) {
	verified := false
	if len(root.JWKSJSON) > 0 {
		jwks, err := crypto.ParseJWKS(root.JWKSJSON)
		if err != nil {
			return carriage.BoundValues{}, Window{}, ErrNoTrustRoot
		}
		claims, err := crypto.VerifyJWTBytes(cred.Bytes, jwks)
		if err != nil {
			return carriage.BoundValues{}, Window{}, ErrSignatureInvalid
		}
		secret.Wipe(claims)
		verified = true
	} else if len(root.IssuerPublicDER) > 0 && len(cred.Signature) > 0 {
		// Detached-signature path over the whole token bytes.
		if err := crypto.VerifyMessage(root.IssuerPublicDER, cred.Bytes, cred.Signature); err != nil {
			return carriage.BoundValues{}, Window{}, ErrSignatureInvalid
		}
		verified = true
	}
	if !verified {
		return carriage.BoundValues{}, Window{}, ErrNoTrustRoot
	}
	bv, err := carriage.DecodeToken(cred.Bytes)
	if err != nil {
		return carriage.BoundValues{}, Window{}, err
	}
	win := windowFromTokenClaimsSegment(cred.Bytes)
	if win.zero() && cred.ValidityWindow != nil {
		win = *cred.ValidityWindow
	}
	return bv, win, nil
}

// standardClaims are the OPTIONAL registered validity claims a real issuer sets on
// a workload-identity document or token alongside the AGID binding claim. The
// verifier reads them (never requires them) to bound the credential's lifetime
// offline. iat is read for completeness but not enforced.
type standardClaims struct {
	NotBefore int64 `json:"nbf"`
	Expiry    int64 `json:"exp"`
	IssuedAt  int64 `json:"iat"`
}

// windowFromStandardClaims reads nbf/exp from a workload-identity document's JSON.
// A document without those claims yields a zero window (the caller's
// ValidityWindow, if any, then applies).
func windowFromStandardClaims(docJSON []byte) Window {
	var c standardClaims
	if err := json.Unmarshal(docJSON, &c); err != nil {
		return Window{}
	}
	return Window{NotBefore: c.NotBefore, NotAfter: c.Expiry}
}

// windowFromTokenClaimsSegment decodes the CLAIMS segment of a compact JWS and
// reads its nbf/exp. It does not verify the signature (that is done separately);
// it only reads validity bounds from the already-decoded credential. A token
// without those claims yields a zero window.
func windowFromTokenClaimsSegment(token []byte) Window {
	segs := bytes.Split(token, []byte("."))
	if len(segs) != 3 {
		return Window{}
	}
	claimsJSON := make([]byte, base64.RawURLEncoding.DecodedLen(len(segs[1])))
	n, err := base64.RawURLEncoding.Decode(claimsJSON, segs[1])
	if err != nil {
		return Window{}
	}
	return windowFromStandardClaims(claimsJSON[:n])
}

// checkValidity decides a credential's validity from the credential alone at the
// clock's instant (AGID-claim-7). It is fail-closed: an absent window is not "valid
// forever" -- when a validity check is demanded and no window is determinable, the
// credential is refused (ErrNoValidityWindow). No query for a credential's revocation state is
// issued; only the bound window and the caller's clock decide.
func checkValidity(win Window, clk Clock, requireWindow bool) error {
	if win.zero() {
		if requireWindow {
			return ErrNoValidityWindow
		}
		return nil
	}
	now := clk.Now().Unix()
	if !win.within(now) {
		return ErrCredentialExpired
	}
	return nil
}
