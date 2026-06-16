package crypto

import (
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Sign-intent attestation / dual-control (RED-003, SIGNER-003 follow-on).
//
// The isolated signer (AN-4) custodies key BYTES; it has never inspected business
// intent — by design the control plane is the policy/RA gate and the signer signs
// the digest it is handed. SIGNER-002/003 added per-key purpose+algorithm
// constraints, which bound WHICH key class a caller may use but not WHAT content
// it signs: a principal that reaches the signer socket with the issuing-CA handle
// and asserts purpose=CA_SIGN can still have the CA key sign sha256(<arbitrary
// attacker TBS>) — the "forge-the-fleet" residual (RED-003).
//
// SignIntent closes that residual for the crown-jewel key classes by binding a
// Sign to an INDEPENDENT authorization that socket access alone cannot forge. An
// approval authority (a dual-control officer, an out-of-band approver, or simply a
// second process that holds the authorizer secret the on-socket attacker does not)
// computes a keyed authorization token over the EXACT signing tuple — the key
// handle, the asserted purpose, the hash/padding, and the digest itself. The
// signer, configured with the same authorizer secret, recomputes and verifies the
// token before it will use a dual-control key. Because the token commits to the
// digest, it authorizes one specific to-be-signed object and cannot be replayed to
// sign different bytes; because the secret is held by the approver and not exposed
// on the socket, a control-plane/socket compromise can no longer coerce the CA key
// into signing anything.
//
// The MAC lives behind the crypto boundary (AN-3): the authorizer key is a
// secret.Buffer ([]byte, mlock'd — AN-8), and the token is HMAC-SHA256. The signer
// imports only internal/crypto, never crypto/* directly.

// ErrNoSignAuthorizer is returned when an authorizer secret is absent.
var ErrNoSignAuthorizer = errors.New("crypto: sign authorizer not configured")

// SignIntent is the exact tuple a dual-control authorization commits to. Every
// field that influences the produced signature is bound, so a token authorizes
// one specific signing operation and nothing else. KeyHandle and Purpose are the
// signer's enum value (an int, carried as the proto KeyPurpose), kept as a plain
// integer here so internal/crypto does not import the signer proto (the signer
// passes its own enum's int value through).
type SignIntent struct {
	KeyHandle string // the signer key-handle id the signature is requested against
	Purpose   int32  // the asserted KeyPurpose enum value
	Hash      Hash   // the digest algorithm
	Padding   RSAPadding
	Digest    []byte // the exact pre-computed digest to be signed
}

// canonicalBytes serializes a SignIntent into an unambiguous, length-prefixed byte
// string so two different intents can never collide under the MAC (a naive
// concatenation would let an attacker shift bytes between fields). A fixed domain
// tag separates this MAC's input space from any other use of the same key.
func (si SignIntent) canonicalBytes() []byte {
	const domain = "trstctl/sign-intent/v1\x00"
	out := make([]byte, 0, len(domain)+len(si.KeyHandle)+len(si.Digest)+32)
	out = append(out, domain...)
	out = appendLenPrefixed(out, []byte(si.KeyHandle))
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(si.Purpose))
	out = append(out, p[:]...)
	out = appendLenPrefixed(out, []byte(string(si.Hash)))
	out = appendLenPrefixed(out, []byte(string(si.Padding)))
	out = appendLenPrefixed(out, si.Digest)
	return out
}

func appendLenPrefixed(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	dst = append(dst, b...)
	return dst
}

// SignAuthorizer mints and verifies dual-control sign authorizations. Its key is
// held in a locked secret buffer (AN-8). The approval side calls Authorize; the
// signer side (which should hold a verify-only authorizer) calls Verify. The two
// sides share the same secret out of band — it is NOT the signer's private key and
// never travels the Sign RPC.
type SignAuthorizer struct {
	key *secret.Buffer
}

// NewSignAuthorizer builds an authorizer from a shared secret. The secret is
// copied into locked memory; the caller should wipe its own copy. A short or empty
// secret is rejected so a misconfiguration cannot create a trivially-forgeable
// gate.
func NewSignAuthorizer(sharedSecret []byte) (*SignAuthorizer, error) {
	if len(sharedSecret) < 16 {
		return nil, errors.New("crypto: sign authorizer secret must be at least 16 bytes")
	}
	buf, err := secret.NewFrom(sharedSecret)
	if err != nil {
		return nil, err
	}
	return &SignAuthorizer{key: buf}, nil
}

// Authorize returns the authorization token for intent: HMAC-SHA256 over the
// intent's canonical bytes under the shared secret. The token is not secret
// itself, but it cannot be produced without the secret.
func (a *SignAuthorizer) Authorize(intent SignIntent) ([]byte, error) {
	if a == nil || a.key == nil {
		return nil, ErrNoSignAuthorizer
	}
	k := a.key.Bytes()
	if k == nil {
		return nil, errors.New("crypto: sign authorizer destroyed")
	}
	return HMACSHA256(k, intent.canonicalBytes()), nil
}

// Verify reports whether token is a valid authorization for intent, comparing in
// constant time. A nil authorizer or empty token fails closed.
func (a *SignAuthorizer) Verify(intent SignIntent, token []byte) bool {
	if a == nil || a.key == nil || len(token) == 0 {
		return false
	}
	want, err := a.Authorize(intent)
	if err != nil {
		return false
	}
	return ConstantTimeEqual(want, token)
}

// Destroy zeroizes the authorizer's secret. It is idempotent.
func (a *SignAuthorizer) Destroy() {
	if a != nil && a.key != nil {
		a.key.Destroy()
	}
}
