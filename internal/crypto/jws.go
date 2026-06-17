package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// This file implements the minimal JOSE (JWS/JWK) surface trstctl needs for
// SPIFFE JWT-SVIDs (signing) and for verifying external OIDC / Kubernetes
// service-account tokens (the S11.7/S11.8 attesters). It lives inside the AN-3
// crypto boundary because it imports crypto/rsa, crypto/ecdsa, and
// crypto/elliptic; no other package may do JWT crypto directly.

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SignJWT builds and signs a compact JWS (a JWT, used for SPIFFE JWT-SVIDs). The
// signing key is a DigestSigner, so the private key may live in the isolated
// signer (AN-4). The JOSE alg is derived from the signer's algorithm.
func SignJWT(signer DigestSigner, kid string, claims any) (string, error) {
	alg, hash, coord, err := joseParams(signer.Algorithm())
	if err != nil {
		return "", err
	}
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal JWT header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal JWT claims: %w", err)
	}
	signingInput := b64url(hb) + "." + b64url(cb)
	digest := hashBytes(hash, []byte(signingInput))
	raw, err := signer.SignDigest(digest, SignOptions{Hash: hash, RSAPadding: RSAPKCS1v15})
	if err != nil {
		return "", fmt.Errorf("crypto: sign JWT: %w", err)
	}
	if strings.HasPrefix(alg, "ES") {
		raw, err = ecdsaDERtoJOSE(raw, coord)
		if err != nil {
			return "", err
		}
	}
	return signingInput + "." + b64url(raw), nil
}

// VerifyJWT verifies a compact JWS against the matching key in jwks (selected by
// the header kid, or the sole key if no kid) and returns the raw claims JSON. It
// checks the signature only; the caller validates iss/aud/exp/nbf.
func VerifyJWT(token string, jwks JWKS) (claimsJSON []byte, err error) {
	return VerifyJWTBytes([]byte(token), jwks)
}

// VerifyJWTBytes verifies a compact JWS token supplied as bytes. Secret-bearing
// authentication paths use this form so they do not need to materialize workload
// credentials as immutable Go strings before entering the crypto boundary.
func VerifyJWTBytes(token []byte, jwks JWKS) (claimsJSON []byte, err error) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("crypto: malformed JWT (want 3 segments)")
	}
	hb := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[0])))
	n, err := base64.RawURLEncoding.Decode(hb, parts[0])
	if err != nil {
		return nil, fmt.Errorf("crypto: JWT header: %w", err)
	}
	hb = hb[:n]
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("crypto: JWT header: %w", err)
	}
	jwk, err := jwks.find(hdr.Kid)
	if err != nil {
		return nil, err
	}
	pub, err := jwk.publicKey()
	if err != nil {
		return nil, err
	}
	sig := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[2])))
	n, err = base64.RawURLEncoding.Decode(sig, parts[2])
	if err != nil {
		return nil, fmt.Errorf("crypto: JWT signature: %w", err)
	}
	sig = sig[:n]
	signingInput := make([]byte, 0, len(parts[0])+1+len(parts[1]))
	signingInput = append(signingInput, parts[0]...)
	signingInput = append(signingInput, '.')
	signingInput = append(signingInput, parts[1]...)
	if err := verifyJOSE(hdr.Alg, pub, signingInput, sig); err != nil {
		return nil, err
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err = base64.RawURLEncoding.Decode(payload, parts[1])
	if err != nil {
		return nil, fmt.Errorf("crypto: JWT payload: %w", err)
	}
	return payload[:n], nil
}

// JWK is the subset of a JSON Web Key needed to verify RS*/ES* tokens and to
// publish a SPIFFE JWT trust bundle.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKS parses a JWKS document (e.g. an OIDC provider's jwks_uri body).
func ParseJWKS(b []byte) (JWKS, error) {
	var s JWKS
	if err := json.Unmarshal(b, &s); err != nil {
		return JWKS{}, fmt.Errorf("crypto: parse JWKS: %w", err)
	}
	return s, nil
}

func (s JWKS) find(kid string) (JWK, error) {
	if kid != "" {
		for _, k := range s.Keys {
			if k.Kid == kid {
				return k, nil
			}
		}
		return JWK{}, fmt.Errorf("crypto: no JWK with kid %q", kid)
	}
	if len(s.Keys) == 1 {
		return s.Keys[0], nil
	}
	return JWK{}, fmt.Errorf("crypto: JWT has no kid and JWKS has %d keys", len(s.Keys))
}

func (k JWK) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("crypto: JWK n: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("crypto: JWK e: %w", err)
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, fmt.Errorf("crypto: JWK e is zero")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	case "EC":
		curve, size := ecCurve(k.Crv)
		if curve == nil {
			return nil, fmt.Errorf("crypto: unsupported JWK crv %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("crypto: JWK x: %w", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("crypto: JWK y: %w", err)
		}
		_ = size
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	default:
		return nil, fmt.Errorf("crypto: unsupported JWK kty %q", k.Kty)
	}
}

// PublicJWK converts a PKIX public key into a JWK for publication in a JWKS, such
// as a SPIFFE JWT trust bundle.
func PublicJWK(pub PublicKey, kid string) (JWK, error) {
	key, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return JWK{}, fmt.Errorf("crypto: parse public key for JWK: %w", err)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA", Kid: kid, Alg: "RS256", Use: "sig",
			N: b64url(k.N.Bytes()),
			E: b64url(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		crv, size := curveName(k.Curve)
		if crv == "" {
			return JWK{}, fmt.Errorf("crypto: unsupported EC curve for JWK")
		}
		xb := make([]byte, size)
		yb := make([]byte, size)
		k.X.FillBytes(xb)
		k.Y.FillBytes(yb)
		return JWK{
			Kty: "EC", Kid: kid, Alg: esAlg(size), Use: "sig", Crv: crv,
			X: b64url(xb), Y: b64url(yb),
		}, nil
	default:
		return JWK{}, fmt.Errorf("crypto: unsupported public key type for JWK")
	}
}

func verifyJOSE(alg string, pub any, signingInput, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("crypto: RSA key required for %s", alg)
		}
		h, ch := rsHash(alg)
		digest := hashBytes(h, signingInput)
		if err := rsa.VerifyPKCS1v15(rp, ch, digest, sig); err != nil {
			return fmt.Errorf("crypto: JWT signature invalid: %w", err)
		}
		return nil
	case strings.HasPrefix(alg, "ES"):
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("crypto: EC key required for %s", alg)
		}
		h, size := esParams(alg)
		digest := hashBytes(h, signingInput)
		if len(sig) != 2*size {
			return fmt.Errorf("crypto: bad ES signature length %d (want %d)", len(sig), 2*size)
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(ep, digest, r, s) {
			return fmt.Errorf("crypto: JWT signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("crypto: unsupported JWT alg %q", alg)
	}
}

func ecdsaDERtoJOSE(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("crypto: parse ECDSA signature: %w", err)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

func hashBytes(h Hash, data []byte) []byte {
	switch h {
	case SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case SHA512:
		s := sha512.Sum512(data)
		return s[:]
	default:
		s := sha256.Sum256(data)
		return s[:]
	}
}

func joseParams(a Algorithm) (alg string, hash Hash, coord int, err error) {
	switch a {
	case ECDSAP256:
		return "ES256", SHA256, 32, nil
	case ECDSAP384:
		return "ES384", SHA384, 48, nil
	case ECDSAP521:
		return "ES512", SHA512, 66, nil
	case RSA2048, RSA3072, RSA4096:
		return "RS256", SHA256, 0, nil
	default:
		return "", "", 0, fmt.Errorf("crypto: no JOSE alg for algorithm %q", a)
	}
}

func ecCurve(crv string) (elliptic.Curve, int) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32
	case "P-384":
		return elliptic.P384(), 48
	case "P-521":
		return elliptic.P521(), 66
	default:
		return nil, 0
	}
}

func curveName(c elliptic.Curve) (string, int) {
	switch c {
	case elliptic.P256():
		return "P-256", 32
	case elliptic.P384():
		return "P-384", 48
	case elliptic.P521():
		return "P-521", 66
	default:
		return "", 0
	}
}

func esAlg(size int) string {
	switch size {
	case 48:
		return "ES384"
	case 66:
		return "ES512"
	default:
		return "ES256"
	}
}

func rsHash(alg string) (Hash, crypto.Hash) {
	switch alg {
	case "RS384":
		return SHA384, crypto.SHA384
	case "RS512":
		return SHA512, crypto.SHA512
	default:
		return SHA256, crypto.SHA256
	}
}

func esParams(alg string) (Hash, int) {
	switch alg {
	case "ES384":
		return SHA384, 48
	case "ES512":
		return SHA512, 66
	default:
		return SHA256, 32
	}
}
