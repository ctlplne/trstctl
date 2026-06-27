package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

var (
	ErrIntuneChallengeMalformed      = errors.New("intune challenge: malformed compact JWS")
	ErrIntuneChallengeSignature      = errors.New("intune challenge: signature verification failed")
	ErrIntuneChallengeExpired        = errors.New("intune challenge: expired")
	ErrIntuneChallengeNotYetValid    = errors.New("intune challenge: not yet valid")
	ErrIntuneChallengeWrongAudience  = errors.New("intune challenge: wrong audience")
	ErrIntuneChallengeUnknownVersion = errors.New("intune challenge: unknown version")
	ErrIntuneChallengeCSRSubject     = errors.New("intune challenge: CSR subject does not match claim")
	ErrIntuneChallengeCSRSAN         = errors.New("intune challenge: CSR SAN set does not match claim")
)

// IntuneChallengeOptions configures Intune dynamic SCEP challenge verification.
// TrustAnchorsDER are operator-pinned connector signing certificates.
type IntuneChallengeOptions struct {
	TrustAnchorsDER    [][]byte
	ExpectedAudience   string
	Now                time.Time
	ClockSkewTolerance time.Duration
}

// IntuneChallengeClaim is the verified v1 Intune dynamic challenge payload.
type IntuneChallengeClaim struct {
	Issuer     string
	Subject    string
	Audience   string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Nonce      string
	DeviceName string
	SANDNS     []string
	SANRFC822  []string
	SANUPN     []string
}

type intuneJWSHeader struct {
	Alg string `json:"alg"`
}

type intuneVersionProbe struct {
	Version string `json:"version,omitempty"`
}

type intunePayloadV1 struct {
	Version    string   `json:"version,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   string   `json:"aud,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
	Nonce      string   `json:"nonce,omitempty"`
	DeviceName string   `json:"device_name,omitempty"`
	SANDNS     []string `json:"san_dns,omitempty"`
	SANRFC822  []string `json:"san_rfc822,omitempty"`
	SANUPN     []string `json:"san_upn,omitempty"`
}

// ValidateIntuneSCEPChallenge verifies a Microsoft Intune dynamic SCEP challenge
// and checks that its device claims match the CSR. It keeps JOSE, X.509, RSA, and
// ECDSA parsing inside the AN-3 boundary.
func ValidateIntuneSCEPChallenge(raw string, csrDER []byte, opts IntuneChallengeOptions) (IntuneChallengeClaim, error) {
	if strings.TrimSpace(raw) == "" {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: empty challenge", ErrIntuneChallengeMalformed)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: expected three non-empty segments", ErrIntuneChallengeMalformed)
	}
	headerJSON, err := b64urlDecode(parts[0])
	if err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: header: %v", ErrIntuneChallengeMalformed, err)
	}
	payloadJSON, err := b64urlDecode(parts[1])
	if err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: payload: %v", ErrIntuneChallengeMalformed, err)
	}
	signature, err := b64urlDecode(parts[2])
	if err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: signature: %v", ErrIntuneChallengeMalformed, err)
	}
	var hdr intuneJWSHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: header JSON: %v", ErrIntuneChallengeMalformed, err)
	}
	trust, err := parseIntuneTrust(opts.TrustAnchorsDER)
	if err != nil {
		return IntuneChallengeClaim{}, err
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifyIntuneJWSSignature(hdr.Alg, signingInput, signature, trust); err != nil {
		return IntuneChallengeClaim{}, err
	}
	claim, err := parseIntuneClaim(payloadJSON)
	if err != nil {
		return IntuneChallengeClaim{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tolerance := opts.ClockSkewTolerance
	if tolerance < 0 {
		tolerance = -tolerance
	}
	if !claim.IssuedAt.IsZero() && now.Add(tolerance).Before(claim.IssuedAt) {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: iat=%s", ErrIntuneChallengeNotYetValid, claim.IssuedAt.Format(time.RFC3339))
	}
	if !claim.ExpiresAt.IsZero() && !now.Add(-tolerance).Before(claim.ExpiresAt) {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: exp=%s", ErrIntuneChallengeExpired, claim.ExpiresAt.Format(time.RFC3339))
	}
	if opts.ExpectedAudience != "" && claim.Audience != "" && claim.Audience != opts.ExpectedAudience {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: claim=%q expected=%q", ErrIntuneChallengeWrongAudience, claim.Audience, opts.ExpectedAudience)
	}
	if err := intuneClaimMatchesCSR(claim, csrDER); err != nil {
		return IntuneChallengeClaim{}, err
	}
	return claim, nil
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseIntuneTrust(anchors [][]byte) ([]*x509.Certificate, error) {
	if len(anchors) == 0 {
		return nil, fmt.Errorf("%w: no trust anchors configured", ErrIntuneChallengeSignature)
	}
	out := make([]*x509.Certificate, 0, len(anchors))
	for _, der := range anchors {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse trust anchor: %v", ErrIntuneChallengeSignature, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func verifyIntuneJWSSignature(alg string, signingInput, signature []byte, trust []*x509.Certificate) error {
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		for _, cert := range trust {
			pub, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				continue
			}
			if err := rsa.VerifyPKCS1v15(pub, stdcrypto.SHA256, digest[:], signature); err == nil {
				return nil
			}
		}
	case "ES256":
		for _, cert := range trust {
			pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				continue
			}
			if len(signature) == 64 {
				r := new(big.Int).SetBytes(signature[:32])
				s := new(big.Int).SetBytes(signature[32:])
				if ecdsa.Verify(pub, digest[:], r, s) {
					return nil
				}
			}
			if ecdsa.VerifyASN1(pub, digest[:], signature) {
				return nil
			}
		}
	case "":
		return fmt.Errorf("%w: missing alg", ErrIntuneChallengeSignature)
	case "none":
		return fmt.Errorf("%w: alg none rejected", ErrIntuneChallengeSignature)
	default:
		return fmt.Errorf("%w: unsupported alg %q", ErrIntuneChallengeSignature, alg)
	}
	return ErrIntuneChallengeSignature
}

func parseIntuneClaim(payloadJSON []byte) (IntuneChallengeClaim, error) {
	var probe intuneVersionProbe
	if err := json.Unmarshal(payloadJSON, &probe); err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: version probe: %v", ErrIntuneChallengeMalformed, err)
	}
	if probe.Version != "" && probe.Version != "v1" {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: %q", ErrIntuneChallengeUnknownVersion, probe.Version)
	}
	var p intunePayloadV1
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return IntuneChallengeClaim{}, fmt.Errorf("%w: payload JSON: %v", ErrIntuneChallengeMalformed, err)
	}
	claim := IntuneChallengeClaim{
		Issuer:     p.Issuer,
		Subject:    p.Subject,
		Audience:   p.Audience,
		Nonce:      p.Nonce,
		DeviceName: p.DeviceName,
		SANDNS:     append([]string(nil), p.SANDNS...),
		SANRFC822:  append([]string(nil), p.SANRFC822...),
		SANUPN:     append([]string(nil), p.SANUPN...),
	}
	if p.IssuedAt > 0 {
		claim.IssuedAt = time.Unix(p.IssuedAt, 0).UTC()
	}
	if p.ExpiresAt > 0 {
		claim.ExpiresAt = time.Unix(p.ExpiresAt, 0).UTC()
	}
	return claim, nil
}

func intuneClaimMatchesCSR(claim IntuneChallengeClaim, csrDER []byte) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("%w: parse CSR: %v", ErrIntuneChallengeCSRSubject, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: CSR signature: %v", ErrIntuneChallengeCSRSubject, err)
	}
	wantCN := firstNonEmptyString(claim.DeviceName, claim.Subject)
	if wantCN != "" && wantCN != csr.Subject.CommonName {
		return fmt.Errorf("%w: claim=%q csr=%q", ErrIntuneChallengeCSRSubject, wantCN, csr.Subject.CommonName)
	}
	if len(claim.SANDNS) > 0 && !equalNormalizedStringSets(claim.SANDNS, csr.DNSNames) {
		return fmt.Errorf("%w: dns claim=%v csr=%v", ErrIntuneChallengeCSRSAN, normalizeStringSet(claim.SANDNS), normalizeStringSet(csr.DNSNames))
	}
	if len(claim.SANRFC822) > 0 && !equalNormalizedStringSets(claim.SANRFC822, csr.EmailAddresses) {
		return fmt.Errorf("%w: email claim=%v csr=%v", ErrIntuneChallengeCSRSAN, normalizeStringSet(claim.SANRFC822), normalizeStringSet(csr.EmailAddresses))
	}
	if len(claim.SANUPN) > 0 {
		return fmt.Errorf("%w: UPN SAN matching is not yet supported", ErrIntuneChallengeCSRSAN)
	}
	return nil
}

func normalizeStringSet(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func equalNormalizedStringSets(a, b []string) bool {
	aa := normalizeStringSet(a)
	bb := normalizeStringSet(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
