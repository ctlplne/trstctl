// SPDX-License-Identifier: BUSL-1.1

// Package tsa implements an RFC 3161 timestamping authority (S14.2, F51): it
// issues signed timestamp tokens so signatures carry a trusted time and remain
// verifiable after the signing certificate expires (long-term validity). Timestamp
// signing routes through the isolated signer (AN-4) and the crypto boundary (AN-3);
// every issuance is audited (AN-2).
//
// Wire format (INTEROP-005): each token carries a real RFC 3161 TimeStampToken —
// a CMS SignedData over a DER-encoded TSTInfo with eContentType id-ct-TSTInfo,
// produced by crypto.BuildTimeStampToken — in Token.DER. The HTTP handler wraps
// that token in the RFC 3161 TimeStampResp envelope that a stock verifier
// (`openssl ts -verify`, a DSS/ESS validator) parses; it is no longer a bespoke JSON
// manifest. The struct fields below remain for the in-process LTV checks and the
// message-imprint binding, and the DER token is the externally interoperable
// artifact.
package tsa

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// ContentTypeQuery is the HTTP content type of an RFC 3161 TimeStampReq body.
const ContentTypeQuery = "application/timestamp-query"

// ContentTypeReply is the HTTP content type of an RFC 3161 TimeStampResp body,
// served when the TSA is exposed over HTTP.
const ContentTypeReply = "application/timestamp-reply"

// TSTInfo is the timestamp-token info (RFC 3161 TSTInfo). MessageImprint
// (HashedMessage) binds the token to the data being timestamped.
type TSTInfo struct {
	Version       int       `json:"version"`
	Policy        string    `json:"policy"`
	HashAlgorithm string    `json:"hash_algorithm"`
	HashedMessage []byte    `json:"hashed_message"`
	SerialNumber  uint64    `json:"serial_number"`
	GenTime       time.Time `json:"gen_time"`
}

// Token is a signed timestamp token. DER is the RFC 3161 TimeStampToken (CMS
// SignedData over a DER TSTInfo) — the wire-conformant artifact stock verifiers
// validate (INTEROP-005). The remaining fields back the in-process LTV checks.
type Token struct {
	Info       TSTInfo `json:"info"`
	Signature  []byte  `json:"signature"`
	TSACertDER []byte  `json:"tsa_cert"`
	DER        []byte  `json:"der"` // RFC 3161 CMS TimeStampToken
}

// Config configures the timestamping Authority.
type Config struct {
	TenantID   string
	Policy     string // TSA policy OID
	TSACertDER []byte
	TSASigner  crypto.DigestSigner
	Audit      auditsink.Auditor
	Clock      func() time.Time
}

// Authority is the timestamping authority.
type Authority struct {
	cfg    Config
	mu     sync.Mutex
	serial uint64
}

// New validates configuration and constructs an Authority.
func New(cfg Config) (*Authority, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tsa: TenantID required (AN-1)")
	}
	if len(cfg.TSACertDER) == 0 || cfg.TSASigner == nil {
		return nil, fmt.Errorf("tsa: TSA certificate and signer required")
	}
	if cfg.Policy == "" {
		// A valid numeric TSA policy OID (RFC 3161 requires policy be an OID, and
		// EncodeTSTInfo encodes it as one): trstctl PEN placeholder arc under
		// iso.org.dod.internet.private.enterprise. Operators override with their own.
		cfg.Policy = "1.3.6.1.4.1.59551.2.1"
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	seed, err := randomSerialSeed()
	if err != nil {
		return nil, err
	}
	return &Authority{cfg: cfg, serial: seed}, nil
}

// randomSerialSeed picks the starting point for this Authority's token serials.
//
// The counter used to start at zero, in memory, persisted nowhere. Every process
// restart therefore reissued serials 1, 2, 3 — so two genuinely different
// timestamp tokens could carry the same serial, and RFC 3161 §2.4.2 requires the
// serial to be unique for each token a given TSA issues. Uniqueness is what lets
// an archived token be referenced unambiguously years later, which is the entire
// point of timestamping.
//
// Seeding randomly and then incrementing keeps serials monotonic within a run
// while making a cross-restart collision negligible: each restart consumes a tiny
// contiguous range. RFC 3161 asks for uniqueness, not sequence.
//
// The seed is 48 bits, and the ceiling is not arbitrary. The token manifest is
// JSON, and an audit anchor is exported, carried, and re-verified through the
// CLI — a path where a number can pass through a float64. Above 2^53 that is
// lossy, the re-encoded manifest no longer matches the bytes that were signed,
// and long-term validation fails with nothing more helpful than "signature
// invalid". A 48-bit seed leaves room for ~2^52 increments while staying exactly
// representable, which is far more headroom than any single run will use.
//
// A persisted counter would be strictly better and is the right answer if this
// package ever gains a store; it has no datastore today, and inventing one here
// to hold a single integer is not the trade to make.
func randomSerialSeed() (uint64, error) {
	b, err := crypto.RandomBytes(8)
	if err != nil {
		return 0, fmt.Errorf("tsa: seed token serial: %w", err)
	}
	return binary.BigEndian.Uint64(b) >> 16, nil
}

// maxJSONExactInteger is the largest integer a float64 represents exactly. Any
// serial at or above it can be silently rounded by a JSON decoder that widens
// numbers, which would break manifest verification after a round trip.
const maxJSONExactInteger = uint64(1) << 53

func manifest(info TSTInfo) ([]byte, error) { return json.Marshal(info) }

// Timestamp issues a timestamp token over hashedMessage (the SHA-256 of the data).
func (a *Authority) Timestamp(ctx context.Context, hashedMessage []byte) (Token, error) {
	return a.timestamp(ctx, hashedMessage, nil)
}

func (a *Authority) timestamp(ctx context.Context, hashedMessage []byte, nonce *big.Int) (Token, error) {
	if len(hashedMessage) == 0 {
		return Token{}, fmt.Errorf("tsa: empty message imprint")
	}
	a.mu.Lock()
	a.serial++
	serial := a.serial
	a.mu.Unlock()

	info := TSTInfo{
		Version: 1, Policy: a.cfg.Policy, HashAlgorithm: "SHA-256",
		HashedMessage: append([]byte(nil), hashedMessage...), SerialNumber: serial, GenTime: a.cfg.Clock().UTC(),
	}
	mb, err := manifest(info)
	if err != nil {
		return Token{}, err
	}
	sig, err := crypto.SignMessage(a.cfg.TSASigner, mb)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: sign token: %w", err)
	}
	// Build the wire-conformant RFC 3161 TimeStampToken (CMS SignedData over a DER
	// TSTInfo) through the crypto boundary (AN-3, INTEROP-005). This is the
	// application/timestamp-reply artifact a stock verifier validates.
	tstInfoDER, err := crypto.EncodeTSTInfo(crypto.TSTInfoParams{
		PolicyOID: a.cfg.Policy, HashedMessage: hashedMessage, SerialNumber: serial, GenTime: info.GenTime, Nonce: nonce,
	})
	if err != nil {
		return Token{}, fmt.Errorf("tsa: encode TSTInfo: %w", err)
	}
	der, err := crypto.BuildTimeStampToken(tstInfoDER, a.cfg.TSACertDER, a.cfg.TSASigner)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: build timestamp token: %w", err)
	}
	_ = auditsink.Emit(ctx, a.cfg.Audit, nil, "tsa.timestamp.issued", a.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"serial":%d,"gen_time":%q}`, serial, info.GenTime.Format(time.RFC3339))))
	return Token{Info: info, Signature: sig, TSACertDER: a.cfg.TSACertDER, DER: der}, nil
}

// Verify checks a token: the imprint matches hashedMessage, the TSA certificate
// chains to tsaRoot, and the TSA signature over the TSTInfo verifies.
func Verify(tok Token, hashedMessage, tsaRootDER []byte) error {
	if !bytes.Equal(tok.Info.HashedMessage, hashedMessage) {
		return fmt.Errorf("tsa: message imprint mismatch")
	}
	if err := crypto.VerifyLeafSignedByCA(tok.TSACertDER, tsaRootDER); err != nil {
		return fmt.Errorf("tsa: TSA certificate does not chain to the trusted root: %w", err)
	}
	// Chaining to the root is necessary but nowhere near sufficient. Without the
	// checks below, ANY end-entity certificate the same CA issued — an ordinary
	// TLS server certificate for the tenant, say — could sign a timestamp token
	// that this verifier accepts. RFC 3161 §2.3 is explicit: the TSA's
	// certificate must carry the timeStamping extended key usage and no other.
	if err := verifyTSACertificateProfile(tok.TSACertDER); err != nil {
		return err
	}
	pub, err := crypto.PublicKeyDERFromCert(tok.TSACertDER)
	if err != nil {
		return err
	}
	mb, err := manifest(tok.Info)
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(pub, mb, tok.Signature); err != nil {
		return fmt.Errorf("tsa: timestamp signature invalid: %w", err)
	}
	if err := verifyDERBinding(tok); err != nil {
		return err
	}
	return nil
}

// verifyDERBinding ties Token.DER to the fields the checks above actually
// verified.
//
// Everything before this point validates the JSON manifest: Info, Signature and
// TSACertDER. But DER is the RFC 3161 artifact — the bytes a recipient feeds to
// `openssl ts -verify` or archives as the durable proof — and nothing checked
// it. Token is JSON-tagged and travels inside export bundles, so a bundle whose
// manifest is intact can carry a DER lifted from an unrelated token; the
// recipient's Verify returns nil and they hand those bytes on as proven.
//
// The binding requires the token to embed the certificate that was just profile-
// checked and chained, and the imprint the caller demanded. A DER taken from any
// other token carries a different imprint (and usually a different TSA
// certificate), so substitution is caught.
//
// Residual, stated plainly: this is a containment check, not a CMS verification.
// Fully validating DER means parsing the SignedData and checking its signature
// over the encapsulated TSTInfo, which needs a CMS parser behind the crypto
// boundary (AN-3) that does not exist yet. An exact re-encode comparison is not
// available either — the DER TSTInfo may carry a nonce (http.go passes the
// client's), and TSTInfo does not record it, so the manifest cannot reproduce
// those bytes.
//
// An absent DER is not an error. Tokens predating the RFC 3161 wire format
// (INTEROP-005) carry only the manifest, which is independently signed and was
// verified above. Stripping the DER removes the artifact an attacker would want
// to forge rather than smuggling one through.
func verifyDERBinding(tok Token) error {
	if len(tok.DER) == 0 {
		return nil
	}
	if !bytes.Contains(tok.DER, tok.TSACertDER) {
		return fmt.Errorf("tsa: the RFC 3161 token does not embed the verified TSA certificate; " +
			"the manifest and the DER token come from different issuances")
	}
	if !bytes.Contains(tok.DER, tok.Info.HashedMessage) {
		return fmt.Errorf("tsa: the RFC 3161 token does not carry the verified message imprint; " +
			"the manifest attests this data but the DER token attests something else")
	}
	return nil
}

// VerifyLongTermValidity is the central LTV property: a signature whose signing
// certificate has expired still validates if a valid timestamp proves it was
// signed while the certificate was valid. It checks the token and that GenTime
// falls within the signing certificate's validity window — regardless of "now".
func VerifyLongTermValidity(tok Token, hashedMessage, tsaRootDER []byte, signingNotBefore, signingNotAfter time.Time) error {
	if err := Verify(tok, hashedMessage, tsaRootDER); err != nil {
		return err
	}
	if tok.Info.GenTime.Before(signingNotBefore) || tok.Info.GenTime.After(signingNotAfter) {
		return fmt.Errorf("tsa: timestamp %s is outside the signing certificate validity window", tok.Info.GenTime.Format(time.RFC3339))
	}
	return nil
}

// verifyTSACertificateProfile enforces the RFC 3161 §2.3 profile on the
// certificate that signed a timestamp token: it must be an end entity (not a
// CA) and must assert the timeStamping extended key usage and ONLY that usage.
//
// It deliberately does NOT compare genTime against the certificate's validity
// window. Long-term validation is the reason timestamps exist — a token proves a
// signature predates an expiry — so refusing a token whose genTime falls outside
// the TSA certificate's own current window would defeat the property this
// package is for. VerifyLongTermValidity does the window comparison that
// actually matters, against the SIGNING certificate.
func verifyTSACertificateProfile(certDER []byte) error {
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return fmt.Errorf("tsa: inspect TSA certificate: %w", err)
	}
	if info.IsCA {
		return errors.New("tsa: TSA certificate is a CA certificate; a timestamp must be signed by an end entity")
	}
	if len(info.ExtKeyUsages) != 1 || !strings.EqualFold(info.ExtKeyUsages[0], "timeStamping") {
		return fmt.Errorf(
			"tsa: TSA certificate extended key usages are %v, want exactly [timeStamping] (RFC 3161 §2.3); "+
				"any other end-entity certificate from this CA could otherwise forge a timestamp",
			info.ExtKeyUsages)
	}
	return nil
}
