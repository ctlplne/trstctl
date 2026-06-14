// Package tsa implements an RFC 3161-style timestamping authority (S14.2, F51):
// it issues signed timestamp tokens so signatures carry a trusted time and remain
// verifiable after the signing certificate expires (long-term validity). Timestamp
// signing routes through the isolated signer (AN-4); every issuance is audited
// (AN-2). (The RFC-3161 CMS wire encoding is a CI-backstop interop detail, like
// the SCEP/CMP differentials; the TSTInfo binding and LTV property are exercised
// here in full.)
package tsa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

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

// Token is a signed timestamp token.
type Token struct {
	Info       TSTInfo `json:"info"`
	Signature  []byte  `json:"signature"`
	TSACertDER []byte  `json:"tsa_cert"`
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
		cfg.Policy = "1.3.6.1.4.1.trustctl.tsa.1"
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Authority{cfg: cfg}, nil
}

func manifest(info TSTInfo) ([]byte, error) { return json.Marshal(info) }

// Timestamp issues a timestamp token over hashedMessage (the SHA-256 of the data).
func (a *Authority) Timestamp(ctx context.Context, hashedMessage []byte) (Token, error) {
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
	_ = a.cfg.Audit.Audit(ctx, "tsa.timestamp.issued", a.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"serial":%d,"gen_time":%q}`, serial, info.GenTime.Format(time.RFC3339))))
	return Token{Info: info, Signature: sig, TSACertDER: a.cfg.TSACertDER}, nil
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
