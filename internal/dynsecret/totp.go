// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// TOTPConfig configures the TOTP provider (A239): each lease is the current
// RFC 6238 code of a configured seed (the base32 secret an authenticator app
// enrolls), valid until the end of its time step. A code can't be withdrawn
// early, so revocation is TTL-only: the lease records the step's end as its
// expiry bound.
type TOTPConfig struct {
	// SeedBase32 is the shared secret as authenticator apps carry it: base32,
	// case-insensitive, spaces and padding ignored.
	SeedBase32 []byte
	// Digits is 6 (the default) to 8; Period is 30 seconds (the default) or
	// 60; Algorithm is SHA1 (the default), SHA256 or SHA512.
	Digits    int
	Period    time.Duration
	Algorithm string
	Now       func() time.Time
}

// TOTPBackend issues one-time codes from a sealed seed.
type TOTPBackend struct {
	seed      *secret.Buffer
	digits    int
	period    int64
	algorithm string
	now       func() time.Time
}

// NewTOTPBackend validates cfg and decodes the seed.
func NewTOTPBackend(cfg TOTPConfig) (*TOTPBackend, error) {
	b := &TOTPBackend{digits: cfg.Digits, algorithm: strings.ToUpper(strings.TrimSpace(cfg.Algorithm)), now: cfg.Now}
	if b.digits == 0 {
		b.digits = 6
	}
	if b.algorithm == "" {
		b.algorithm = "SHA1"
	}
	switch cfg.Period {
	case 0, 30 * time.Second:
		b.period = 30
	case 60 * time.Second:
		b.period = 60
	default:
		return nil, errors.New("dynsecret totp: period must be 30s or 60s")
	}
	if b.now == nil {
		b.now = time.Now
	}
	seed, err := decodeTOTPSeed(cfg.SeedBase32)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(seed)
	if len(seed) < 10 {
		return nil, errors.New("dynsecret totp: the seed must decode to at least 80 bits")
	}
	// The parameters are checked once, here, with the real seed.
	code, err := crypto.HOTP(seed, 0, b.digits, b.algorithm)
	if err != nil {
		return nil, err
	}
	secret.Wipe(code)
	if b.seed, err = secret.NewFrom(seed); err != nil {
		return nil, err
	}
	return b, nil
}

// decodeTOTPSeed reads a base32 seed with spaces, hyphens, lower case and
// missing padding tolerated, as authenticator secrets are written.
func decodeTOTPSeed(raw []byte) ([]byte, error) {
	clean := make([]byte, 0, len(raw))
	for _, c := range bytes.TrimSpace(raw) {
		switch {
		case c == ' ' || c == '-' || c == '=':
		case c >= 'a' && c <= 'z':
			clean = append(clean, c-'a'+'A')
		default:
			clean = append(clean, c)
		}
	}
	defer secret.Wipe(clean)
	seed := make([]byte, base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(clean)))
	n, err := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(seed, clean)
	if err != nil || n == 0 {
		secret.Wipe(seed)
		return nil, errors.New("dynsecret totp: the seed is not base32")
	}
	return seed[:n], nil
}

// Create implements Backend.
func (b *TOTPBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: the code for the current step,
// with the instant it stops being valid.
func (b *TOTPBackend) CreateCredential(_ context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret totp: static credentials are not served")
	}
	now := b.now().Unix()
	if now < 0 {
		return "", nil, errors.New("dynsecret totp: the clock is before 1970")
	}
	step := now / b.period
	var code []byte
	if err := b.seed.Use(func(seed []byte) error {
		var err error
		code, err = crypto.HOTP(seed, uint64(step), b.digits, b.algorithm) // #nosec G115 -- step = now / period with now checked non-negative above (CWE-190)
		return err
	}); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(code)
	validUntil := time.Unix((step+1)*b.period, 0).UTC()
	credential, err := json.Marshal(struct {
		Code          secret.JSONBytes `json:"code"`
		ValidUntil    time.Time        `json:"valid_until"`
		PeriodSeconds int64            `json:"period_seconds"`
	}{Code: code, ValidUntil: validUntil, PeriodSeconds: b.period})
	if err != nil {
		return "", nil, err
	}
	return "totp-step-" + strconv.FormatInt(step, 10), credential, nil
}

// Revoke implements Backend. A code can't be withdrawn: it lapses at the end
// of its step, which the lease already records as its expiry.
func (b *TOTPBackend) Revoke(context.Context, string) error { return nil }

// Close wipes the seed.
func (b *TOTPBackend) Close() { b.seed.Destroy() }
