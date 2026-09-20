// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"errors"
	"math/big"
	"time"
)

// LeafPreparation retains the random serial and clock value used to construct
// one certificate. The caller must durably bind it to the exact CSR, issuer and
// profile before signing. These public values contain no key material.
//
// Reusing this preparation produces the same to-be-signed certificate only when
// all other inputs are unchanged. It does not itself make signing idempotent:
// callers also need an operation-bound signer that journals its exact signature.
type LeafPreparation struct {
	Serial         []byte    `json:"serial"`
	ValidityAnchor time.Time `json:"validity_anchor"`
}

// NewLeafPreparation performs no signature. Preserve its result before calling
// SignLeafFromCSRWithPreparation; generating another preparation is a new leaf.
func NewLeafPreparation() (LeafPreparation, error) {
	serial, err := randomSerial()
	if err != nil {
		return LeafPreparation{}, err
	}
	if serial.Sign() <= 0 {
		return LeafPreparation{}, errors.New("crypto: generated leaf serial is not positive")
	}
	return LeafPreparation{Serial: serial.Bytes(), ValidityAnchor: time.Now().UTC().Truncate(time.Microsecond)}, nil
}

func (p LeafPreparation) validatedSerial() (*big.Int, error) {
	// Match the existing 128-bit serial generator and require its canonical
	// positive encoding. Do not silently normalize corrupted persisted inputs.
	if len(p.Serial) == 0 || len(p.Serial) > 16 || p.Serial[0] == 0 || p.ValidityAnchor.IsZero() ||
		!p.ValidityAnchor.Equal(p.ValidityAnchor.UTC().Truncate(time.Microsecond)) {
		return nil, errors.New("crypto: invalid retained leaf preparation")
	}
	return new(big.Int).SetBytes(p.Serial), nil
}

// SignLeafFromCSRWithPreparation retains the exact validity anchor and serial
// across receiver retries. CSR, issuer, profile and returned-signature validation
// are the same as the ordinary leaf constructor; no policy gate is bypassed.
func SignLeafFromCSRWithPreparation(caCertDER []byte, caSigner DigestSigner, csrDER []byte, ttl time.Duration, prof LeafProfile, prepared LeafPreparation) (IssuedLeaf, error) {
	if _, err := prepared.validatedSerial(); err != nil {
		return IssuedLeaf{}, err
	}
	return signLeafFromCSRWithPreparation(caCertDER, caSigner, csrDER, ttl, prof, &prepared)
}
