// SPDX-License-Identifier: LicenseRef-trstctl-EE

package compatlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// The signer-side readiness-report signer (epic M1).
//
// It is linked into cmd/trstctl-signer through signing.WithArtifactSigner and
// signs ONLY the pqc-readiness-report kind. Its private key is generated inside
// the signer process and never crosses the gRPC boundary, exactly like the XREC
// artifact signer — a readiness report is a signed recommendation about an
// irreversible migration, so the key that vouches for it lives where every other
// authority-bearing key does.

const defaultReadinessKeyID = "pqc-readiness-report"

// ErrReportRefused is returned when the signer will not sign a request.
var ErrReportRefused = errors.New("compatlab: readiness report signing refused")

// ArtifactSigner is the signer-side key for readiness reports.
type ArtifactSigner struct {
	mu    sync.Mutex
	keyID string
	key   *crypto.LockedSigner
}

// NewArtifactSigner generates the readiness-report signing key inside the signer.
func NewArtifactSigner(keyID string) (*ArtifactSigner, error) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("compatlab readiness keygen: %w", err)
	}
	id := strings.TrimSpace(keyID)
	if id == "" {
		id = defaultReadinessKeyID
	}
	return &ArtifactSigner{keyID: id, key: key}, nil
}

// SignArtifact signs a readiness report. It REFUSES any other kind, so this key
// cannot be borrowed to sign a witness, a plan, or a state digest — the chain
// in cmd/trstctl-signer tries each signer, and one that signed everything would
// defeat the point of separating the keys.
func (s *ArtifactSigner) SignArtifact(ctx context.Context, req signing.ArtifactSignRequest) (signing.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return signing.ArtifactSignature{}, err
	}
	if s == nil || s.key == nil {
		return signing.ArtifactSignature{}, ErrReportRefused
	}
	if req.Kind != ArtifactKindReadinessReport {
		return signing.ArtifactSignature{}, fmt.Errorf("%w: unsupported kind %q", ErrReportRefused, req.Kind)
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		keyID = s.keyID
	}
	if keyID != s.keyID {
		return signing.ArtifactSignature{}, fmt.Errorf("%w: unknown key id", ErrReportRefused)
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AuthorityID) == "" || len(req.Payload) == 0 {
		return signing.ArtifactSignature{}, fmt.Errorf("%w: missing artifact metadata", ErrReportRefused)
	}
	digest, err := crypto.Digest(crypto.SHA256, req.Payload)
	if err != nil {
		return signing.ArtifactSignature{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return signing.ArtifactSignature{}, ErrReportRefused
	}
	sig, err := s.key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return signing.ArtifactSignature{}, err
	}
	pub := s.key.Public()
	return signing.ArtifactSignature{
		KeyID:        keyID,
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
	}, nil
}

// Public returns the report-signing public key so a verifier's trust can be
// provisioned with it.
func (s *ArtifactSigner) Public() crypto.PublicKey {
	if s == nil || s.key == nil {
		return crypto.PublicKey{}
	}
	pub := s.key.Public()
	return crypto.PublicKey{Algorithm: pub.Algorithm, DER: append([]byte(nil), pub.DER...)}
}

// KeyID returns the stable readiness-report key identifier.
func (s *ArtifactSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// Destroy zeroizes the held key.
func (s *ArtifactSigner) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
}
