// SPDX-License-Identifier: BUSL-1.1

package digest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const defaultArtifactKeyID = "xrec-state-digest"
const defaultWitnessArtifactKeyID = "xrec-divergence-witness"
const defaultPlanRefusalArtifactKeyID = "xrec-plan-refusal"

const (
	ArtifactKindDivergenceWitness = "divergence-witness"
	ArtifactKindWitnessDispute    = "witness-dispute"
	ArtifactKindPlanRefusal       = "plan-refusal"
)

var ErrArtifactRefused = errors.New("digest: artifact signing refused")

// ArtifactSignerConfig configures the signer-side digest artifact signer.
type ArtifactSignerConfig struct {
	SignerID  string
	KeyID     string
	Algorithm crypto.Algorithm
}

// ArtifactSigner is linked into cmd/trstctl-signer through signing.WithArtifactSigner.
// Its private key is generated inside the signer process and never crosses the
// gRPC boundary.
type ArtifactSigner struct {
	mu           sync.Mutex
	keyID        string
	key          *crypto.LockedSigner
	witnessKeyID string
	witnessKey   *crypto.LockedSigner
	refusalKeyID string
	refusalKey   *crypto.LockedSigner
}

// NewArtifactSigner creates the signer-side state-digest signing key.
func NewArtifactSigner(cfg ArtifactSignerConfig) (*ArtifactSigner, error) {
	alg := cfg.Algorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("digest artifact keygen: %w", err)
	}
	witnessKey, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		key.Destroy()
		return nil, fmt.Errorf("witness artifact keygen: %w", err)
	}
	refusalKey, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		key.Destroy()
		witnessKey.Destroy()
		return nil, fmt.Errorf("plan refusal artifact keygen: %w", err)
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = defaultArtifactKeyID
	}
	return &ArtifactSigner{
		keyID:        keyID,
		key:          key,
		witnessKeyID: defaultWitnessArtifactKeyID,
		witnessKey:   witnessKey,
		refusalKeyID: defaultPlanRefusalArtifactKeyID,
		refusalKey:   refusalKey,
	}, nil
}

// SignArtifact signs XREC evidence artifacts. The payload is canonical evidence
// bytes from the control plane; this method hashes and signs them inside the
// signer process.
func (s *ArtifactSigner) SignArtifact(ctx context.Context, req signing.ArtifactSignRequest) (signing.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return signing.ArtifactSignature{}, err
	}
	if s == nil || s.key == nil {
		return signing.ArtifactSignature{}, ErrArtifactRefused
	}
	if req.Kind != ArtifactKindStateRoot && req.Kind != ArtifactKindDivergenceWitness && req.Kind != ArtifactKindWitnessDispute && req.Kind != ArtifactKindPlanRefusal {
		return signing.ArtifactSignature{}, fmt.Errorf("%w: unsupported kind %q", ErrArtifactRefused, req.Kind)
	}
	key, keyID, err := s.keyFor(req.Kind, req.KeyID)
	if err != nil {
		return signing.ArtifactSignature{}, err
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.AuthorityID) == "" || len(req.Payload) == 0 {
		return signing.ArtifactSignature{}, fmt.Errorf("%w: missing artifact metadata", ErrArtifactRefused)
	}
	if containsSecretEvidence(req.Payload) {
		return signing.ArtifactSignature{}, ErrSecretEvidence
	}
	digest, err := crypto.Digest(crypto.SHA256, req.Payload)
	if err != nil {
		return signing.ArtifactSignature{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == nil {
		return signing.ArtifactSignature{}, ErrArtifactRefused
	}
	sig, err := key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return signing.ArtifactSignature{}, err
	}
	pub := key.Public()
	return signing.ArtifactSignature{
		KeyID:        keyID,
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
	}, nil
}

func (s *ArtifactSigner) keyFor(kind, requested string) (*crypto.LockedSigner, string, error) {
	keyID := strings.TrimSpace(requested)
	switch kind {
	case ArtifactKindStateRoot:
		if keyID == "" {
			keyID = s.keyID
		}
		if keyID != s.keyID {
			return nil, "", fmt.Errorf("%w: unknown key id", ErrArtifactRefused)
		}
		return s.key, keyID, nil
	case ArtifactKindDivergenceWitness, ArtifactKindWitnessDispute:
		if keyID == "" {
			keyID = s.witnessKeyID
		}
		if keyID != s.witnessKeyID {
			return nil, "", fmt.Errorf("%w: unknown key id", ErrArtifactRefused)
		}
		return s.witnessKey, keyID, nil
	case ArtifactKindPlanRefusal:
		if keyID == "" {
			keyID = s.refusalKeyID
		}
		if keyID != s.refusalKeyID {
			return nil, "", fmt.Errorf("%w: unknown key id", ErrArtifactRefused)
		}
		return s.refusalKey, keyID, nil
	default:
		return nil, "", fmt.Errorf("%w: unsupported kind %q", ErrArtifactRefused, kind)
	}
}

// Public returns the signer public key for provisioning verifier trust.
func (s *ArtifactSigner) Public() crypto.PublicKey {
	if s == nil || s.key == nil {
		return crypto.PublicKey{}
	}
	pub := s.key.Public()
	return crypto.PublicKey{Algorithm: pub.Algorithm, DER: append([]byte(nil), pub.DER...)}
}

// KeyID returns the stable artifact-signing key identifier.
func (s *ArtifactSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *ArtifactSigner) WitnessPublic() crypto.PublicKey {
	if s == nil || s.witnessKey == nil {
		return crypto.PublicKey{}
	}
	pub := s.witnessKey.Public()
	return crypto.PublicKey{Algorithm: pub.Algorithm, DER: append([]byte(nil), pub.DER...)}
}

func (s *ArtifactSigner) WitnessKeyID() string {
	if s == nil {
		return ""
	}
	return s.witnessKeyID
}

func (s *ArtifactSigner) RefusalPublic() crypto.PublicKey {
	if s == nil || s.refusalKey == nil {
		return crypto.PublicKey{}
	}
	pub := s.refusalKey.Public()
	return crypto.PublicKey{Algorithm: pub.Algorithm, DER: append([]byte(nil), pub.DER...)}
}

func (s *ArtifactSigner) RefusalKeyID() string {
	if s == nil {
		return ""
	}
	return s.refusalKeyID
}

// Destroy zeroizes the digest artifact signing key.
func (s *ArtifactSigner) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
	if s.witnessKey != nil {
		s.witnessKey.Destroy()
		s.witnessKey = nil
	}
	if s.refusalKey != nil {
		s.refusalKey.Destroy()
		s.refusalKey = nil
	}
}
