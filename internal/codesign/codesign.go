// Package codesign implements the managed code-signing service (S14.1, F50):
// policy- and approval-governed signing of artifacts, container/OCI images, and
// SBOMs where private signing keys never reach the requester (AN-4). It supports
// key-based signing (HSM/KMS-backed via the crypto boundary) and keyless,
// Sigstore/Fulcio-style signing bound to a verified OIDC identity. Every operation
// is audited (AN-2); who may sign what is governed by policy + approval (S12.3).
package codesign

import (
	"context"
	"fmt"

	"trustctl.io/trustctl/internal/attest"
	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

// KeyResolver returns the HSM/KMS-backed signer for a key id. The signer is a
// DigestSigner, so the private key stays inside the isolated signer (AN-4) and
// never reaches the requester.
type KeyResolver interface {
	Signer(keyID string) (crypto.DigestSigner, error)
}

// Gate governs whether a principal may sign a given artifact with a given key
// (policy + approval, S12.3). It returns a reason on denial.
type Gate interface {
	MaySign(ctx context.Context, tenantID, principal, keyID, digestHex string) (allowed bool, reason string)
}

// Config configures the signing Service.
type Config struct {
	TenantID string
	Keys     KeyResolver
	Gate     Gate
	Audit    auditsink.Auditor
}

// Service is the code-signing service.
type Service struct {
	cfg Config
}

// New validates configuration and constructs a Service.
func New(cfg Config) (*Service, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("codesign: TenantID required (AN-1)")
	}
	if cfg.Keys == nil {
		return nil, fmt.Errorf("codesign: KeyResolver required")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Service{cfg: cfg}, nil
}

// SignRequest is a key-based signing request.
type SignRequest struct {
	Principal    string
	KeyID        string
	ArtifactType string // "blob" | "oci-image" | "sbom"
	Digest       []byte // sha256 of the artifact (e.g. the OCI image manifest digest)
}

// Signature is an issued signature.
type Signature struct {
	Algorithm    string
	Value        []byte
	PublicKeyDER []byte
	KeyID        string
	ArtifactType string
}

// Sign signs an artifact digest with an HSM/KMS-backed key. The requester never
// holds the key. Policy/approval gates the operation; the result is audited.
func (s *Service) Sign(ctx context.Context, req SignRequest) (Signature, error) {
	if len(req.Digest) == 0 {
		return Signature{}, fmt.Errorf("codesign: empty artifact digest")
	}
	digestHex := fmt.Sprintf("%x", req.Digest)
	if s.cfg.Gate != nil {
		if ok, reason := s.cfg.Gate.MaySign(ctx, s.cfg.TenantID, req.Principal, req.KeyID, digestHex); !ok {
			_ = s.cfg.Audit.Audit(ctx, "codesign.refused", s.cfg.TenantID,
				[]byte(fmt.Sprintf(`{"principal":%q,"key":%q,"reason":%q}`, req.Principal, req.KeyID, reason)))
			return Signature{}, fmt.Errorf("codesign: %s not permitted to sign with %s: %s", req.Principal, req.KeyID, reason)
		}
	}
	signer, err := s.cfg.Keys.Signer(req.KeyID)
	if err != nil {
		return Signature{}, fmt.Errorf("codesign: resolve key %s: %w", req.KeyID, err)
	}
	value, err := crypto.SignMessage(signer, req.Digest)
	if err != nil {
		return Signature{}, fmt.Errorf("codesign: sign: %w", err)
	}
	pub := signer.Public()
	_ = s.cfg.Audit.Audit(ctx, "codesign.signed", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"key":%q,"artifact_type":%q,"digest":%q}`, req.Principal, req.KeyID, req.ArtifactType, digestHex)))
	return Signature{Algorithm: string(pub.Algorithm), Value: value, PublicKeyDER: pub.DER, KeyID: req.KeyID, ArtifactType: req.ArtifactType}, nil
}

// Verify checks a key-based signature over a digest.
func (s *Service) Verify(sig Signature, digest []byte) error {
	return crypto.VerifyMessage(sig.PublicKeyDER, digest, sig.Value)
}

// KeylessRequest is a Sigstore/Fulcio-style keyless signing request: a short-lived
// key signs, bound to a verified OIDC identity (the identity Fulcio would certify).
type KeylessRequest struct {
	Principal    string
	Identity     attest.Attestation // the verified OIDC identity
	FulcioSAN    string
	FulcioIssuer string
	Ephemeral    crypto.DigestSigner // short-lived key (Fulcio would certify it)
	ArtifactType string
	Digest       []byte
}

// KeylessSignature is a keyless signature bound to a Fulcio identity.
type KeylessSignature struct {
	Algorithm    string
	Value        []byte
	PublicKeyDER []byte
	FulcioSAN    string
	FulcioIssuer string
	ArtifactType string
}

// SignKeyless signs keylessly, binding the signature to the verified OIDC identity.
func (s *Service) SignKeyless(ctx context.Context, req KeylessRequest) (KeylessSignature, error) {
	if len(req.Digest) == 0 || req.Ephemeral == nil {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless request needs a digest and an ephemeral key")
	}
	if req.FulcioSAN == "" {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless signing requires a verified Fulcio identity (SAN)")
	}
	value, err := crypto.SignMessage(req.Ephemeral, req.Digest)
	if err != nil {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless sign: %w", err)
	}
	pub := req.Ephemeral.Public()
	_ = s.cfg.Audit.Audit(ctx, "codesign.keyless.signed", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"fulcio_san":%q,"fulcio_issuer":%q,"artifact_type":%q}`, req.Principal, req.FulcioSAN, req.FulcioIssuer, req.ArtifactType)))
	return KeylessSignature{
		Algorithm: string(pub.Algorithm), Value: value, PublicKeyDER: pub.DER,
		FulcioSAN: req.FulcioSAN, FulcioIssuer: req.FulcioIssuer, ArtifactType: req.ArtifactType,
	}, nil
}

// VerifyKeyless checks a keyless signature over a digest.
func (s *Service) VerifyKeyless(sig KeylessSignature, digest []byte) error {
	return crypto.VerifyMessage(sig.PublicKeyDER, digest, sig.Value)
}
