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

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
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
			_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.refused", s.cfg.TenantID,
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
	_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.signed", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"key":%q,"artifact_type":%q,"digest":%q}`, req.Principal, req.KeyID, req.ArtifactType, digestHex)))
	return Signature{Algorithm: string(pub.Algorithm), Value: value, PublicKeyDER: pub.DER, KeyID: req.KeyID, ArtifactType: req.ArtifactType}, nil
}

// Verify checks a key-based signature over a digest.
func (s *Service) Verify(sig Signature, digest []byte) error {
	return crypto.VerifyMessage(sig.PublicKeyDER, digest, sig.Value)
}

// KeylessRequest is a Sigstore/Fulcio-style keyless signing request: a short-lived
// key signs, bound to a verified OIDC identity (the identity Fulcio would certify).
//
// Identity is the VERIFIED attestation (produced by attest.Verifier.Verify), and it
// is authoritative: SignKeyless derives the signed identity's SAN and issuer from it
// and refuses to honor a caller-supplied FulcioSAN/FulcioIssuer that contradicts it
// (PKIGOV-011). FulcioSAN/FulcioIssuer are therefore optional assertions checked
// against the attestation, not the source of truth.
type KeylessRequest struct {
	Principal    string
	Identity     attest.Attestation  // the verified OIDC identity (authoritative)
	FulcioSAN    string              // optional; must equal the attestation subject if set
	FulcioIssuer string              // optional; must equal the attestation's issuer if set
	Ephemeral    crypto.DigestSigner // short-lived key (Fulcio would certify it)
	ArtifactType string
	Digest       []byte
}

// attestationIssuer derives the OIDC issuer the keyless identity is bound to from a
// verified attestation: an explicit "oidc_issuer"/"issuer" verified claim wins,
// otherwise the attestation method (e.g. "github_oidc") names the proof source.
func attestationIssuer(att attest.Attestation) string {
	if iss := att.Claims["oidc_issuer"]; iss != "" {
		return iss
	}
	if iss := att.Claims["issuer"]; iss != "" {
		return iss
	}
	return att.Method
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

// SignKeyless signs keylessly, binding the signature to the VERIFIED OIDC identity.
//
// The signed identity (SAN + issuer) is DERIVED from the verified attestation
// (req.Identity), not taken from caller-supplied strings (PKIGOV-011): a request
// must carry a populated, verified attestation (a non-empty Subject and a non-zero
// VerifiedAt — what attest.Verifier.Verify stamps). The Fulcio SAN is the
// attestation's verified Subject and the issuer is derived from it; a caller that
// also passes FulcioSAN/FulcioIssuer must pass values that MATCH the attestation, or
// the request is rejected — so a caller can no longer attach an arbitrary SAN.
func (s *Service) SignKeyless(ctx context.Context, req KeylessRequest) (KeylessSignature, error) {
	if len(req.Digest) == 0 || req.Ephemeral == nil {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless request needs a digest and an ephemeral key")
	}
	// The attestation is the source of the identity; it must be a verified one.
	if req.Identity.Subject == "" || req.Identity.VerifiedAt.IsZero() {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless signing requires a verified identity attestation (Subject + VerifiedAt)")
	}
	san := req.Identity.Subject
	issuer := attestationIssuer(req.Identity)

	// A caller may assert the SAN/issuer it expects, but it must agree with the
	// verified attestation — it cannot override it with an arbitrary value.
	if req.FulcioSAN != "" && req.FulcioSAN != san {
		_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.keyless.refused", s.cfg.TenantID,
			[]byte(fmt.Sprintf(`{"principal":%q,"reason":"san_mismatch","claimed_san":%q,"verified_san":%q}`, req.Principal, req.FulcioSAN, san)))
		return KeylessSignature{}, fmt.Errorf("codesign: keyless SAN %q does not match the verified attestation subject %q", req.FulcioSAN, san)
	}
	if req.FulcioIssuer != "" && req.FulcioIssuer != issuer {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless issuer %q does not match the verified attestation issuer %q", req.FulcioIssuer, issuer)
	}

	value, err := crypto.SignMessage(req.Ephemeral, req.Digest)
	if err != nil {
		return KeylessSignature{}, fmt.Errorf("codesign: keyless sign: %w", err)
	}
	pub := req.Ephemeral.Public()
	_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.keyless.signed", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"fulcio_san":%q,"fulcio_issuer":%q,"artifact_type":%q}`, req.Principal, san, issuer, req.ArtifactType)))
	return KeylessSignature{
		Algorithm: string(pub.Algorithm), Value: value, PublicKeyDER: pub.DER,
		FulcioSAN: san, FulcioIssuer: issuer, ArtifactType: req.ArtifactType,
	}, nil
}

// VerifyKeyless checks a keyless signature over a digest.
func (s *Service) VerifyKeyless(sig KeylessSignature, digest []byte) error {
	return crypto.VerifyMessage(sig.PublicKeyDER, digest, sig.Value)
}
