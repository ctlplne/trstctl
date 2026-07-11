// SPDX-License-Identifier: MPL-2.0

// Package codesign implements the managed code-signing service (S14.1, F50):
// policy- and approval-governed signing of artifacts, container/OCI images, and
// SBOMs where private signing keys never reach the requester (AN-4). It supports
// persistent signer-held key signing and keyless, Sigstore/Fulcio-style signing
// bound to a verified OIDC identity. HSM/KMS custody is served by the separate
// managed-key surface; it is not silently implied by this resolver. Every
// operation is audited (AN-2); who may sign what is governed by policy + approval
// (S12.3).
package codesign

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

// KeyResolver returns the isolated signer-held key for a key id. The signer is a
// DigestSigner, so the private key stays inside trstctl-signer (AN-4) and never
// reaches the requester.
type KeyResolver interface {
	Signer(tenantID, keyID string) (crypto.DigestSigner, error)
}

// Gate governs whether a principal may sign a given artifact with a given key
// (policy + approval, S12.3). It returns a reason on denial.
type Gate interface {
	MaySign(ctx context.Context, tenantID, principal, keyID, digestHex string) (allowed bool, reason string)
}

// Closed error classes let the served worker decide whether a failure belongs to
// the immutable request/domain or to retryable signing infrastructure. Error text
// is deliberately not the classifier: provider and policy messages may change or
// contain attacker-controlled values, while errors.Is remains stable.
var (
	ErrInvalidRequest  = errors.New("codesign: invalid request")
	ErrPolicyDenied    = errors.New("codesign: policy denied")
	ErrKeyUnavailable  = errors.New("codesign: key unavailable")
	ErrSignerOperation = errors.New("codesign: signer operation failed")
)

type classifiedError struct {
	class error
	cause error
}

func (e *classifiedError) Error() string { return e.cause.Error() }

func (e *classifiedError) Unwrap() []error { return []error{e.class, e.cause} }

func classify(class, cause error) error {
	if cause == nil {
		cause = class
	}
	return &classifiedError{class: class, cause: cause}
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
		return nil, classify(ErrInvalidRequest, fmt.Errorf("codesign: TenantID required (AN-1)"))
	}
	if cfg.Keys == nil {
		return nil, classify(ErrInvalidRequest, fmt.Errorf("codesign: KeyResolver required"))
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Service{cfg: cfg}, nil
}

// SignRequest is a key-based signing request.
type SignRequest struct {
	// OperationID is the durable command identity. Signers that support result
	// journaling bind the exact signature to it, so a worker crash after signing
	// can replay the original bytes instead of producing a second ECDSA value.
	OperationID  string
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

// Sign signs an artifact digest with an isolated signer-held key. The requester
// never holds the key. Policy/approval gates the operation; the result is audited.
func (s *Service) Sign(ctx context.Context, req SignRequest) (Signature, error) {
	if len(req.Digest) != 32 {
		return Signature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: artifact digest must be exactly 32 bytes (SHA-256)"))
	}
	digestHex := fmt.Sprintf("%x", req.Digest)
	if s.cfg.Gate != nil {
		if ok, reason := s.cfg.Gate.MaySign(ctx, s.cfg.TenantID, req.Principal, req.KeyID, digestHex); !ok {
			_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.refused", s.cfg.TenantID,
				[]byte(fmt.Sprintf(`{"principal":%q,"key":%q,"reason":%q}`, req.Principal, req.KeyID, reason)))
			return Signature{}, classify(ErrPolicyDenied, fmt.Errorf("codesign: %s not permitted to sign with %s: %s", req.Principal, req.KeyID, reason))
		}
	}
	signer, err := s.cfg.Keys.Signer(s.cfg.TenantID, req.KeyID)
	if err != nil {
		return Signature{}, classify(ErrKeyUnavailable, fmt.Errorf("codesign: resolve key %s: %w", req.KeyID, err))
	}
	if signer == nil {
		return Signature{}, classify(ErrKeyUnavailable, fmt.Errorf("codesign: no key %s", req.KeyID))
	}
	// Digest is already the caller's SHA-256 artifact digest. Sign it directly.
	// SignMessage would hash it again, producing SHA256(SHA256(artifact)) and a
	// signature Rekor/stock artifact verifiers correctly reject.
	value, err := signDigestForOperation(signer, req.OperationID, req.Digest, codeSigningOptions())
	if err != nil {
		return Signature{}, classify(ErrSignerOperation, fmt.Errorf("codesign: sign: %w", err))
	}
	pub := signer.Public()
	_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.signed", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"principal":%q,"key":%q,"artifact_type":%q,"digest":%q}`, req.Principal, req.KeyID, req.ArtifactType, digestHex)))
	return Signature{Algorithm: string(pub.Algorithm), Value: value, PublicKeyDER: pub.DER, KeyID: req.KeyID, ArtifactType: req.ArtifactType}, nil
}

// Verify checks a key-based signature over a digest.
func (s *Service) Verify(sig Signature, digest []byte) error {
	if len(digest) != 32 {
		return classify(ErrInvalidRequest, fmt.Errorf("codesign: artifact digest must be exactly 32 bytes (SHA-256)"))
	}
	return crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.Algorithm(sig.Algorithm), DER: sig.PublicKeyDER}, digest, sig.Value, codeSigningOptions())
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
	OperationID  string
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
	if iss := att.Claims["fulcio_issuer"]; iss != "" {
		return iss
	}
	if iss := att.Claims["oidc_issuer"]; iss != "" {
		return iss
	}
	if iss := att.Claims["issuer"]; iss != "" {
		return iss
	}
	return att.Method
}

func attestationSAN(att attest.Attestation) string {
	if san := att.Claims["fulcio_san"]; san != "" {
		return san
	}
	return att.Subject
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
	if len(req.Digest) != 32 || req.Ephemeral == nil {
		return KeylessSignature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: keyless request needs a digest and an ephemeral key"))
	}
	// The attestation is the source of the identity; it must be a verified one.
	if req.Identity.Subject == "" || req.Identity.VerifiedAt.IsZero() {
		return KeylessSignature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: keyless signing requires a verified identity attestation (Subject + VerifiedAt)"))
	}
	san := attestationSAN(req.Identity)
	issuer := attestationIssuer(req.Identity)
	if san == "" || issuer == "" {
		return KeylessSignature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: keyless identity has no Fulcio SAN or issuer"))
	}

	// A caller may assert the SAN/issuer it expects, but it must agree with the
	// verified attestation — it cannot override it with an arbitrary value.
	if req.FulcioSAN != "" && req.FulcioSAN != san {
		_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.keyless.refused", s.cfg.TenantID,
			[]byte(fmt.Sprintf(`{"principal":%q,"reason":"san_mismatch","claimed_san":%q,"verified_san":%q}`, req.Principal, req.FulcioSAN, san)))
		return KeylessSignature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: keyless SAN %q does not match the verified attestation subject %q", req.FulcioSAN, san))
	}
	if req.FulcioIssuer != "" && req.FulcioIssuer != issuer {
		return KeylessSignature{}, classify(ErrInvalidRequest, fmt.Errorf("codesign: keyless issuer %q does not match the verified attestation issuer %q", req.FulcioIssuer, issuer))
	}
	if s.cfg.Gate != nil {
		digestHex := fmt.Sprintf("%x", req.Digest)
		keylessIdentity := "keyless:" + san
		if ok, reason := s.cfg.Gate.MaySign(ctx, s.cfg.TenantID, req.Principal, keylessIdentity, digestHex); !ok {
			_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "codesign.keyless.refused", s.cfg.TenantID,
				[]byte(fmt.Sprintf(`{"principal":%q,"reason":%q}`, req.Principal, reason)))
			return KeylessSignature{}, classify(ErrPolicyDenied, fmt.Errorf("codesign: %s not permitted to sign as %s: %s", req.Principal, keylessIdentity, reason))
		}
	}

	value, err := signDigestForOperation(req.Ephemeral, req.OperationID, req.Digest, codeSigningOptions())
	if err != nil {
		return KeylessSignature{}, classify(ErrSignerOperation, fmt.Errorf("codesign: keyless sign: %w", err))
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
	if len(digest) != 32 {
		return classify(ErrInvalidRequest, fmt.Errorf("codesign: artifact digest must be exactly 32 bytes (SHA-256)"))
	}
	return crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.Algorithm(sig.Algorithm), DER: sig.PublicKeyDER}, digest, sig.Value, codeSigningOptions())
}

func codeSigningOptions() crypto.SignOptions {
	return crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}
}

// OperationDigestSigner is implemented by the isolated signing-service client.
// It persists the exact signature result against operationID before returning.
// In-process signers remain usable in focused library tests, while the served
// production path requires this interface and fails closed without it.
type OperationDigestSigner interface {
	SignDigestForOperation(operationID string, digest []byte, opts crypto.SignOptions) ([]byte, error)
}

func signDigestForOperation(signer crypto.DigestSigner, operationID string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if operationID != "" {
		if durable, ok := signer.(OperationDigestSigner); ok {
			return durable.SignDigestForOperation(operationID, digest, opts)
		}
		return nil, fmt.Errorf("codesign: signer does not support durable operation result journaling")
	}
	return signer.SignDigest(digest, opts)
}
