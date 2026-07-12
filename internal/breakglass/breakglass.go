// SPDX-License-Identifier: MPL-2.0

// Package breakglass implements the break-glass emergency-issuance ceremony
// (S12.4, F34): a degraded, offline mode of the signing service for when the
// control plane itself is unavailable, so an outage of trstctl does not become
// an outage of everything it protects.
//
// Emergency issuance requires an m-of-n operator quorum, is signed by an
// operator-held escrow key (a locked DigestSigner — AN-4 isolated signer, AN-8
// key material), and produces a self-verifying bundle. On recovery the bundles
// reconcile into the control plane's audit log (AN-2): each becomes an audited
// event, and a tampered bundle is detected and rejected.
package breakglass

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bgquorum "trstctl.com/trstctl/internal/breakglass/quorum"
	"trstctl.com/trstctl/internal/crypto"
)

// Quorum enforces m-of-n operator authorization.
type Quorum = bgquorum.Quorum

// EmergencyRequest is a request to issue a certificate under break-glass.
type EmergencyRequest struct {
	CeremonyID string
	ID         string
	Subject    string
	CSRDer     []byte
	Reason     string
	Approvals  []string // operator ids authorizing this issuance (m-of-n)
}

// IssuePurpose binds one tenant-scoped ceremony to the exact online emergency
// request. Approver identities are intentionally absent: they are derived from
// immutable ca.ceremony.approved events when the operation is consumed.
func IssuePurpose(tenantID string, req EmergencyRequest, ttl time.Duration) string {
	payload, err := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		RequestID  string `json:"request_id"`
		Subject    string `json:"subject"`
		CSRHash    string `json:"csr_sha256"`
		Reason     string `json:"reason"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}{tenantID, req.ID, req.Subject, crypto.SHA256Hex(req.CSRDer), req.Reason, int64(ttl / time.Second)})
	if err != nil {
		panic(fmt.Sprintf("breakglass: canonical issue purpose: %v", err))
	}
	return "breakglass-issue:" + crypto.SHA256Hex(payload)
}

// RotationPurpose binds a ceremony to the exact active signer/certificate and
// requested successor lifetime. A rotation approval cannot be replayed after a
// different rotation has advanced the active CA.
func RotationPurpose(tenantID, signerHandle string, currentCertDER []byte, reason string, ttl time.Duration) string {
	payload, err := json.Marshal(struct {
		TenantID      string `json:"tenant_id"`
		SignerHandle  string `json:"signer_handle"`
		CurrentCAHash string `json:"current_ca_sha256"`
		Reason        string `json:"reason"`
		TTLSeconds    int64  `json:"ttl_seconds"`
	}{tenantID, signerHandle, crypto.SHA256Hex(currentCertDER), reason, int64(ttl / time.Second)})
	if err != nil {
		panic(fmt.Sprintf("breakglass: canonical rotation purpose: %v", err))
	}
	return "breakglass-rotate:" + crypto.SHA256Hex(payload)
}

// CrossSignPurpose binds a ceremony to the exact active break-glass CA and
// target public certificate.
func CrossSignPurpose(tenantID, signerHandle string, targetCertDER []byte) string {
	payload, err := json.Marshal(struct {
		TenantID     string `json:"tenant_id"`
		SignerHandle string `json:"signer_handle"`
		TargetHash   string `json:"target_ca_sha256"`
	}{tenantID, signerHandle, crypto.SHA256Hex(targetCertDER)})
	if err != nil {
		panic(fmt.Sprintf("breakglass: canonical cross-sign purpose: %v", err))
	}
	return "breakglass-cross-sign:" + crypto.SHA256Hex(payload)
}

// Bundle is a signed emergency credential produced offline. Its Signature is over
// a deterministic manifest of its contents, so a reconciler can verify it offline
// against the break-glass public key.
type Bundle struct {
	RequestID string    `json:"request_id"`
	Subject   string    `json:"subject"`
	CertDER   []byte    `json:"cert_der"`
	Reason    string    `json:"reason"`
	Approvals []string  `json:"approvals"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature []byte    `json:"signature"`
}

type manifest struct {
	RequestID  string   `json:"request_id"`
	Subject    string   `json:"subject"`
	CertSHA256 string   `json:"cert_sha256"`
	Reason     string   `json:"reason"`
	Approvals  []string `json:"approvals"`
	IssuedAt   int64    `json:"issued_at"`
}

func manifestBytes(b Bundle) ([]byte, error) {
	ap := append([]string(nil), b.Approvals...)
	sort.Strings(ap)
	return json.Marshal(manifest{
		RequestID: b.RequestID, Subject: b.Subject, CertSHA256: crypto.SHA256Hex(b.CertDER),
		Reason: b.Reason, Approvals: ap, IssuedAt: b.IssuedAt.Unix(),
	})
}

// Config configures the offline signing Service.
type Config struct {
	TenantID  string
	Quorum    Quorum
	CACertDER []byte
	// CASigner is the operator-held escrow key. In production it is a locked
	// DigestSigner inside the isolated signer (AN-4/AN-8), never in-process with a
	// control plane.
	CASigner crypto.DigestSigner
	Clock    func() time.Time
}

// Service is the degraded, offline break-glass signer.
type Service struct {
	cfg Config
}

// New validates configuration and constructs a Service.
func New(cfg Config) (*Service, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("breakglass: TenantID required (AN-1)")
	}
	if len(cfg.CACertDER) == 0 || cfg.CASigner == nil {
		return nil, fmt.Errorf("breakglass: CA certificate and escrow signer required")
	}
	if cfg.Quorum.Threshold <= 0 || len(cfg.Quorum.Operators) < cfg.Quorum.Threshold {
		return nil, fmt.Errorf("breakglass: invalid quorum (threshold %d, operators %d)", cfg.Quorum.Threshold, len(cfg.Quorum.Operators))
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{cfg: cfg}, nil
}

// PublicKeyDER returns the break-glass public key callers use to verify bundles.
func (s *Service) PublicKeyDER() []byte { return s.cfg.CASigner.Public().DER }

// IssueOffline enforces the m-of-n quorum, signs a short-lived emergency
// certificate with the escrow key, and returns a self-verifying signed bundle.
// Sub-quorum or unauthorized requests are refused (fail-closed).
func (s *Service) IssueOffline(req EmergencyRequest, ttl time.Duration) (Bundle, error) {
	if req.Reason == "" {
		return Bundle{}, fmt.Errorf("breakglass: a reason is required for emergency issuance")
	}
	if err := s.cfg.Quorum.Verify(req.Approvals); err != nil {
		return Bundle{}, err
	}
	certDER, err := crypto.SignLeafFromCSR(s.cfg.CACertDER, s.cfg.CASigner, req.CSRDer, ttl)
	if err != nil {
		return Bundle{}, fmt.Errorf("breakglass: sign emergency cert: %w", err)
	}
	b := Bundle{
		RequestID: req.ID, Subject: req.Subject, CertDER: certDER, Reason: req.Reason,
		Approvals: req.Approvals, IssuedAt: s.cfg.Clock().UTC(),
	}
	mb, err := manifestBytes(b)
	if err != nil {
		return Bundle{}, err
	}
	sig, err := crypto.SignMessage(s.cfg.CASigner, mb)
	if err != nil {
		return Bundle{}, fmt.Errorf("breakglass: sign bundle manifest: %w", err)
	}
	b.Signature = sig
	return b, nil
}

// Verify checks a bundle offline: the manifest signature must verify against the
// break-glass public key, and the embedded certificate must chain to the CA.
func Verify(b Bundle, caCertDER, breakglassPubDER []byte) error {
	mb, err := manifestBytes(b)
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(breakglassPubDER, mb, b.Signature); err != nil {
		return fmt.Errorf("breakglass: bundle manifest signature invalid: %w", err)
	}
	if err := crypto.VerifyLeafSignedByCA(b.CertDER, caCertDER); err != nil {
		return fmt.Errorf("breakglass: bundle certificate does not chain to the CA: %w", err)
	}
	return nil
}
