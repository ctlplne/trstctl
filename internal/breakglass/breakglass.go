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

	"trstctl.com/trstctl/internal/crypto"
)

// Quorum enforces m-of-n operator authorization.
type Quorum struct {
	Threshold int      // m
	Operators []string // the n authorized operators
}

// Verify checks that the approvals meet the quorum: every approver is an
// authorized operator and the count of distinct approvers is at least Threshold.
func (q Quorum) Verify(approvals []string) error {
	if q.Threshold <= 0 {
		return fmt.Errorf("breakglass: quorum threshold must be positive")
	}
	allowed := make(map[string]bool, len(q.Operators))
	for _, op := range q.Operators {
		allowed[op] = true
	}
	seen := map[string]bool{}
	count := 0
	for _, a := range approvals {
		if !allowed[a] {
			return fmt.Errorf("breakglass: %q is not an authorized break-glass operator", a)
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		count++
	}
	if count < q.Threshold {
		return fmt.Errorf("breakglass: quorum not met (%d of %d required)", count, q.Threshold)
	}
	return nil
}

// EmergencyRequest is a request to issue a certificate under break-glass.
type EmergencyRequest struct {
	ID        string
	Subject   string
	CSRDer    []byte
	Reason    string
	Approvals []string // operator ids authorizing this issuance (m-of-n)
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
