// This file implements S13.4 (F45): SSH user certificates issued only against a
// valid attestation — the same F30 gate as ephemeral X.509-SVIDs (S11.9) — so
// standing raw-key SSH access is replaced by attested, expiring access.

package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
)

// AttestedConfig configures an attestation-gated SSH user-cert issuer.
type AttestedConfig struct {
	TenantID string
	CA       *CA
	Verifier *attest.Verifier
	Profile  Profile
	TTL      time.Duration
	// Principals derives the certificate principals from the verified identity.
	// If nil, the attestation subject is used as the sole principal.
	Principals func(attest.Attestation) []string
	Audit      auditsink.Auditor
}

// AttestedUserCertIssuer issues short-lived SSH user certificates gated on a valid
// attestation.
type AttestedUserCertIssuer struct {
	cfg AttestedConfig
}

// NewAttestedUserCertIssuer validates configuration and constructs the issuer.
func NewAttestedUserCertIssuer(cfg AttestedConfig) (*AttestedUserCertIssuer, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("ssh: TenantID required (AN-1)")
	}
	if cfg.CA == nil || cfg.Verifier == nil {
		return nil, fmt.Errorf("ssh: CA and Verifier required")
	}
	if !cfg.Profile.AllowUserCerts {
		return nil, fmt.Errorf("ssh: profile must allow user certificates")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 15 * time.Minute
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &AttestedUserCertIssuer{cfg: cfg}, nil
}

// AttestedRequest is a request for an attestation-gated SSH user cert.
type AttestedRequest struct {
	Method           string // attestation method
	Payload          []byte // attestation proof
	SubjectPublicKey []byte // the user's SSH public key
	KeyID            string
	Approver         string
	Principals       []string
	CriticalOptions  map[string]string
}

// Issue verifies the attestation (the gate) and, only on success, signs a
// short-lived SSH user certificate whose principals derive from the verified
// identity, binding the attestation to the issued cert. Without a valid
// attestation it issues nothing.
func (i *AttestedUserCertIssuer) Issue(ctx context.Context, req AttestedRequest) (Issued, attest.Attestation, error) {
	att, err := i.cfg.Verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: attestation required: %w", err)
	}
	var principals []string
	if i.cfg.Principals != nil {
		principals = i.cfg.Principals(att)
	}
	if len(principals) == 0 {
		principals = []string{att.Subject}
	}
	if len(req.Principals) > 0 {
		principals = compactSSHStrings(req.Principals)
		if len(principals) == 0 {
			return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: principal required")
		}
		for _, principal := range principals {
			if !attestationAllowsSSHPrincipal(att, principal) {
				return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: requested principal %q is not bound to attested subject", principal)
			}
		}
	}
	approver := strings.TrimSpace(req.Approver)
	if approver == "" {
		return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: approver required")
	}
	if approver == att.Subject {
		return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: approver must be distinct from attested subject")
	}
	keyID := req.KeyID
	if keyID == "" {
		keyID = att.Subject
	}
	iss, err := i.cfg.CA.IssueUserCert(ctx, i.cfg.Profile, IssueRequest{
		SubjectPublicKey: req.SubjectPublicKey,
		KeyID:            keyID,
		Principals:       principals,
		TTL:              i.cfg.TTL,
		CriticalOptions:  req.CriticalOptions,
	})
	if err != nil {
		return Issued{}, attest.Attestation{}, err
	}
	credID := fmt.Sprintf("ssh-cert:%d", iss.Serial)
	if err := i.cfg.Verifier.Bind(ctx, att, credID); err != nil {
		return Issued{}, attest.Attestation{}, fmt.Errorf("ssh: bind attestation: %w", err)
	}
	payload, _ := json.Marshal(map[string]any{
		"key_id":           keyID,
		"serial":           iss.Serial,
		"method":           att.Method,
		"subject":          att.Subject,
		"approver":         approver,
		"principals":       principals,
		"critical_options": req.CriticalOptions,
	})
	_ = auditsink.Emit(ctx, i.cfg.Audit, nil, "ssh.attested_cert.issued", i.cfg.TenantID, payload)
	return iss, att, nil
}

func compactSSHStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func attestationAllowsSSHPrincipal(att attest.Attestation, principal string) bool {
	if principal == att.Subject {
		return true
	}
	for _, value := range att.Claims {
		if value == principal {
			return true
		}
	}
	return false
}
