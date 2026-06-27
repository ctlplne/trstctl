package privacy

import (
	"context"
	"time"
)

const (
	DefaultRetentionInterval = 24 * time.Hour

	defaultOwnerInactiveAfter       = 730 * 24 * time.Hour
	defaultIdentityTerminalAfter    = 397 * 24 * time.Hour
	defaultCertificateTerminalAfter = 397 * 24 * time.Hour
	defaultSSHStaleAfter            = 180 * 24 * time.Hour
	defaultAccessTerminalAfter      = 90 * 24 * time.Hour
	defaultApprovalActorAfter       = 397 * 24 * time.Hour
	defaultProfileActorAfter        = 397 * 24 * time.Hour
	defaultAttestationEvidenceAfter = 397 * 24 * time.Hour
	defaultAgentStaleAfter          = 180 * 24 * time.Hour
)

// RetentionPolicy defines when non-audit personal data may be pseudonymized after
// its operational need ends. Zero fields inherit the product default for that
// class; negative fields are rejected by config validation before the server runs.
type RetentionPolicy struct {
	OwnerInactiveAfter       time.Duration
	IdentityTerminalAfter    time.Duration
	CertificateTerminalAfter time.Duration
	SSHStaleAfter            time.Duration
	AccessTerminalAfter      time.Duration
	ApprovalActorAfter       time.Duration
	ProfileActorAfter        time.Duration
	AttestationEvidenceAfter time.Duration
	AgentStaleAfter          time.Duration
}

// RetentionPolicySource lets licensed governance policy refine the default
// non-audit PII retention windows per tenant. The mechanism remains core: callers
// provide a base policy, and no source means the base/default policy applies.
type RetentionPolicySource interface {
	RetentionPolicy(ctx context.Context, tenantID string, base RetentionPolicy) (RetentionPolicy, bool, error)
}

// DefaultRetentionPolicy is deliberately conservative: it touches only rows that
// are already terminal, stale, orphaned, or no longer referenced by active
// operational state.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		OwnerInactiveAfter:       defaultOwnerInactiveAfter,
		IdentityTerminalAfter:    defaultIdentityTerminalAfter,
		CertificateTerminalAfter: defaultCertificateTerminalAfter,
		SSHStaleAfter:            defaultSSHStaleAfter,
		AccessTerminalAfter:      defaultAccessTerminalAfter,
		ApprovalActorAfter:       defaultApprovalActorAfter,
		ProfileActorAfter:        defaultProfileActorAfter,
		AttestationEvidenceAfter: defaultAttestationEvidenceAfter,
		AgentStaleAfter:          defaultAgentStaleAfter,
	}
}

// WithDefaults fills unset windows from DefaultRetentionPolicy.
func (p RetentionPolicy) WithDefaults() RetentionPolicy {
	d := DefaultRetentionPolicy()
	if p.OwnerInactiveAfter <= 0 {
		p.OwnerInactiveAfter = d.OwnerInactiveAfter
	}
	if p.IdentityTerminalAfter <= 0 {
		p.IdentityTerminalAfter = d.IdentityTerminalAfter
	}
	if p.CertificateTerminalAfter <= 0 {
		p.CertificateTerminalAfter = d.CertificateTerminalAfter
	}
	if p.SSHStaleAfter <= 0 {
		p.SSHStaleAfter = d.SSHStaleAfter
	}
	if p.AccessTerminalAfter <= 0 {
		p.AccessTerminalAfter = d.AccessTerminalAfter
	}
	if p.ApprovalActorAfter <= 0 {
		p.ApprovalActorAfter = d.ApprovalActorAfter
	}
	if p.ProfileActorAfter <= 0 {
		p.ProfileActorAfter = d.ProfileActorAfter
	}
	if p.AttestationEvidenceAfter <= 0 {
		p.AttestationEvidenceAfter = d.AttestationEvidenceAfter
	}
	if p.AgentStaleAfter <= 0 {
		p.AgentStaleAfter = d.AgentStaleAfter
	}
	return p
}

// ResolveRetentionPolicy merges the core base policy with an optional licensed
// governance source. Missing source or missing tenant override is a safe core
// default; source errors fail closed so retention does not run under ambiguous
// governance policy.
func ResolveRetentionPolicy(ctx context.Context, source RetentionPolicySource, tenantID string, base RetentionPolicy) (RetentionPolicy, error) {
	base = base.WithDefaults()
	if source == nil {
		return base, nil
	}
	override, ok, err := source.RetentionPolicy(ctx, tenantID, base)
	if err != nil {
		return RetentionPolicy{}, err
	}
	if !ok {
		return base, nil
	}
	return override.WithDefaults(), nil
}
