// SPDX-License-Identifier: BUSL-1.1

package tlsvalidity

import (
	"sort"
	"time"
)

// Scope says whether section 6.3.2 binds a certificate.
type Scope string

const (
	// ScopePublicTLS is a TLS server certificate asserting one of the CA/Browser
	// Forum's reserved certificate policy identifiers, which every publicly
	// trusted TLS subscriber certificate carries.
	ScopePublicTLS Scope = "public_tls"
	// ScopePrivateTLS can authenticate a TLS server, but nothing marks it
	// publicly trusted, so the maximum does not bind it. It is evaluated anyway,
	// for planning.
	ScopePrivateTLS Scope = "private_tls"
	// ScopeNotTLSServer has extended key usages that exclude TLS server
	// authentication.
	ScopeNotTLSServer Scope = "not_tls_server"
	// ScopeCACertificate is a CA certificate; the subscriber maximum does not
	// bind it.
	ScopeCACertificate Scope = "ca_certificate"
	// ScopeUnknown has no certificate bytes the report could read.
	ScopeUnknown Scope = "unknown"
)

// ReservedPolicyIdentifiers are the CA/Browser Forum's reserved certificate
// policy identifiers, by dotted OID.
var ReservedPolicyIdentifiers = map[string]string{
	"2.23.140.1.2.1": "domain-validated",
	"2.23.140.1.2.2": "organization-validated",
	"2.23.140.1.2.3": "individual-validated",
	"2.23.140.1.1":   "extended-validation",
}

// ClassifyCertificate places a parsed certificate in a Scope from its extended
// key usages and certificate policy OIDs, named as internal/crypto/certinfo
// names them.
func ClassifyCertificate(isCA bool, extKeyUsages, policyOIDs []string) Scope {
	if isCA {
		return ScopeCACertificate
	}
	if !ServerAuthCapable(extKeyUsages) {
		return ScopeNotTLSServer
	}
	for _, oid := range policyOIDs {
		if _, ok := ReservedPolicyIdentifiers[oid]; ok {
			return ScopePublicTLS
		}
	}
	return ScopePrivateTLS
}

// ServerAuthCapable reports whether extended key usages permit TLS server
// authentication. A certificate with none restricts nothing.
func ServerAuthCapable(extKeyUsages []string) bool {
	if len(extKeyUsages) == 0 {
		return true
	}
	for _, usage := range extKeyUsages {
		if usage == "serverAuth" || usage == "any" {
			return true
		}
	}
	return false
}

// Automation is what renews a certificate.
type Automation string

const (
	// AutomationScheduled is the served certificate of a deployed lifecycle
	// identity, which trstctl's renewal scheduler renews and redeploys.
	AutomationScheduled Automation = "scheduled"
	// AutomationClient was issued by trstctl to a client or agent that renews
	// it itself: an ACME, EST, SCEP or CMP client, an agent's own certificate,
	// or an in-cluster Kubernetes certificate.
	AutomationClient Automation = "client"
	// AutomationNone has nothing that renews it automatically.
	AutomationNone Automation = "none"
)

// Deployment is how a scheduled renewal reaches the endpoint that serves it.
type Deployment string

const (
	// DeploymentVerified: a connector delivered it and read the served
	// certificate back.
	DeploymentVerified Deployment = "verified"
	// DeploymentDelivered: a connector delivered it, and nothing read the
	// served certificate back.
	DeploymentDelivered Deployment = "delivered"
	// DeploymentFailed: the latest delivery or verification failed, which
	// holds unattended renewal.
	DeploymentFailed Deployment = "failed"
	// DeploymentNone: no connector delivers it, so a renewal is not installed.
	DeploymentNone Deployment = "none"
	// DeploymentNotApplicable: the client renews it, or nothing does.
	DeploymentNotApplicable Deployment = "not_applicable"
)

// Verdict is whether a certificate keeps renewing under a step.
type Verdict string

const (
	VerdictRenews Verdict = "renews"
	VerdictAtRisk Verdict = "at_risk"
	VerdictManual Verdict = "manual"
)

// Reason codes explain a certificate verdict or a profile flag.
const (
	ReasonSchedulerDisabled             = "scheduler_disabled"
	ReasonNoAutomatedRenewal            = "no_automated_renewal"
	ReasonClientRenewalUnobserved       = "client_renewal_unobserved"
	ReasonRenewalFailed                 = "renewal_failed"
	ReasonRenewalPaused                 = "renewal_paused"
	ReasonTargetConflict                = "target_conflict"
	ReasonDeliveryFailed                = "delivery_failed"
	ReasonDeploymentUnverified          = "deployment_unverified"
	ReasonNoAutomatedDeployment         = "no_automated_deployment"
	ReasonApprovalRequired              = "approval_required"
	ReasonProfileUnavailable            = "profile_unavailable"
	ReasonRenewalLifetimeExceedsMaximum = "renewal_lifetime_exceeds_maximum"
	ReasonNoValidityCeiling             = "no_validity_ceiling"
	ReasonRequestedValidityExceeds      = "requested_validity_exceeds_maximum"
)

// Scheduler is the renewal scheduler's configuration.
type Scheduler struct {
	Enabled     bool
	RenewBefore time.Duration
}

// RenewalLead is how long before expiry the scheduler renews a certificate of
// the given lifetime: at the earlier of the configured lead and the start of the
// ARI window, when one third of the lifetime remains. A configured lead that
// covers the whole lifetime would make every successor due at issuance, so the
// scheduler uses the ARI window alone then.
func RenewalLead(renewBefore, lifetime time.Duration) time.Duration {
	ari := lifetime / 3
	if renewBefore <= 0 || renewBefore >= lifetime || renewBefore < ari {
		return ari
	}
	return renewBefore
}

// CertificateFacts is what the report knows about one certificate.
type CertificateFacts struct {
	ID, Subject, Issuer string
	NotBefore, NotAfter time.Time
	Scope               Scope
	Automation          Automation
	// The rest describes scheduled certificates only.
	IdentityID, IdentityName string
	Deployment               Deployment
	// Holds are reason codes that stop or stall the scheduler for the identity
	// now: a failed last renewal, an operator's pause, a destination conflict.
	Holds            []string
	ApprovalRequired bool
	// RenewalLifetime is the validity a scheduled renewal requests.
	RenewalLifetime time.Duration
}

// ProfileFacts is what the report knows about one certificate profile.
type ProfileFacts struct {
	Name    string
	Version int
	// PublicTLS is the profile's own statement that it issues publicly trusted
	// TLS server certificates.
	PublicTLS  bool
	ServerAuth bool
	// MaxValidity is the profile's validity ceiling; zero is none.
	MaxValidity time.Duration
}

// Report is the dated lifetime-reduction readiness of one tenant.
type Report struct {
	Requirements Source                 `json:"requirements"`
	GeneratedAt  time.Time              `json:"generated_at"`
	Scheduler    SchedulerSummary       `json:"scheduler"`
	Steps        []StepSummary          `json:"steps"`
	Profiles     []ProfileReadiness     `json:"profiles"`
	Certificates []CertificateReadiness `json:"certificates"`
	// Truncated is set when the tenant holds more active certificates than
	// Limit; the report then covers the Limit that expire first.
	Truncated bool `json:"truncated"`
	Limit     int  `json:"limit"`
}

// SchedulerSummary is the renewal configuration the verdicts assume.
type SchedulerSummary struct {
	Enabled            bool   `json:"enabled"`
	RenewBefore        string `json:"renew_before"`
	RenewBeforeSeconds int64  `json:"renew_before_seconds"`
}

// StepSummary counts one dated step's verdicts.
type StepSummary struct {
	Effective       string `json:"effective"`
	ShouldDays      int    `json:"should_days"`
	MaxDays         int    `json:"max_days"`
	InEffect        bool   `json:"in_effect"`
	Renews          int    `json:"renews"`
	AtRisk          int    `json:"at_risk"`
	Manual          int    `json:"manual"`
	PublicTLS       int    `json:"public_tls"`
	PublicTLSAtRisk int    `json:"public_tls_at_risk"`
	PublicTLSManual int    `json:"public_tls_manual"`
	// ManualRenewalsPerYear is how many hand renewals a year the public TLS
	// certificates nothing renews need at the step's maximum lifetime.
	ManualRenewalsPerYear int `json:"manual_renewals_per_year"`
	FlaggedProfiles       int `json:"flagged_profiles"`
}

// CertificateReadiness is one certificate's verdict under each step.
type CertificateReadiness struct {
	CertificateID string    `json:"certificate_id"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ValidityDays  int       `json:"validity_days"`
	Scope         Scope     `json:"scope"`
	// MaxDaysAtIssuance is the maximum for the date it was issued;
	// ExceedsMaximumAtIssuance is set only for a public TLS certificate whose
	// own validity is longer.
	MaxDaysAtIssuance        int        `json:"max_days_at_issuance"`
	ExceedsMaximumAtIssuance bool       `json:"exceeds_maximum_at_issuance"`
	Automation               Automation `json:"automation"`
	IdentityID               string     `json:"identity_id,omitempty"`
	IdentityName             string     `json:"identity_name,omitempty"`
	Deployment               Deployment `json:"deployment"`
	// RenewalLifetimeDays and RenewalLeadDays are whole days, for scheduled
	// certificates: what a renewal requests and how long before expiry the
	// scheduler starts it.
	RenewalLifetimeDays int               `json:"renewal_lifetime_days,omitempty"`
	RenewalLeadDays     int               `json:"renewal_lead_days,omitempty"`
	Steps               []CertificateStep `json:"steps"`
}

// CertificateStep is a certificate's verdict under one step.
type CertificateStep struct {
	Effective string   `json:"effective"`
	MaxDays   int      `json:"max_days"`
	Verdict   Verdict  `json:"verdict"`
	Reasons   []string `json:"reasons"`
}

// ProfileReadiness flags a public TLS profile under each step.
type ProfileReadiness struct {
	Name       string `json:"name"`
	Version    int    `json:"version"`
	PublicTLS  bool   `json:"public_tls"`
	ServerAuth bool   `json:"server_auth"`
	// MaxValidity is the profile's ceiling as written ("" when it has none);
	// RequestedDays is that ceiling in BR days (0 when it has none).
	MaxValidity   string        `json:"max_validity"`
	RequestedDays int           `json:"requested_days"`
	Steps         []ProfileStep `json:"steps"`
}

// ProfileStep is whether a profile requests more than one step allows.
type ProfileStep struct {
	Effective string `json:"effective"`
	MaxDays   int    `json:"max_days"`
	Flagged   bool   `json:"flagged"`
	Reason    string `json:"reason,omitempty"`
}

const dayLayout = "2006-01-02"

// NewReport evaluates every certificate and profile under each dated
// reduction.
func NewReport(now time.Time, scheduler Scheduler, certificates []CertificateFacts, profiles []ProfileFacts, truncated bool, limit int) Report {
	now = now.UTC()
	steps := Reductions()
	report := Report{
		Requirements: BaselineRequirements,
		GeneratedAt:  now,
		Scheduler: SchedulerSummary{
			Enabled: scheduler.Enabled, RenewBefore: scheduler.RenewBefore.String(),
			RenewBeforeSeconds: int64(scheduler.RenewBefore / time.Second),
		},
		Steps:        make([]StepSummary, len(steps)),
		Profiles:     make([]ProfileReadiness, 0, len(profiles)),
		Certificates: make([]CertificateReadiness, 0, len(certificates)),
		Truncated:    truncated,
		Limit:        limit,
	}
	for i, step := range steps {
		report.Steps[i] = StepSummary{
			Effective: step.From.Format(dayLayout), ShouldDays: step.ShouldDays,
			MaxDays: step.MaxDays, InEffect: step.InEffect(now),
		}
	}
	for _, facts := range certificates {
		row := certificateReadiness(facts, scheduler)
		for i, step := range steps {
			verdict := evaluateCertificate(facts, scheduler, step)
			row.Steps = append(row.Steps, verdict)
			summary := &report.Steps[i]
			public := facts.Scope == ScopePublicTLS
			if public {
				summary.PublicTLS++
			}
			switch verdict.Verdict {
			case VerdictRenews:
				summary.Renews++
			case VerdictAtRisk:
				summary.AtRisk++
				if public {
					summary.PublicTLSAtRisk++
				}
			case VerdictManual:
				summary.Manual++
				if public {
					summary.PublicTLSManual++
					summary.ManualRenewalsPerYear += renewalsPerYear(step.MaxDays)
				}
			}
		}
		report.Certificates = append(report.Certificates, row)
	}
	sorted := append([]ProfileFacts(nil), profiles...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, facts := range sorted {
		row := ProfileReadiness{
			Name: facts.Name, Version: facts.Version, PublicTLS: facts.PublicTLS,
			ServerAuth: facts.ServerAuth, Steps: make([]ProfileStep, 0, len(steps)),
		}
		if facts.MaxValidity > 0 {
			row.MaxValidity = facts.MaxValidity.String()
			row.RequestedDays = RequestedDays(facts.MaxValidity)
		}
		for i, step := range steps {
			flag := evaluateProfile(facts, step)
			if flag.Flagged {
				report.Steps[i].FlaggedProfiles++
			}
			row.Steps = append(row.Steps, flag)
		}
		report.Profiles = append(report.Profiles, row)
	}
	return report
}

func certificateReadiness(facts CertificateFacts, scheduler Scheduler) CertificateReadiness {
	row := CertificateReadiness{
		CertificateID: facts.ID, Subject: facts.Subject, Issuer: facts.Issuer,
		NotBefore: facts.NotBefore.UTC(), NotAfter: facts.NotAfter.UTC(), Scope: facts.Scope,
		Automation: facts.Automation, Deployment: DeploymentNotApplicable, Steps: []CertificateStep{},
	}
	if !facts.NotBefore.IsZero() {
		atIssuance := StepFor(facts.NotBefore)
		row.ValidityDays = ValidityDays(facts.NotBefore, facts.NotAfter)
		row.MaxDaysAtIssuance = atIssuance.MaxDays
		row.ExceedsMaximumAtIssuance = facts.Scope == ScopePublicTLS && row.ValidityDays > atIssuance.MaxDays
	}
	if facts.Automation == AutomationScheduled {
		row.IdentityID, row.IdentityName, row.Deployment = facts.IdentityID, facts.IdentityName, facts.Deployment
		if facts.RenewalLifetime > 0 {
			row.RenewalLifetimeDays = int(facts.RenewalLifetime / (24 * time.Hour))
			row.RenewalLeadDays = int(RenewalLead(scheduler.RenewBefore, facts.RenewalLifetime) / (24 * time.Hour))
		}
	}
	return row
}

func evaluateCertificate(facts CertificateFacts, scheduler Scheduler, step Step) CertificateStep {
	out := CertificateStep{Effective: step.From.Format(dayLayout), MaxDays: step.MaxDays, Reasons: []string{}}
	switch facts.Automation {
	case AutomationClient:
		out.Verdict = VerdictAtRisk
		out.Reasons = append(out.Reasons, ReasonClientRenewalUnobserved)
	case AutomationScheduled:
		if !scheduler.Enabled {
			out.Verdict = VerdictManual
			out.Reasons = append(out.Reasons, ReasonSchedulerDisabled)
			return out
		}
		out.Reasons = append(out.Reasons, facts.Holds...)
		switch facts.Deployment {
		case DeploymentFailed:
			out.Reasons = append(out.Reasons, ReasonDeliveryFailed)
		case DeploymentDelivered:
			out.Reasons = append(out.Reasons, ReasonDeploymentUnverified)
		case DeploymentNone, DeploymentNotApplicable, "":
			out.Reasons = append(out.Reasons, ReasonNoAutomatedDeployment)
		}
		if facts.ApprovalRequired {
			out.Reasons = append(out.Reasons, ReasonApprovalRequired)
		}
		if facts.Scope == ScopePublicTLS && RequestedDays(facts.RenewalLifetime) > step.MaxDays {
			out.Reasons = append(out.Reasons, ReasonRenewalLifetimeExceedsMaximum)
		}
		out.Verdict = VerdictRenews
		if len(out.Reasons) > 0 {
			out.Verdict = VerdictAtRisk
		}
	default:
		out.Verdict = VerdictManual
		out.Reasons = append(out.Reasons, ReasonNoAutomatedRenewal)
	}
	return out
}

func evaluateProfile(facts ProfileFacts, step Step) ProfileStep {
	out := ProfileStep{Effective: step.From.Format(dayLayout), MaxDays: step.MaxDays}
	if !facts.PublicTLS {
		return out
	}
	switch {
	case facts.MaxValidity <= 0:
		out.Flagged, out.Reason = true, ReasonNoValidityCeiling
	case RequestedDays(facts.MaxValidity) > step.MaxDays:
		out.Flagged, out.Reason = true, ReasonRequestedValidityExceeds
	}
	return out
}

// renewalsPerYear is how many renewals a year a certificate renewed at the
// maximum lifetime needs.
func renewalsPerYear(maxDays int) int {
	if maxDays <= 0 {
		return 0
	}
	return (365 + maxDays - 1) / maxDays
}
