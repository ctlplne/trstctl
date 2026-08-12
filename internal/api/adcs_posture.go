// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

// The AD CS template posture surface (epic F1).
//
// What an operator needs from this page is not a template list — it is the
// answer to "which of my templates can be used to become someone else, and does
// a CA actually offer them". So the response leads with the verdict and carries
// the directory attributes as supporting detail, rather than the other way
// around.

// ADCSTemplateFinding is one dangerous property of one template, as the
// analysis reported it.
type ADCSTemplateFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Summary states what an attacker can do. Remediation names the specific
	// change that removes it — a posture finding an operator cannot act on is a
	// complaint.
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
	Published   bool   `json:"published"`
	// Evidence names the exact directory attributes and values that produced
	// this finding (epic F3). It is what makes the finding falsifiable: an
	// operator can open the template's own property page and check, rather than
	// taking the verdict on faith. The first false positive an operator cannot
	// check destroys their trust in every true finding that follows.
	Evidence []ADCSFindingEvidence `json:"evidence,omitempty"`
}

// ADCSFindingEvidence is one attribute reference behind a finding.
//
// Observed rather than Value: what is recorded here is a directory attribute's
// state — a flag bit, an EKU OID, a schema version — never a credential. The
// name says so, which also keeps it clear of the AN-8 secret-surface
// vocabulary, where a field called Value is assumed to carry material.
type ADCSFindingEvidence struct {
	Attribute string `json:"attribute"`
	Observed  string `json:"observed"`
}

// ADCSTemplate is one observed certificate template.
type ADCSTemplate struct {
	Domain               string   `json:"domain"`
	Template             string   `json:"template"`
	DisplayName          string   `json:"display_name,omitempty"`
	SchemaVersion        int      `json:"schema_version,omitempty"`
	PublishedBy          []string `json:"published_by"`
	EnrollmentPrincipals []string `json:"enrollment_principals"`
	// WorstSeverity is empty when the template has no findings. That is a real
	// state and the console renders it as clean, not as unknown.
	WorstSeverity string                `json:"worst_severity"`
	Findings      []ADCSTemplateFinding `json:"findings"`
	// ObservedBy and ObservedAt are what stop this page being read as current
	// when it is not. A dangerous template an operator is looking at might have
	// been observed last week by a relay that has since stopped running.
	ObservedBy string    `json:"observed_by,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// ADCSEnrollmentEndpoint is one no-body relay observation of an operator-scoped
// IIS enrollment surface. The state vocabulary is closed; no response body,
// redirect target, cookie, or authentication challenge crosses the boundary.
type ADCSEnrollmentEndpoint struct {
	Kind               string   `json:"kind"`
	URL                string   `json:"url"`
	State              string   `json:"state"`
	HTTPStatus         int      `json:"http_status,omitempty"`
	Authentication     []string `json:"authentication"`
	TLSVerified        bool     `json:"tls_verified"`
	ExtendedProtection string   `json:"extended_protection"`
}

// ADCSEnrollmentService is one published CA plus live enrollment-surface and
// CA-side restriction evidence observed by the same authenticated relay run.
type ADCSEnrollmentService struct {
	Domain                 string                   `json:"domain"`
	Service                string                   `json:"service"`
	DNSName                string                   `json:"dns_name,omitempty"`
	EnrollmentWebServices  []string                 `json:"enrollment_web_services"`
	Endpoints              []ADCSEnrollmentEndpoint `json:"endpoints"`
	AgentRestrictionState  string                   `json:"agent_restriction_state"`
	AgentRestrictionSource string                   `json:"agent_restriction_source"`
	WorstSeverity          string                   `json:"worst_severity"`
	Findings               []ADCSTemplateFinding    `json:"findings"`
	ObservedBy             string                   `json:"observed_by"`
	ObservedAt             time.Time                `json:"observed_at"`
}

// ADCSInventorySource is the operator-visible lifecycle of one configured
// directory reader. It carries references and run metadata only; bind
// credentials and raw directory responses never cross this read surface.
type ADCSInventorySource struct {
	SourceID                  string     `json:"source_id"`
	Name                      string     `json:"name"`
	ScheduleID                string     `json:"schedule_id,omitempty"`
	ScheduleEnabled           bool       `json:"schedule_enabled"`
	MonitoringIntervalSeconds int        `json:"monitoring_interval_seconds,omitempty"`
	LastRunID                 string     `json:"last_run_id,omitempty"`
	LastRunStatus             string     `json:"last_run_status"`
	LastRunError              string     `json:"last_run_error,omitempty"`
	LastRunCreatedAt          *time.Time `json:"last_run_created_at,omitempty"`
	LastRunCompletedAt        *time.Time `json:"last_run_completed_at,omitempty"`
}

// ADCSPosture is the served template view.
type ADCSPosture struct {
	// Observed reports whether any relay has ever read a directory for this
	// tenant. Without it an empty list is ambiguous between "no AD CS estate"
	// and "nobody has looked", and those are opposite facts.
	Observed           bool                    `json:"observed"`
	Sources            []ADCSInventorySource   `json:"sources"`
	Templates          []ADCSTemplate          `json:"templates"`
	EnrollmentServices []ADCSEnrollmentService `json:"enrollment_services"`
	// Counts summarize what the page is about to show, so an operator can tell
	// at a glance whether to read it now or later.
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	// Guidance says what is NOT covered, on the page rather than in a document
	// nobody opens. Enrollment ACLs decide who can use a dangerous template,
	// and they are not yet decoded.
	Guidance string `json:"guidance"`
}

// ADCSTemplateDriftChange is one checkable semantic before/after fact. Before
// and After contain normalized flags, OIDs, CA names, or trustee SIDs — never a
// credential or a raw directory security descriptor.
type ADCSTemplateDriftChange struct {
	Template  string `json:"template"`
	Direction string `json:"direction"`
	Change    string `json:"change"`
	Attribute string `json:"attribute,omitempty"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
}

// ADCSTemplateLifecycleChange records a template appearing or disappearing.
type ADCSTemplateLifecycleChange struct {
	Template     string `json:"template"`
	Lifecycle    string `json:"lifecycle"`
	WasDangerous bool   `json:"was_dangerous,omitempty"`
	NowDangerous bool   `json:"now_dangerous,omitempty"`
}

// ADCSTemplateDrift is one immutable source/run-bound comparison between
// consecutive sweeps.
type ADCSTemplateDrift struct {
	ID         string                        `json:"id"`
	RunID      string                        `json:"run_id"`
	SourceID   string                        `json:"source_id"`
	Domain     string                        `json:"domain"`
	AgentID    string                        `json:"agent_id"`
	ObservedBy string                        `json:"observed_by"`
	ObservedAt time.Time                     `json:"observed_at"`
	Direction  string                        `json:"direction"`
	Worsened   bool                          `json:"worsened"`
	Changes    []ADCSTemplateDriftChange     `json:"changes"`
	Lifecycle  []ADCSTemplateLifecycleChange `json:"lifecycle"`
}

// ADCSDriftHistory is the bounded tenant history served to Posture.
type ADCSDriftHistory struct {
	Items []ADCSTemplateDrift `json:"items"`
}

// ADCSPostureProvider reads source lifecycle and observed template posture.
type ADCSPostureProvider func(ctx context.Context, tenantID string) ([]ADCSInventorySource, []ADCSTemplate, []ADCSEnrollmentService, error)

// ADCSDriftProvider reads the tenant's immutable semantic drift history.
type ADCSDriftProvider func(ctx context.Context, tenantID string, limit int) ([]ADCSTemplateDrift, error)

// WithADCSPosture wires the served AD CS template view.
func WithADCSPosture(provider ADCSPostureProvider) Option {
	return func(c *config) { c.adcsPosture = provider }
}

// WithADCSDrift wires the readable semantic drift history.
func WithADCSDrift(provider ADCSDriftProvider) Option {
	return func(c *config) { c.adcsDrift = provider }
}

// adcsPostureGuidance is the honest caveat, carried on the response so it
// travels with the data rather than living only in documentation.
const adcsPostureGuidance = "Enrollment trustees are canonical SIDs from template DACLs. IIS endpoints are only probed when explicitly configured. CA Enrollment Agent Restrictions require a Windows relay with certutil access; inaccessible evidence stays unobserved. Group expansion, inherited/conditional policy, and effective access remain directory-side decisions."

func (a *API) getADCSPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := ADCSPosture{Sources: []ADCSInventorySource{}, Templates: []ADCSTemplate{}, EnrollmentServices: []ADCSEnrollmentService{}, Guidance: adcsPostureGuidance}
	if a.adcsPosture == nil {
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	sources, templates, services, err := a.adcsPosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out.Sources = sources
	if len(templates) > 0 || len(services) > 0 {
		out.Observed = true
		out.Templates = templates
		out.EnrollmentServices = services
	}
	for _, service := range services {
		switch service.WorstSeverity {
		case "critical":
			out.Critical++
		case "high":
			out.High++
		case "medium":
			out.Medium++
		}
	}
	for _, t := range templates {
		switch t.WorstSeverity {
		case "critical":
			out.Critical++
		case "high":
			out.High++
		case "medium":
			out.Medium++
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getADCSDrift(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := ADCSDriftHistory{Items: []ADCSTemplateDrift{}}
	if a.adcsDrift == nil {
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	items, err := a.adcsDrift(r.Context(), tenantID, 50)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items != nil {
		out.Items = items
	}
	a.writeJSON(w, http.StatusOK, out)
}
