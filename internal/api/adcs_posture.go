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
	Observed  bool                  `json:"observed"`
	Sources   []ADCSInventorySource `json:"sources"`
	Templates []ADCSTemplate        `json:"templates"`
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

// ADCSPostureProvider reads source lifecycle and observed template posture.
type ADCSPostureProvider func(ctx context.Context, tenantID string) ([]ADCSInventorySource, []ADCSTemplate, error)

// WithADCSPosture wires the served AD CS template view.
func WithADCSPosture(provider ADCSPostureProvider) Option {
	return func(c *config) { c.adcsPosture = provider }
}

// adcsPostureGuidance is the honest caveat, carried on the response so it
// travels with the data rather than living only in documentation.
const adcsPostureGuidance = "Enrollment trustees are reported as canonical Windows SIDs from each template DACL. Group expansion, inherited or conditional policy, and a user's effective access remain directory-side decisions; verify those before changing access."

func (a *API) getADCSPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := ADCSPosture{Sources: []ADCSInventorySource{}, Templates: []ADCSTemplate{}, Guidance: adcsPostureGuidance}
	if a.adcsPosture == nil {
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	sources, templates, err := a.adcsPosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out.Sources = sources
	if len(templates) > 0 {
		out.Observed = true
		out.Templates = templates
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
