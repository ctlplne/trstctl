// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
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
}

// ADCSTemplate is one observed certificate template.
type ADCSTemplate struct {
	Domain        string   `json:"domain"`
	Template      string   `json:"template"`
	DisplayName   string   `json:"display_name,omitempty"`
	SchemaVersion int      `json:"schema_version,omitempty"`
	PublishedBy   []string `json:"published_by"`
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

// ADCSPosture is the served template view.
type ADCSPosture struct {
	// Observed reports whether any relay has ever read a directory for this
	// tenant. Without it an empty list is ambiguous between "no AD CS estate"
	// and "nobody has looked", and those are opposite facts.
	Observed  bool           `json:"observed"`
	Templates []ADCSTemplate `json:"templates"`
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

// ADCSPostureProvider reads the observed template posture.
type ADCSPostureProvider func(ctx context.Context, tenantID string) ([]ADCSTemplate, error)

// WithADCSPosture wires the served AD CS template view.
func WithADCSPosture(provider ADCSPostureProvider) Option {
	return func(c *config) { c.adcsPosture = provider }
}

// adcsPostureGuidance is the honest caveat, carried on the response so it
// travels with the data rather than living only in documentation.
const adcsPostureGuidance = "Enrollment ACLs are not yet decoded, so these findings describe what a template permits, not who may use it. A dangerous template restricted to a small group is a different risk from the same template open to Domain Users, and this page cannot yet tell them apart."

func (a *API) getADCSPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := ADCSPosture{Templates: []ADCSTemplate{}, Guidance: adcsPostureGuidance}
	if a.adcsPosture == nil {
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	templates, err := a.adcsPosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
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

// decodeADCSFindings turns the stored analysis output into the served shape. A
// row whose findings do not decode is rendered with none rather than dropped:
// the template itself is still a fact worth showing.
func decodeADCSFindings(raw json.RawMessage) []ADCSTemplateFinding {
	out := []ADCSTemplateFinding{}
	if len(raw) == 0 {
		return out
	}
	var decoded []ADCSTemplateFinding
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return out
	}
	return append(out, decoded...)
}
