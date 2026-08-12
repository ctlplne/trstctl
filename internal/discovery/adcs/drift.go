// SPDX-License-Identifier: MPL-2.0

package adcs

import (
	"sort"
	"strings"
)

// Template drift: what changed, in security terms (epic F2).
//
// A textual diff of two directory dumps is useless to an operator. Attribute
// values are bit fields and OID lists; "msPKI-Certificate-Name-Flag changed from
// 0 to 1" is technically a diff and tells nobody anything. What matters is that
// somebody turned on enrollee-supplies-subject on a template that authenticates
// users, which is the difference between an ordinary template and a domain
// escalation path.
//
// So the diff is SEMANTIC. Each change says what it means and whether it made
// things worse, because "worse" is the only signal that should reach an operator
// out of hours. A template that gained manager approval changed too, and nobody
// needs waking for it.

// DriftDirection says which way a change moved the template's safety.
type DriftDirection string

const (
	// DriftWorse means the change opened something. These are what alert.
	DriftWorse DriftDirection = "worse"
	// DriftBetter means the change closed something. Recorded, never alerted:
	// an operator who just hardened a template does not need telling.
	DriftBetter DriftDirection = "better"
	// DriftNeutral is a change with no direct safety meaning — a display name,
	// a schema bump — kept because "the template changed at all" is sometimes
	// the fact that matters in an incident.
	DriftNeutral DriftDirection = "neutral"
)

// TemplateChange is one semantic change to one template.
type TemplateChange struct {
	Template  string         `json:"template"`
	Direction DriftDirection `json:"direction"`
	// Change states what happened in the terms an operator thinks in, not the
	// attribute that carried it.
	Change string `json:"change"`
	// Attribute and the before/after values are the audit trail behind the
	// sentence, for the same reason findings carry evidence: a claim about
	// someone's directory that they cannot check is a claim they will not act
	// on.
	Attribute string `json:"attribute,omitempty"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
}

// TemplateLifecycle is a template appearing or disappearing between sweeps.
type TemplateLifecycle string

const (
	// TemplateAdded is a template that did not exist at the last sweep. A new
	// template is worth seeing even when it is safe — it is a change to the
	// estate's enrollment surface that somebody made deliberately.
	TemplateAdded TemplateLifecycle = "added"
	// TemplateRemoved is a template that has gone. Usually good news, and
	// recorded so an incident timeline can show when it went.
	TemplateRemoved TemplateLifecycle = "removed"
)

// LifecycleChange is one template appearing or disappearing.
type LifecycleChange struct {
	Template  string            `json:"template"`
	Lifecycle TemplateLifecycle `json:"lifecycle"`
	// WasDangerous reports whether a REMOVED template had findings, so a
	// timeline can distinguish "they deleted an unused template" from "they
	// removed the escalation path we reported".
	WasDangerous bool `json:"was_dangerous,omitempty"`
	// NowDangerous reports whether an ADDED template arrives with findings.
	// A new template that is immediately exploitable is the single most
	// alarming thing this whole epic can observe.
	NowDangerous bool `json:"now_dangerous,omitempty"`
}

// Drift is the whole semantic difference between two sweeps.
type Drift struct {
	Changes   []TemplateChange  `json:"changes"`
	Lifecycle []LifecycleChange `json:"lifecycle"`
}

// Direction summarizes the whole sweep without discarding the per-attribute
// direction below it. Any newly opened access wins because that is the fact an
// alert router must see. Otherwise a pure hardening sweep is better; appearance,
// disappearance, or descriptive edits are neutral timeline facts.
func (d Drift) Direction() DriftDirection {
	if d.Worsened() {
		return DriftWorse
	}
	hasBetter := false
	for _, change := range d.Changes {
		switch change.Direction {
		case DriftNeutral:
			return DriftNeutral
		case DriftBetter:
			hasBetter = true
		}
	}
	if len(d.Lifecycle) > 0 {
		return DriftNeutral
	}
	if hasBetter {
		return DriftBetter
	}
	return DriftNeutral
}

// Worsened reports whether anything got less safe. It is the single question an
// alert should be gated on: a sweep where three templates were hardened and a
// display name changed is not an event anyone needs woken for.
func (d Drift) Worsened() bool {
	for _, change := range d.Changes {
		if change.Direction == DriftWorse {
			return true
		}
	}
	for _, life := range d.Lifecycle {
		if life.Lifecycle == TemplateAdded && life.NowDangerous {
			return true
		}
	}
	return false
}

// DiffTemplates computes the semantic difference between two sweeps.
//
// previous being empty means this is a first sweep, and a first sweep is NOT
// drift: reporting an entire estate as "added" the first time anyone looks
// would bury the real change that comes next under ninety notifications. It
// returns an empty diff, and the caller records the baseline.
func DiffTemplates(previous, current []Template) Drift {
	if len(previous) == 0 {
		return Drift{}
	}
	before := index(previous)
	after := index(current)

	var drift Drift
	names := make([]string, 0, len(after))
	for name := range after {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		old, existed := before[name]
		now := after[name]
		if !existed {
			drift.Lifecycle = append(drift.Lifecycle, LifecycleChange{
				Template: name, Lifecycle: TemplateAdded,
				NowDangerous: len(findingsForTemplate(now, EnrollmentAgentRestrictions{State: EvidenceUnobserved, Source: "drift_template_only"})) > 0,
			})
			continue
		}
		drift.Changes = append(drift.Changes, compareTemplate(old, now)...)
	}

	goneNames := make([]string, 0)
	for name := range before {
		if _, still := after[name]; !still {
			goneNames = append(goneNames, name)
		}
	}
	sort.Strings(goneNames)
	for _, name := range goneNames {
		drift.Lifecycle = append(drift.Lifecycle, LifecycleChange{
			Template: name, Lifecycle: TemplateRemoved,
			WasDangerous: len(findingsForTemplate(before[name], EnrollmentAgentRestrictions{State: EvidenceUnobserved, Source: "drift_template_only"})) > 0,
		})
	}
	return drift
}

// compareTemplate produces the semantic changes between two versions of one
// template.
func compareTemplate(before, after Template) []TemplateChange {
	var out []TemplateChange
	add := func(direction DriftDirection, change, attribute, from, to string) {
		out = append(out, TemplateChange{
			Template: after.Name, Direction: direction, Change: change,
			Attribute: attribute, Before: from, After: to,
		})
	}

	if !before.EnrolleeSuppliesSubject && after.EnrolleeSuppliesSubject {
		add(DriftWorse,
			"The requester may now supply their own subject. On a template that authenticates, this is the canonical escalation path.",
			"msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT clear", "ENROLLEE_SUPPLIES_SUBJECT set")
	}
	if before.EnrolleeSuppliesSubject && !after.EnrolleeSuppliesSubject {
		add(DriftBetter,
			"The CA now builds the subject from the directory rather than accepting the requester's.",
			"msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT set", "ENROLLEE_SUPPLIES_SUBJECT clear")
	}
	if !before.EnrolleeSuppliesSAN && after.EnrolleeSuppliesSAN {
		add(DriftWorse,
			"The requester may now supply the subject alternative name, which is what Windows authentication actually reads.",
			"msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME clear", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME set")
	}
	if before.EnrolleeSuppliesSAN && !after.EnrolleeSuppliesSAN {
		add(DriftBetter,
			"The requester may no longer supply the subject alternative name.",
			"msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME set", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME clear")
	}
	if before.RequiresManagerApproval && !after.RequiresManagerApproval {
		// The most consequential single change this diff can report: removing
		// approval is what turns a monitored template into an automatic one.
		add(DriftWorse,
			"Manager approval was REMOVED. Requests on this template now issue without a human seeing them.",
			"msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS set", "PEND_ALL_REQUESTS clear")
	}
	if !before.RequiresManagerApproval && after.RequiresManagerApproval {
		add(DriftBetter,
			"Manager approval was added. Requests on this template now wait for a human.",
			"msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS clear", "PEND_ALL_REQUESTS set")
	}
	if !before.ExportableKey && after.ExportableKey {
		add(DriftWorse,
			"Private keys from this template are now exportable, so an identity it issues can be copied off the machine it was issued to.",
			"msPKI-Private-Key-Flag", "CT_FLAG_EXPORTABLE_KEY clear", "CT_FLAG_EXPORTABLE_KEY set")
	}
	if before.ExportableKey && !after.ExportableKey {
		add(DriftBetter,
			"Private keys from this template are no longer exportable.",
			"msPKI-Private-Key-Flag", "CT_FLAG_EXPORTABLE_KEY set", "CT_FLAG_EXPORTABLE_KEY clear")
	}

	// EKU changes are judged by what they enable, not by count. Gaining a
	// server-auth OID is unremarkable; gaining client-auth on a template that
	// could not authenticate before changes what the template IS.
	if !before.AllowsClientAuthentication() && after.AllowsClientAuthentication() {
		add(DriftWorse,
			"This template can now be used to authenticate. Whatever else it permits, certificates from it can now act as an identity.",
			"pKIExtendedKeyUsage", strings.Join(before.EKUs, ", "), strings.Join(after.EKUs, ", "))
	} else if before.AllowsClientAuthentication() && !after.AllowsClientAuthentication() {
		add(DriftBetter,
			"This template can no longer be used to authenticate.",
			"pKIExtendedKeyUsage", strings.Join(before.EKUs, ", "), strings.Join(after.EKUs, ", "))
	} else if !sameStrings(before.EKUs, after.EKUs) {
		add(DriftNeutral,
			"The permitted uses changed, without changing whether this template can authenticate.",
			"pKIExtendedKeyUsage", strings.Join(before.EKUs, ", "), strings.Join(after.EKUs, ", "))
	}

	// Publication is what turns a latent risk into a live one.
	newlyPublished := notIn(after.PublishedBy, before.PublishedBy)
	if len(newlyPublished) > 0 {
		direction := DriftNeutral
		change := "A CA now publishes this template: " + strings.Join(newlyPublished, ", ") + "."
		if len(findingsForTemplate(after, EnrollmentAgentRestrictions{State: EvidenceUnobserved, Source: "drift_template_only"})) > 0 {
			// A dangerous template that was not offered anywhere has just been
			// offered somewhere. That is a real escalation of exposure even
			// though no attribute of the template itself moved.
			direction = DriftWorse
			change = "A CA now publishes this template — and it carries findings, so a latent risk has become an offered one: " +
				strings.Join(newlyPublished, ", ") + "."
		}
		add(direction, change, "certificateTemplates",
			strings.Join(before.PublishedBy, ", "), strings.Join(after.PublishedBy, ", "))
	}
	if unpublished := notIn(before.PublishedBy, after.PublishedBy); len(unpublished) > 0 {
		add(DriftBetter,
			"A CA stopped publishing this template: "+strings.Join(unpublished, ", ")+".",
			"certificateTemplates", strings.Join(before.PublishedBy, ", "), strings.Join(after.PublishedBy, ", "))
	}

	// The enrollment DACL is already reduced at the relay to canonical trustee
	// SIDs. Keep only that safe semantic form: the raw security descriptor is a
	// large binary policy document, not a useful or appropriate console payload.
	// Gaining any trustee opens access and therefore wins over simultaneous
	// removals. A pure trustee removal is recorded as hardening without paging.
	if !sameStrings(before.EnrollmentPrincipals, after.EnrollmentPrincipals) {
		gained := notIn(after.EnrollmentPrincipals, before.EnrollmentPrincipals)
		lost := notIn(before.EnrollmentPrincipals, after.EnrollmentPrincipals)
		direction := DriftBetter
		parts := make([]string, 0, 2)
		if len(gained) > 0 {
			direction = DriftWorse
			parts = append(parts, strings.Join(gained, ", ")+" gained enrollment access")
		}
		if len(lost) > 0 {
			parts = append(parts, strings.Join(lost, ", ")+" lost enrollment access")
		}
		add(direction, strings.Join(parts, "; ")+".",
			"nTSecurityDescriptor enrollment trustees",
			canonicalStrings(before.EnrollmentPrincipals), canonicalStrings(after.EnrollmentPrincipals))
	}
	return out
}

func index(templates []Template) map[string]Template {
	out := make(map[string]Template, len(templates))
	for _, t := range templates {
		out[t.Name] = t
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func canonicalStrings(values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return strings.Join(values, ", ")
}

// notIn returns the members of a that are absent from b.
func notIn(a, b []string) []string {
	have := map[string]bool{}
	for _, s := range b {
		have[strings.TrimSpace(s)] = true
	}
	var out []string
	for _, s := range a {
		if s = strings.TrimSpace(s); s != "" && !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
