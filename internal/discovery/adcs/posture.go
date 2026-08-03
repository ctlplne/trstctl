// SPDX-License-Identifier: MPL-2.0

package adcs

import (
	"sort"
	"strings"
)

// Dangerous-combination analysis (epic F1).
//
// An inventory of template attributes is not useful on its own. No operator
// scans four boolean columns across ninety templates and notices that number
// forty-one is a domain escalation path. What makes this worth reading is that
// the COMBINATIONS are named, because that is what a finding is: not "this
// template has enrollee-supplies-subject set" but "anyone who can enrol on this
// template can obtain a certificate that authenticates as anyone else".
//
// Each check below states the condition, why the combination is dangerous, and
// what removes it. The last part matters most: a posture finding an operator
// cannot act on is a complaint.

// Severity of a template finding.
type Severity string

const (
	// SeverityCritical: the combination is directly exploitable by anyone
	// holding the enrollment right.
	SeverityCritical Severity = "critical"
	// SeverityHigh: the combination is exploitable with an additional
	// condition that is commonly true.
	SeverityHigh Severity = "high"
	// SeverityMedium: the combination weakens containment rather than granting
	// impersonation on its own.
	SeverityMedium Severity = "medium"
)

// Finding is one dangerous property of one template.
type Finding struct {
	Template string   `json:"template"`
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	// Summary states what an attacker can do, in those terms. A finding that
	// describes a flag rather than a consequence gets triaged as noise.
	Summary string `json:"summary"`
	// Remediation names the specific change. "Review this template" is not a
	// remediation; "clear the enrollee-supplies-subject flag, or require manager
	// approval" is.
	Remediation string `json:"remediation"`
	// Published reports whether a CA actually offers this template. An
	// unpublished dangerous template is a latent risk an operator can fix
	// calmly; a published one is not.
	Published bool `json:"published"`
}

// Findings returns every dangerous combination in the inventory, most severe
// first, then by template name so two runs over an unchanged domain produce
// identical output.
func Findings(inv Inventory) []Finding {
	var out []Finding
	for _, t := range inv.Templates {
		out = append(out, findingsForTemplate(t)...)
	}
	rank := map[Severity]int{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].Template != out[j].Template {
			return out[i].Template < out[j].Template
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func findingsForTemplate(t Template) []Finding {
	published := len(t.PublishedBy) > 0
	var out []Finding

	// The canonical AD CS escalation. Every element is required: the ability to
	// name your own subject, a purpose that authenticates, and no human in the
	// loop. Any one of them missing changes the answer, which is exactly why
	// reporting the flags separately would not have surfaced this.
	if t.EnrolleeSuppliesSubject && t.AllowsClientAuthentication() && !t.RequiresManagerApproval {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC1", Severity: SeverityCritical,
			Summary:     "Anyone holding enrollment rights on this template can request a certificate naming any subject — including a domain administrator — and use it to authenticate as them. The template supplies no manager approval to interrupt that.",
			Remediation: "Clear msPKI-Certificate-Name-Flag's enrollee-supplies-subject bit so the CA builds the subject from the directory, or set the pend-manager-approval enrollment flag so a human sees each request. Removing the client-authentication EKU also closes it, if the template does not need to authenticate.",
			Published:   published,
		})
	}

	// The SAN variant, which matters more in practice than the subject one:
	// modern Windows authentication reads the SAN's UPN, not the subject DN.
	if t.EnrolleeSuppliesSAN && t.AllowsClientAuthentication() && !t.RequiresManagerApproval {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC1-SAN", Severity: SeverityCritical,
			Summary:     "The requester may supply the subject alternative name, which is what Windows authentication actually reads. A certificate carrying another account's UPN authenticates as that account.",
			Remediation: "Clear the enrollee-supplies-subject-alt-name bit in msPKI-Certificate-Name-Flag, or require manager approval. This is the more urgent of the two supplies-subject variants, because SAN-based mapping is the default path.",
			Published:   published,
		})
	}

	// Approval turns an exploitable template into a monitored one. Saying so
	// separately gives an operator a defensible interim step when clearing the
	// flag would break an enrollment their business depends on.
	if (t.EnrolleeSuppliesSubject || t.EnrolleeSuppliesSAN) && t.RequiresManagerApproval {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-SUPPLIES-SUBJECT-APPROVED", Severity: SeverityMedium,
			Summary:     "The requester may supply their own subject or SAN, but manager approval is required, so issuance is not automatic. The risk is now whoever approves — and whether they can tell a legitimate request from an escalation.",
			Remediation: "Keep approval in place, and make sure approvers can see the requested subject. Clearing the enrollee-supplies-subject bits removes the risk entirely where the enrollment does not need them.",
			Published:   published,
		})
	}

	// Schema version 1 templates predate the enrollment controls entirely.
	if t.SchemaVersion == 1 && t.AllowsClientAuthentication() {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-V1-AUTH", Severity: SeverityHigh,
			Summary:     "This is a schema version 1 template that can issue authentication certificates. Version 1 templates cannot express the enrollment and key controls later versions have, so several hardening options simply do not exist for it.",
			Remediation: "Duplicate it as a version 2 or later template, apply the controls there, republish, and unpublish the version 1 original. Duplicating rather than editing is the point — version 1 templates cannot be upgraded in place.",
			Published:   published,
		})
	}

	// Exportable keys weaken every other control, because the certificate stops
	// being bound to the machine it was issued to.
	if t.ExportableKey && t.AllowsClientAuthentication() {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-EXPORTABLE-AUTH", Severity: SeverityHigh,
			Summary:     "Certificates from this template authenticate, and their private keys can be exported. An identity that can be copied off its machine can be used from anywhere, and the theft leaves no trace on the CA.",
			Remediation: "Clear the exportable-key bit in msPKI-Private-Key-Flag so the key is generated non-exportable, and prefer a TPM or smart-card key storage provider where the platform supports it.",
			Published:   published,
		})
	}

	// A template with no EKU restriction at all.
	if len(t.EKUs) == 0 {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-NO-EKU", Severity: SeverityHigh,
			Summary:     "This template restricts no extended key usage, so certificates it issues are valid for every purpose — client authentication, server authentication, code signing, and anything else a relying party checks for.",
			Remediation: "Set pKIExtendedKeyUsage to the specific purposes this template exists to serve. An unrestricted certificate is a credential whose blast radius nobody has decided.",
			Published:   published,
		})
	}
	if containsEKU(t.EKUs, EKUAnyPurpose) {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ANY-PURPOSE", Severity: SeverityHigh,
			Summary:     "This template carries the any-purpose EKU, which explicitly permits every use. It is the same blast radius as no EKU at all, stated deliberately.",
			Remediation: "Replace the any-purpose OID with the specific EKUs this template needs.",
			Published:   published,
		})
	}
	return out
}

func containsEKU(ekus []string, want string) bool {
	for _, eku := range ekus {
		if strings.TrimSpace(eku) == want {
			return true
		}
	}
	return false
}
