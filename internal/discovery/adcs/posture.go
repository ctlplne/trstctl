// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"net/url"
	"sort"
	"strconv"
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
	Template string `json:"template"`
	// ResourceKind and Resource let the same evidence vocabulary cover both
	// certificate templates and enrollment-service endpoints. Template remains
	// populated for backward-compatible per-template grouping.
	ResourceKind string   `json:"resource_kind"`
	Resource     string   `json:"resource"`
	ID           string   `json:"id"`
	Severity     Severity `json:"severity"`
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
	// Evidence names the exact directory attributes that produced this finding,
	// with the values that were read (epic F3). Without it a posture finding is
	// an assertion an operator has to take on faith and cannot check against
	// their own console — and the first false positive destroys trust in every
	// true one. With it, the finding is falsifiable.
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// EvidenceRef is one directory attribute and what was read from it.
//
// Observed rather than Value: this records an attribute's state — a flag bit,
// an EKU OID, a schema version — and never a credential. Naming it Value would
// put it in the AN-8 secret-surface vocabulary, where that word means material.
type EvidenceRef struct {
	Attribute string `json:"attribute"`
	Observed  string `json:"observed"`
}

// Findings returns every dangerous combination in the inventory, most severe
// first, then by template name so two runs over an unchanged domain produce
// identical output.
func Findings(inv Inventory) []Finding {
	var out []Finding
	for _, t := range inv.Templates {
		findings := findingsForTemplate(t, restrictionsForTemplate(t, inv.EnrollmentServices))
		for i := range findings {
			findings[i].ResourceKind = "template"
			findings[i].Resource = t.Name
		}
		out = append(out, findings...)
	}
	for _, service := range inv.EnrollmentServices {
		findings := findingsForEnrollmentService(service)
		for i := range findings {
			findings[i].ResourceKind = "enrollment_service"
			findings[i].Resource = service.Name
		}
		out = append(out, findings...)
	}
	rank := map[Severity]int{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].ResourceKind != out[j].ResourceKind {
			return out[i].ResourceKind < out[j].ResourceKind
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func findingsForTemplate(t Template, restrictions EnrollmentAgentRestrictions) []Finding {
	published := len(t.PublishedBy) > 0
	var out []Finding
	lowPrivilege := lowPrivilegeEnrollmentPrincipals(t.EnrollmentPrincipals)

	// The canonical AD CS escalation. Every element is required: the ability to
	// name your own subject, a purpose that authenticates, and no human in the
	// loop. Any one of them missing changes the answer, which is exactly why
	// reporting the flags separately would not have surfaced this.
	if t.EnrolleeSuppliesSubject && t.AllowsClientAuthentication() && !t.RequiresManagerApproval && len(lowPrivilege) > 0 {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC1", Severity: SeverityCritical,
			Summary:     "Anyone holding enrollment rights on this template can request a certificate naming any subject — including a domain administrator — and use it to authenticate as them. The template supplies no manager approval to interrupt that.",
			Remediation: "Clear msPKI-Certificate-Name-Flag's enrollee-supplies-subject bit so the CA builds the subject from the directory, or set the pend-manager-approval enrollment flag so a human sees each request. Removing the client-authentication EKU also closes it, if the template does not need to authenticate.",
			Published:   published,
			Evidence:    ekuEvidence(t, evidenceRef("msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT is set"), evidenceRef("msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS is not set"), evidenceRef("nTSecurityDescriptor enrollment trustees", strings.Join(lowPrivilege, ", ")+" (broad/low-privileged trustee)")),
		})
	}

	// The SAN variant, which matters more in practice than the subject one:
	// modern Windows authentication reads the SAN's UPN, not the subject DN.
	if t.EnrolleeSuppliesSAN && t.AllowsClientAuthentication() && !t.RequiresManagerApproval && len(lowPrivilege) > 0 {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC1-SAN", Severity: SeverityCritical,
			Summary:     "The requester may supply the subject alternative name, which is what Windows authentication actually reads. A certificate carrying another account's UPN authenticates as that account.",
			Remediation: "Clear the enrollee-supplies-subject-alt-name bit in msPKI-Certificate-Name-Flag, or require manager approval. This is the more urgent of the two supplies-subject variants, because SAN-based mapping is the default path.",
			Published:   published,
			Evidence:    ekuEvidence(t, evidenceRef("msPKI-Certificate-Name-Flag", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME is set"), evidenceRef("msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS is not set"), evidenceRef("nTSecurityDescriptor enrollment trustees", strings.Join(lowPrivilege, ", ")+" (broad/low-privileged trustee)")),
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
			Evidence:    []EvidenceRef{evidenceRef("msPKI-Certificate-Name-Flag", "an enrollee-supplies bit is set"), evidenceRef("msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS is set")},
		})
	}

	// Schema version 1 templates predate the enrollment controls entirely.
	if t.SchemaVersion == 1 && t.AllowsClientAuthentication() {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-V1-AUTH", Severity: SeverityHigh,
			Summary:     "This is a schema version 1 template that can issue authentication certificates. Version 1 templates cannot express the enrollment and key controls later versions have, so several hardening options simply do not exist for it.",
			Remediation: "Duplicate it as a version 2 or later template, apply the controls there, republish, and unpublish the version 1 original. Duplicating rather than editing is the point — version 1 templates cannot be upgraded in place.",
			Published:   published,
			Evidence:    ekuEvidence(t, evidenceRef("msPKI-Template-Schema-Version", "1")),
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
			Evidence:    ekuEvidence(t, evidenceRef("msPKI-Private-Key-Flag", "CT_FLAG_EXPORTABLE_KEY is set")),
		})
	}

	// The enrollment-agent primitive. This is not impersonation of one account;
	// it is the ability to request certificates on behalf of ANY principal, so
	// a single such certificate is a master key to every template that accepts
	// agent-signed requests. It is worth its own finding rather than being
	// folded into the client-auth checks, because the remediation is different:
	// restricting who may enrol is not enough, the CA must also restrict which
	// templates accept agent requests and from which agents.
	if containsEKU(t.EKUs, EKUCertificateRequestAgent) && !t.RequiresManagerApproval && restrictions.State == EvidenceDisabled {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC3-AGENT", Severity: SeverityCritical,
			Summary:     "This template issues enrollment-agent certificates without manager approval. An enrollment agent can request certificates on behalf of any principal, so one of these is not an impersonation of a single account — it is a master key to every template that accepts agent-signed requests.",
			Remediation: "Require manager approval on this template, and on the CA restrict enrollment-agent rights (Enrollment Agent Restrictions) so agents may only request specific templates for specific groups. Removing the Certificate Request Agent EKU closes it entirely where the workflow does not need delegated enrollment.",
			Published:   published,
			Evidence:    ekuEvidence(t, evidenceRef("pKIExtendedKeyUsage", EKUCertificateRequestAgent), evidenceRef("msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS is not set"), evidenceRef("CA Enrollment Agent Restrictions", string(restrictions.State)+" via "+restrictions.Source)),
		})
	}
	if containsEKU(t.EKUs, EKUCertificateRequestAgent) && restrictions.State == EvidenceUnobserved {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC3-RESTRICTIONS-UNOBSERVED", Severity: SeverityMedium,
			Summary:     "This template issues enrollment-agent certificates, but the relay could not observe the CA's Enrollment Agent Restrictions. The template alone cannot prove whether an issued agent is tightly scoped or remains a master key to every accepting template.",
			Remediation: "Collect CA-side Enrollment Agent Restrictions from a Windows relay that can query the publishing CA. Until the result is enabled and scoped, do not treat manager approval or a narrow template DACL as proof that delegated enrollment is contained.",
			Published:   published,
			Evidence: ekuEvidence(t, evidenceRef("pKIExtendedKeyUsage", EKUCertificateRequestAgent),
				evidenceRef("CA Enrollment Agent Restrictions", "unobserved via "+restrictions.Source)),
		})
	}
	// Even with approval, an enrollment-agent template is worth naming: the
	// control now rests entirely on whoever approves.
	if containsEKU(t.EKUs, EKUCertificateRequestAgent) && t.RequiresManagerApproval && restrictions.State == EvidenceDisabled {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ESC3-AGENT-APPROVED", Severity: SeverityMedium,
			Summary:     "This template issues enrollment-agent certificates, gated by manager approval. Delegated enrollment is legitimate, but the certificates it produces can request on behalf of others, so the approval step is now the only thing standing between a request and a master key.",
			Remediation: "Confirm the CA's Enrollment Agent Restrictions actually bound which templates and which principals these agents may request for. Approval alone does not scope what an issued agent certificate can go on to do.",
			Published:   published,
			Evidence: []EvidenceRef{evidenceRef("pKIExtendedKeyUsage", EKUCertificateRequestAgent), evidenceRef("msPKI-Enrollment-Flag", "PEND_ALL_REQUESTS is set"),
				evidenceRef("CA Enrollment Agent Restrictions", string(restrictions.State)+" via "+restrictions.Source)},
		})
	}

	// A template with no EKU restriction at all.
	if len(t.EKUs) == 0 {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-NO-EKU", Severity: SeverityHigh,
			Summary:     "This template restricts no extended key usage, so certificates it issues are valid for every purpose — client authentication, server authentication, code signing, and anything else a relying party checks for.",
			Remediation: "Set pKIExtendedKeyUsage to the specific purposes this template exists to serve. An unrestricted certificate is a credential whose blast radius nobody has decided.",
			Published:   published,
			Evidence:    []EvidenceRef{evidenceRef("pKIExtendedKeyUsage", "no values")},
		})
	}
	if containsEKU(t.EKUs, EKUAnyPurpose) {
		out = append(out, Finding{
			Template: t.Name, ID: "ADCS-ANY-PURPOSE", Severity: SeverityHigh,
			Summary:     "This template carries the any-purpose EKU, which explicitly permits every use. It is the same blast radius as no EKU at all, stated deliberately.",
			Remediation: "Replace the any-purpose OID with the specific EKUs this template needs.",
			Published:   published,
			Evidence:    []EvidenceRef{evidenceRef("pKIExtendedKeyUsage", EKUAnyPurpose)},
		})
	}
	return out
}

func restrictionsForTemplate(t Template, services []EnrollmentService) EnrollmentAgentRestrictions {
	result := EnrollmentAgentRestrictions{State: EvidenceUnobserved, Source: "publishing_ca_not_observed"}
	for _, service := range services {
		if !containsString(t.PublishedBy, service.Name) {
			continue
		}
		switch service.AgentRestrictions.State {
		case EvidenceDisabled:
			return service.AgentRestrictions
		case EvidenceEnabled:
			result = service.AgentRestrictions
		}
	}
	return result
}

func lowPrivilegeEnrollmentPrincipals(principals []string) []string {
	out := make([]string, 0, len(principals))
	for _, sid := range principals {
		if broadEnrollmentSID(sid) {
			out = append(out, sid)
		}
	}
	sort.Strings(out)
	return out
}

func broadEnrollmentSID(sid string) bool {
	switch sid {
	case "S-1-1-0", "S-1-5-11", "S-1-5-32-545": // Everyone, Authenticated Users, BUILTIN Users.
		return true
	}
	parts := strings.Split(sid, "-")
	if len(parts) < 5 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	switch parts[len(parts)-1] {
	case "513", "515": // Domain Users and Domain Computers in any domain SID namespace.
		return true
	default:
		return false
	}
}

func findingsForEnrollmentService(service EnrollmentService) []Finding {
	var out []Finding
	for _, raw := range service.EnrollmentWebServices {
		if parsed, err := url.Parse(raw); err == nil && parsed.Scheme == "http" {
			out = append(out, Finding{
				ID: "ADCS-CES-PLAINTEXT", Severity: SeverityHigh,
				Summary:     "This Certificate Enrollment Web Service URI is published over plaintext HTTP. Enrollment authentication and certificate request metadata can cross the network without server-authenticated TLS.",
				Remediation: "Publish the enrollment web service only over HTTPS with a certificate clients validate, remove the HTTP URI from msPKI-Enrollment-Servers, and confirm clients have refreshed policy before retiring the old endpoint.",
				Published:   true,
				Evidence:    []EvidenceRef{evidenceRef("msPKI-Enrollment-Servers", raw)},
			})
		}
	}
	for _, endpoint := range service.Endpoints {
		parsed, err := url.Parse(endpoint.URL)
		if err != nil {
			continue
		}
		observed := string(endpoint.State)
		if endpoint.HTTPStatus != 0 {
			observed += " HTTP " + strconv.Itoa(endpoint.HTTPStatus)
		}
		if endpoint.State != EndpointAnonymousAccess && endpoint.State != EndpointAuthenticationNeeded {
			continue
		}
		if parsed.Scheme == "http" {
			id := "ADCS-WEB-ENROLLMENT-PLAINTEXT"
			surface := "CA Web Enrollment"
			if endpoint.Kind == EndpointNDES || endpoint.Kind == EndpointNDESAdmin {
				id, surface = "ADCS-NDES-PLAINTEXT", "NDES"
			}
			out = append(out, Finding{
				ID: id, Severity: SeverityCritical,
				Summary:     surface + " is reachable over plaintext HTTP. A network attacker can tamper with enrollment traffic or relay credentials before any certificate policy is evaluated.",
				Remediation: "Disable the HTTP binding, require a certificate-validated HTTPS endpoint, and retest from the in-domain relay. If Windows authentication is used, verify Extended Protection on the IIS application before treating NTLM relay risk as contained.",
				Published:   true,
				Evidence:    []EvidenceRef{evidenceRef("enrollment endpoint", endpoint.URL+"; "+observed), evidenceRef("TLS", "not used")},
			})
		}
		if endpoint.Kind == EndpointNDESAdmin && endpoint.State == EndpointAnonymousAccess {
			out = append(out, Finding{
				ID: "ADCS-NDES-ADMIN-ANONYMOUS", Severity: SeverityCritical,
				Summary:     "The NDES administration endpoint returned content without an authentication challenge. That surface issues enrollment passwords, so anonymous reachability can hand an unauthenticated caller issuance authority.",
				Remediation: "Require authenticated, tightly scoped access to mscep_admin, place it behind verified TLS, rotate any exposed challenge material, and confirm an unauthenticated relay probe receives 401 or 403 rather than content.",
				Published:   true,
				Evidence:    []EvidenceRef{evidenceRef("NDES administration endpoint", endpoint.URL+"; "+observed)},
			})
		}
		if endpoint.Kind == EndpointWebEnrollment && endpoint.State == EndpointAuthenticationNeeded &&
			containsAuthentication(endpoint.Authentication, "ntlm", "negotiate") && endpoint.ExtendedProtection != EvidenceEnabled {
			severity := SeverityMedium
			id := "ADCS-WEB-ENROLLMENT-EPA-UNOBSERVED"
			if endpoint.ExtendedProtection == EvidenceDisabled {
				severity, id = SeverityCritical, "ADCS-WEB-ENROLLMENT-EPA-DISABLED"
			}
			out = append(out, Finding{
				ID: id, Severity: severity,
				Summary:     "CA Web Enrollment advertises Windows authentication, but Extended Protection is " + string(endpoint.ExtendedProtection) + ". Template hardening does not stop credential relay at an IIS enrollment endpoint whose channel binding is absent or unknown.",
				Remediation: "Enable and require IIS Extended Protection for the CA Web Enrollment application, keep the endpoint on verified TLS, then collect CA-host evidence so the control is observed as enabled rather than assumed.",
				Published:   true,
				Evidence:    []EvidenceRef{evidenceRef("CA Web Enrollment endpoint", endpoint.URL+"; "+observed), evidenceRef("WWW-Authenticate", strings.Join(endpoint.Authentication, ", ")), evidenceRef("Extended Protection", string(endpoint.ExtendedProtection))},
			})
		}
	}
	return out
}

func containsAuthentication(values []string, wants ...string) bool {
	for _, value := range values {
		for _, want := range wants {
			if strings.EqualFold(strings.TrimSpace(value), want) {
				return true
			}
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// evidenceRef builds one attribute reference.
func evidenceRef(attribute, observed string) EvidenceRef {
	return EvidenceRef{Attribute: attribute, Observed: observed}
}

// ekuEvidence appends the template's EKU list to the given references, since
// almost every dangerous combination depends on what the certificate may be
// used FOR. Naming the OIDs read means an operator can match the finding
// against the template's own property page rather than trusting it.
func ekuEvidence(t Template, refs ...EvidenceRef) []EvidenceRef {
	observed := strings.Join(t.EKUs, ", ")
	if observed == "" {
		observed = "no values (unrestricted, therefore includes authentication)"
	}
	return append(refs, evidenceRef("pKIExtendedKeyUsage", observed))
}

func containsEKU(ekus []string, want string) bool {
	for _, eku := range ekus {
		if strings.TrimSpace(eku) == want {
			return true
		}
	}
	return false
}
