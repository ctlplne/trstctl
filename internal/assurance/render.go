// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"fmt"
	"strings"
	"time"
)

// Render is the record as readable Markdown: every stage, its basis and its
// evidence IDs. It is a rendering of the signed record, not a separate claim.
func Render(r Record) string {
	var b strings.Builder
	c := r.Credential
	fmt.Fprintf(&b, "# Credential assurance record\n\n")
	fmt.Fprintf(&b, "Certificate %s, fingerprint `%s`, serial `%s`, issued by %s.\n", orNone(c.Subject), c.Fingerprint, orNone(c.Serial), orNone(c.Issuer))
	fmt.Fprintf(&b, "Valid %s to %s; status %s.\n", day(c.NotBefore), day(c.NotAfter), orNone(c.Status))
	if len(c.IdentityIDs) > 0 {
		fmt.Fprintf(&b, "Lifecycle identities: %s.\n", strings.Join(c.IdentityIDs, ", "))
	}
	fmt.Fprintf(&b, "Generated %s for tenant %s (%s).\n\n", r.GeneratedAt.UTC().Format(time.RFC3339), r.TenantID, r.Format)
	fmt.Fprintf(&b, "- Independently observed: %s\n", list(r.IndependentlyObserved))
	fmt.Fprintf(&b, "- Recorded by trstctl only: %s\n", list(r.RecordedOnly))
	fmt.Fprintf(&b, "- No evidence: %s\n", list(r.Absent))
	if len(r.Truncated) > 0 {
		fmt.Fprintf(&b, "- Bounded lists (more evidence exists): %s\n", list(r.Truncated))
	}

	fmt.Fprintf(&b, "\n## Discovery\n\n")
	if len(r.Discovery) == 0 {
		fmt.Fprintf(&b, "No discovery source has found this certificate.\n")
	}
	for _, d := range r.Discovery {
		fmt.Fprintf(&b, "- %s: %s (%s) at %s, %s. Evidence `%s`.\n", stamp(d.ObservedAt), orNone(d.Source), orNone(d.SourceKind), orNone(d.Location), d.Basis, d.EvidenceID)
	}

	fmt.Fprintf(&b, "\n## Owner\n\n")
	if r.Owner == nil {
		fmt.Fprintf(&b, "No owner is recorded.\n")
	} else {
		fmt.Fprintf(&b, "%s (%s), %s. Evidence `%s`.\n", r.Owner.Name, r.Owner.Kind, r.Owner.Basis, r.Owner.EvidenceID)
	}

	i := r.Issuance
	fmt.Fprintf(&b, "\n## Issuance\n\n")
	if i.IssuedByTrstctl {
		fmt.Fprintf(&b, "Issued through trstctl by %s", orNone(i.CA))
		if i.ExternalCAID != "" {
			fmt.Fprintf(&b, " (external CA %s)", i.ExternalCAID)
		}
		if i.IssuedAt != nil {
			fmt.Fprintf(&b, " at %s", stamp(*i.IssuedAt))
		}
		fmt.Fprintf(&b, ", %s. Evidence `%s`.\n", i.Basis, i.EvidenceID)
	} else {
		fmt.Fprintf(&b, "Not issued through trstctl: recorded from source %s, naming issuer %s. Evidence `%s`.\n", orNone(i.Source), orNone(i.CA), i.EvidenceID)
	}
	if i.Profile != nil {
		fmt.Fprintf(&b, "- Profile %s v%d (spec %s). Evidence `%s`.\n", i.Profile.Name, i.Profile.Version, i.Profile.SpecDigest, i.Profile.EvidenceID)
	} else if i.IssuedByTrstctl {
		fmt.Fprintf(&b, "- No profile binding was retained with this issuance.\n")
	}
	if i.Approval != nil {
		fmt.Fprintf(&b, "- Approved under request %s (%d approvals required, requested by %s). Evidence `%s`.\n", i.Approval.RequestID, i.Approval.RequiredApprovals, orNone(i.Approval.Requester), i.Approval.EvidenceID)
	}
	if i.KeyOrigin != "" {
		fmt.Fprintf(&b, "- Key origin: %s.\n", i.KeyOrigin)
	}

	fmt.Fprintf(&b, "\n## Deployments\n\n")
	if len(r.Deployments) == 0 {
		fmt.Fprintf(&b, "No connector has delivered this certificate.\n")
	}
	for _, d := range r.Deployments {
		fmt.Fprintf(&b, "- %s: %s to %s via %s, %s (%s). Evidence `%s`.\n", stamp(d.At), d.Status, orNone(d.Target), orNone(d.Connector), d.Basis, orNone(d.Reason), d.EvidenceID)
	}

	fmt.Fprintf(&b, "\n## Verifications\n\n")
	if len(r.Verifications) == 0 {
		fmt.Fprintf(&b, "Nothing has checked what an endpoint serves for this certificate.\n")
	}
	for _, v := range r.Verifications {
		where := firstNonEmpty(v.Address, v.Endpoint, v.Target)
		fmt.Fprintf(&b, "- %s: %s from the %s vantage", stamp(v.At), v.Outcome, v.Vantage)
		if v.Agent != "" {
			fmt.Fprintf(&b, " (%s)", v.Agent)
		}
		if where != "" {
			fmt.Fprintf(&b, " at %s", where)
		}
		if v.ServedFingerprint != "" {
			fmt.Fprintf(&b, ", serving `%s`", v.ServedFingerprint)
		}
		if v.Mismatch != "" {
			fmt.Fprintf(&b, ", %s mismatch", v.Mismatch)
		}
		if v.CheckedChain {
			fmt.Fprintf(&b, ", chain checked")
		}
		fmt.Fprintf(&b, ", %s. Evidence `%s`", v.Basis, v.EvidenceID)
		if v.TranscriptDigest != "" {
			fmt.Fprintf(&b, ", transcript %s", v.TranscriptDigest)
		}
		fmt.Fprintf(&b, ".\n")
	}

	fmt.Fprintf(&b, "\n## Renewals\n\n")
	if r.Renewals.Predecessor == nil && len(r.Renewals.Successors) == 0 && len(r.Renewals.Runs) == 0 {
		fmt.Fprintf(&b, "No renewal is recorded.\n")
	}
	if p := r.Renewals.Predecessor; p != nil {
		fmt.Fprintf(&b, "- Replaced %s (`%s`, %s).\n", p.CertificateID, p.Fingerprint, p.Status)
	}
	for _, s := range r.Renewals.Successors {
		fmt.Fprintf(&b, "- Replaced by %s (`%s`, %s).\n", s.CertificateID, s.Fingerprint, s.Status)
	}
	for _, run := range r.Renewals.Runs {
		fmt.Fprintf(&b, "- %s: renewal %s as %s (%s trigger), %s. Evidence `%s`.\n", stamp(run.StartedAt), run.Status, run.Role, orNone(run.Trigger), run.Basis, run.EvidenceID)
	}

	fmt.Fprintf(&b, "\n## Revocation\n\n")
	if r.Revocation == nil {
		fmt.Fprintf(&b, "Not revoked.\n")
	} else {
		fmt.Fprintf(&b, "Revoked %s (%s), %s. Evidence `%s`.\n", stamp(r.Revocation.RevokedAt), orNone(r.Revocation.Reason), r.Revocation.Basis, r.Revocation.EvidenceID)
	}

	fmt.Fprintf(&b, "\n## Audit references\n\n")
	if len(r.Audit) == 0 {
		fmt.Fprintf(&b, "No audit entry names this certificate.\n")
	}
	for _, a := range r.Audit {
		fmt.Fprintf(&b, "- #%d %s at %s, event %s, chain hash %s.\n", a.Sequence, a.Type, stamp(a.At), a.EventID, a.Hash)
	}
	return b.String()
}

func list(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(none)"
	}
	return value
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func day(t *time.Time) string {
	if t == nil {
		return "(unknown)"
	}
	return t.UTC().Format(time.RFC3339)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
