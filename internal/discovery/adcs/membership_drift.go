// SPDX-License-Identifier: BUSL-1.1
package adcs

import "strings"

// Compare confirmed link sets separately from DACL trustee changes. A refused
// or partial read cannot turn disappearance of evidence into hardening.
func compareEnrollmentMembership(before, after Template) []TemplateChange {
	old, now := before.EnrollmentMembership, after.EnrollmentMembership
	if old == nil && now == nil {
		return nil
	}
	state := func(e *EnrollmentMembership) string {
		if e == nil {
			return "not_requested"
		}
		return e.State
	}
	if state(old) != state(now) {
		return []TemplateChange{{Template: after.Name, Direction: DriftNeutral, Change: "Nested enrollment read coverage changed; this is not proof of an authorization change.", Attribute: "nested enrollment evidence completeness", Before: state(old), After: state(now)}}
	}
	if old == nil || now == nil || old.State != "complete" || now.State != "complete" {
		return nil
	}
	identities := func(e *EnrollmentMembership) []string {
		var sids []string
		for _, member := range e.Members {
			sids = append(sids, member.SID)
		}
		return membershipUnique(sids)
	}
	previous, current := identities(old), identities(now)
	if sameStrings(previous, current) {
		return nil
	}
	direction := DriftBetter
	if len(notIn(current, previous)) > 0 {
		direction = DriftWorse
	}
	return []TemplateChange{{Template: after.Name, Direction: direction, Change: "The observed users or computers with an unopposed security-group enrollment path changed. Full Windows authorization remains unassessed.", Attribute: "observed nested enrollment members", Before: strings.Join(previous, ", "), After: strings.Join(current, ", ")}}
}
