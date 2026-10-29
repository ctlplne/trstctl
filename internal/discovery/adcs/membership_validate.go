// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/go-ldap/ldap/v3"
)

// validateMembershipInventory re-derives every reported member from the signed
// raw link evidence. A relay's summary/positive-control boolean is not proof.
func validateMembershipInventory(intent InventoryIntent, inventory Inventory) error {
	total := 0
	for _, template := range inventory.Templates {
		acl := template.EnrollmentACL
		if acl != nil {
			if acl.UnassessedACEs < 0 || acl.UnassessedACEs > maxACEs {
				return errors.New("adcs: invalid unassessed ACE count")
			}
			for _, values := range [][]string{acl.Allowed, acl.Denied} {
				if err := validateMembershipSIDs(values); err != nil {
					return err
				}
			}
			if !sameStrings(acl.DirectPrincipals(), template.EnrollmentPrincipals) {
				return errors.New("adcs: direct enrollment trustees differ from ACL evidence")
			}
		}
		evidence := template.EnrollmentMembership
		if !intent.NestedGroupsEnabled {
			if evidence != nil {
				return errors.New("adcs: undeclared nested enrollment evidence")
			}
			continue
		}
		if evidence == nil {
			return errors.New("adcs: nested command omitted membership completeness")
		}
		raw, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		total += len(raw)
		if total > MaxMembershipEvidenceBytes {
			return errors.New("adcs: membership evidence exceeds its total report bound")
		}
		if evidence.DomainDN != intent.MembershipDomainDN || evidence.MatchingRule != InChainMatchingRule || evidence.ObservedAt.IsZero() || !sameStrings(evidence.Limitations, membershipLimitations()) {
			return errors.New("adcs: membership scope, time or limitations are invalid")
		}
		if evidence.State != "complete" && evidence.State != "incomplete" {
			return errors.New("adcs: unknown membership completeness state")
		}
		if evidence.BudgetExceeded {
			if evidence.State != "incomplete" || len(evidence.Trustees) != 0 || len(evidence.Members) != 0 {
				return errors.New("adcs: budget-limited evidence claims members")
			}
			continue
		}
		if acl == nil {
			if evidence.State != "incomplete" || len(evidence.Trustees) != 0 || len(evidence.Members) != 0 {
				return errors.New("adcs: membership invented an unreadable ACL")
			}
			continue
		}
		want := membershipUnique(append(append([]string(nil), acl.Allowed...), acl.Denied...))
		if len(want) != len(evidence.Trustees) {
			return errors.New("adcs: membership omitted or invented ACL trustees")
		}
		complete := acl.UnassessedACEs == 0
		for index, trustee := range evidence.Trustees {
			if trustee.SID != want[index] {
				return errors.New("adcs: membership trustee coverage is not canonical")
			}
			if err := validateEnrollmentTrustee(intent.MembershipDomainDN, trustee); err != nil {
				return err
			}
			if trustee.State != "complete" {
				complete = false
			}
		}
		members, pathsComplete := deriveEnrollmentMembers(*acl, evidence.Trustees)
		complete = complete && pathsComplete
		if (evidence.State == "complete") != complete {
			return errors.New("adcs: membership completeness differs from its raw evidence")
		}
		if !complete {
			if len(evidence.Members) != 0 {
				return errors.New("adcs: incomplete membership claims verified members")
			}
			continue
		}
		// Treat nil and [] equally for an empty member set, but preserve exact paths,
		// ordering and trustee attribution for every nonempty result.
		if len(members) == 0 && len(evidence.Members) == 0 {
			continue
		}
		expected, _ := json.Marshal(members)
		actual, _ := json.Marshal(evidence.Members)
		if !bytes.Equal(expected, actual) {
			return errors.New("adcs: enrollment members do not match reconstructed security-group paths")
		}
	}
	return nil
}
func validateMembershipSIDs(values []string) error {
	if len(values) > maxPrincipals {
		return errors.New("adcs: membership SID count exceeds its bound")
	}
	previous := ""
	for _, sid := range values {
		if err := validateCanonicalSIDText(sid); err != nil {
			return err
		}
		if sid <= previous {
			return errors.New("adcs: membership SIDs are not unique and sorted")
		}
		previous = sid
	}
	return nil
}
func validateEnrollmentTrustee(domain string, trustee EnrollmentTrustee) error {
	switch trustee.State {
	case "complete", "unresolved", "read_failed", "invalid_identity", "non_security_group", "membership_unconfirmed", "incomplete_search", "incomplete_attributes", "ambiguous_identity", "matching_rule_unconfirmed":
	default:
		return errors.New("adcs: unknown trustee evidence state")
	}
	if len(trustee.Nodes) > MaxMembersPerTrustee+1 || len(trustee.DirectMemberDNs) > MaxMembersPerTrustee {
		return errors.New("adcs: trustee evidence exceeds its node bound")
	}
	base, err := membershipDomain(domain)
	if err != nil {
		return err
	}
	validDN := func(raw string) bool {
		parsed, err := ldap.ParseDN(raw)
		return err == nil && len(raw) <= maxIntentTextBytes && base.AncestorOfFold(parsed)
	}
	if trustee.DN != "" && !validDN(trustee.DN) {
		return errors.New("adcs: trustee DN escapes the explicit domain")
	}
	byDN := map[string]MembershipNode{}
	sids := map[string]bool{}
	for _, node := range trustee.Nodes {
		if !validDN(node.DN) || validateCanonicalSIDText(node.SID) != nil {
			return errors.New("adcs: invalid membership node identity")
		}
		key := foldMembershipDN(node.DN)
		if _, ok := byDN[key]; ok || sids[node.SID] {
			return errors.New("adcs: duplicate membership node identity")
		}
		byDN[key] = node
		sids[node.SID] = true
		if node.Kind != "group" && node.Kind != "user" && node.Kind != "computer" {
			return errors.New("adcs: unassessed membership object type")
		}
		if node.Kind != "group" && node.SecurityGroup {
			return errors.New("adcs: non-group claims a security-group token")
		}
		if len(node.Parents) > 64 {
			return errors.New("adcs: membership parent count exceeds its bound")
		}
		for _, parent := range node.Parents {
			if !validDN(parent) {
				return errors.New("adcs: membership parent escapes the explicit domain")
			}
		}
	}
	if trustee.State != "complete" {
		if trustee.PositiveControl {
			return errors.New("adcs: incomplete trustee claims a positive control")
		}
		return nil
	}
	root, ok := byDN[foldMembershipDN(trustee.DN)]
	if !ok || root.SID != trustee.SID {
		return errors.New("adcs: complete trustee has no unique resolved identity")
	}
	if root.Kind != "group" {
		if len(trustee.Nodes) != 1 || trustee.PositiveControl || len(trustee.DirectMemberDNs) != 0 {
			return errors.New("adcs: direct member claims group expansion")
		}
		return nil
	}
	if !root.SecurityGroup || !trustee.PositiveControl || len(trustee.DirectMemberDNs) == 0 {
		return errors.New("adcs: complete group lacks an observed positive matching-rule control")
	}
	seen := map[string]bool{}
	for _, dn := range trustee.DirectMemberDNs {
		key := foldMembershipDN(dn)
		node, ok := byDN[key]
		if !validDN(dn) || !ok || seen[key] {
			return errors.New("adcs: direct positive-control member is absent or ambiguous")
		}
		seen[key] = true
		linked := false
		for _, parent := range node.Parents {
			if foldMembershipDN(parent) == foldMembershipDN(root.DN) {
				linked = true
			}
		}
		if !linked {
			return errors.New("adcs: positive-control member has no observed link to its trustee")
		}
	}
	return nil
}
