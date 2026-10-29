// SPDX-License-Identifier: BUSL-1.1
package adcs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/discovery/adcs"
)

const membershipDomainDN = "DC=corp,DC=example"
const membershipOuterSID = "S-1-5-21-111-222-333-1101"
const membershipInnerSID = "S-1-5-21-111-222-333-1102"
const membershipUserSID = "S-1-5-21-111-222-333-1103"
const membershipOuterDN = "CN=Enrollment Outer,OU=Groups," + membershipDomainDN
const membershipInnerDN = "CN=Enrollment Inner,OU=Groups," + membershipDomainDN
const membershipUserDN = "CN=Nested User,OU=People," + membershipDomainDN

type membershipDirectory struct {
	base        *fakeDirectory
	unsupported bool
	requests    []adcs.SearchRequest
}

func binarySIDAssertion(sid string) string {
	var out strings.Builder
	for _, value := range sidBytes(sid) {
		fmt.Fprintf(&out, "\\%02x", value)
	}
	return out.String()
}
func membershipObject(dn, sid, kind string, parents, members []string) adcs.Entry {
	attrs := map[string][]string{"objectClass": {kind}, "memberOf": parents, "member": members}
	if kind == "group" {
		attrs["groupType"] = []string{"-2147483646"}
	}
	return adcs.Entry{DN: dn, Attributes: attrs, BinaryAttributes: map[string][][]byte{"objectSid": {sidBytes(sid)}}}
}
func (d *membershipDirectory) Search(ctx context.Context, request adcs.SearchRequest) ([]adcs.Entry, error) {
	d.requests = append(d.requests, request)
	if strings.Contains(request.BaseDN, adcs.PublicKeyServicesRDN) {
		return d.base.Search(ctx, request)
	}
	if request.BaseDN != membershipDomainDN {
		return nil, fmt.Errorf("membership escaped its explicit domain scope: %s", request.BaseDN)
	}
	if request.MaxEntries <= 0 || len(request.Attributes) == 0 {
		return nil, fmt.Errorf("membership search lost bounds or attribute projection")
	}
	outer := membershipObject(membershipOuterDN, membershipOuterSID, "group", nil, []string{membershipInnerDN})
	inner := membershipObject(membershipInnerDN, membershipInnerSID, "group", []string{membershipOuterDN}, []string{membershipUserDN})
	user := membershipObject(membershipUserDN, membershipUserSID, "user", []string{membershipInnerDN}, nil)
	if strings.Contains(strings.ToLower(request.Filter), "objectsid=") {
		if strings.Contains(strings.ToLower(request.Filter), binarySIDAssertion(membershipOuterSID)) {
			return []adcs.Entry{outer}, nil
		}
		if strings.Contains(strings.ToLower(request.Filter), binarySIDAssertion(membershipInnerSID)) {
			return []adcs.Entry{inner}, nil
		}
		if strings.Contains(strings.ToLower(request.Filter), binarySIDAssertion(membershipUserSID)) {
			return []adcs.Entry{user}, nil
		}
		return nil, nil
	}
	if strings.Contains(request.Filter, "1.2.840.113556.1.4.1941") {
		if d.unsupported {
			return nil, nil
		}
		return []adcs.Entry{inner, user}, nil
	}
	return nil, fmt.Errorf("unexpected unbounded/different membership query: %s", request.Filter)
}
func nestedDirectory(deny bool) *membershipDirectory {
	aces := [][]byte{allowACE(0x100, sidBytes(membershipOuterSID))}
	if deny {
		ace := allowACE(0x100, sidBytes(membershipUserSID))
		ace[0] = 0x01
		aces = append(aces, ace)
	}
	base := directoryWith([]adcs.Entry{{DN: "CN=Nested," + configDN, Attributes: map[string][]string{"cn": {"Nested"}, "pKIExtendedKeyUsage": {adcs.EKUClientAuth}}, BinaryAttributes: map[string][][]byte{"nTSecurityDescriptor": {securityDescriptor(aces...)}}}}, nil)
	return &membershipDirectory{base: base}
}
func TestNestedEnrollmentMemberRequiresAnObservedSecurityGroupPath(t *testing.T) {
	directory := nestedDirectory(false)
	inventory, err := adcs.CollectWithMembership(t.Context(), directory, configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	evidence := inventory.Templates[0].EnrollmentMembership
	if evidence == nil || evidence.State != "complete" {
		t.Fatalf("nested membership stayed unassessed: %+v", evidence)
	}
	found := false
	for _, member := range evidence.Members {
		if member.SID == membershipUserSID && member.DN == membershipUserDN {
			found = true
		}
	}
	if !found {
		t.Fatalf("user who inherits enrollment through inner -> outer group was omitted: %+v", evidence)
	}
	sawInChain := false
	for _, query := range directory.requests {
		if strings.Contains(query.Filter, "1.2.840.113556.1.4.1941") {
			sawInChain = true
		}
	}
	if !sawInChain {
		t.Fatal("nested expansion did not use the read-only LDAP matching rule")
	}
}
func TestNestedEnrollmentCannotUndoAnExplicitUserDeny(t *testing.T) {
	inventory, err := adcs.CollectWithMembership(t.Context(), nestedDirectory(true), configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	evidence := inventory.Templates[0].EnrollmentMembership
	if evidence == nil {
		t.Fatal("denial coverage was dropped")
	}
	for _, member := range evidence.Members {
		if member.SID == membershipUserSID {
			t.Fatal("nested allow reintroduced a directly denied user")
		}
	}
}
func TestEmptyUnsupportedInChainResultDoesNotBecomeVerifiedAbsence(t *testing.T) {
	directory := nestedDirectory(false)
	directory.unsupported = true
	inventory, err := adcs.CollectWithMembership(t.Context(), directory, configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	evidence := inventory.Templates[0].EnrollmentMembership
	if evidence == nil || evidence.State != "incomplete" || len(evidence.Members) != 0 {
		t.Fatalf("unconfirmed matching rule became complete empty access: %+v", evidence)
	}
}

func TestNestedReportRecomputesPathsAndPositiveControl(t *testing.T) {
	inv, err := adcs.CollectWithMembership(t.Context(), nestedDirectory(false), configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	intent := adcs.InventoryIntent{ID: "run", SourceID: "source", JobKind: adcs.NestedGroupsJobKind, Execution: adcs.ExecutionRelay, RequiredAgentRole: adcs.RequiredRoleNetwork, NestedGroupsEnabled: true, MembershipDomainDN: membershipDomainDN}
	good := adcs.InventoryReport{Status: "succeeded", Inventory: inv, Findings: adcs.Findings(inv)}
	if err := adcs.ValidateInventoryReport(intent, good); err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*adcs.InventoryReport){
		"invented path": func(r *adcs.InventoryReport) {
			r.Inventory.Templates[0].EnrollmentMembership.Members[0].Path = []string{membershipUserDN, membershipOuterDN}
		},
		"missing positive control": func(r *adcs.InventoryReport) {
			r.Inventory.Templates[0].EnrollmentMembership.Trustees[0].DirectMemberDNs = nil
		},
		"foreign domain": func(r *adcs.InventoryReport) {
			r.Inventory.Templates[0].EnrollmentMembership.Trustees[0].Nodes[0].DN = "CN=Foreign,DC=other"
		},
		"omitted trustee": func(r *adcs.InventoryReport) { r.Inventory.Templates[0].EnrollmentMembership.Trustees = nil },
		"invented member": func(r *adcs.InventoryReport) {
			r.Inventory.Templates[0].EnrollmentMembership.Members[0].SID = "S-1-5-21-9-9-9-999"
		},
		"unknown state": func(r *adcs.InventoryReport) { r.Inventory.Templates[0].EnrollmentMembership.State = "verified" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(good)
			var r adcs.InventoryReport
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			tamper(&r)
			if err := adcs.ValidateInventoryReport(intent, r); err == nil {
				t.Fatal("tampered nested report accepted")
			}
		})
	}
	intent.NestedGroupsEnabled = false
	intent.JobKind = adcs.JobKind
	if err := adcs.ValidateInventoryReport(intent, good); err == nil {
		t.Fatal("ordinary inventory accepted undeclared nested evidence")
	}
}

type membershipTransformDirectory struct {
	base      adcs.Searcher
	transform func(adcs.SearchRequest, []adcs.Entry) []adcs.Entry
}

func (d membershipTransformDirectory) Search(ctx context.Context, request adcs.SearchRequest) ([]adcs.Entry, error) {
	entries, err := d.base.Search(ctx, request)
	if err != nil {
		return nil, err
	}
	if request.BaseDN == membershipDomainDN {
		return d.transform(request, entries), nil
	}
	return entries, nil
}

func TestNestedCollectionRefusesIncompleteOrNonSecurityLinks(t *testing.T) {
	cases := map[string]func(adcs.SearchRequest, []adcs.Entry) []adcs.Entry{
		"distribution group": func(_ adcs.SearchRequest, e []adcs.Entry) []adcs.Entry {
			for i := range e {
				if e[i].DN == membershipInnerDN {
					e[i].Attributes["groupType"] = []string{"2"}
				}
			}
			return e
		},
		"missing direct parent": func(_ adcs.SearchRequest, e []adcs.Entry) []adcs.Entry {
			for i := range e {
				if e[i].DN == membershipUserDN {
					delete(e[i].Attributes, "memberOf")
				}
			}
			return e
		},
		"ranged group": func(_ adcs.SearchRequest, e []adcs.Entry) []adcs.Entry {
			for i := range e {
				if e[i].DN == membershipOuterDN {
					e[i].Attributes["member;range=0-0"] = e[i].Attributes["member"]
					delete(e[i].Attributes, "member")
				}
			}
			return e
		},
		"unconfirmed direct control": func(_ adcs.SearchRequest, e []adcs.Entry) []adcs.Entry {
			for i := range e {
				if e[i].DN == membershipOuterDN {
					e[i].Attributes["member"] = []string{"CN=Missing," + membershipDomainDN}
				}
			}
			return e
		},
		"oversize attributes": func(request adcs.SearchRequest, e []adcs.Entry) []adcs.Entry {
			if strings.Contains(request.Filter, adcs.InChainMatchingRule) {
				e[0].Attributes["memberOf"] = []string{strings.Repeat("X", adcs.MaxMembershipTextBytes+1)}
			}
			return e
		},
	}
	for name, transform := range cases {
		t.Run(name, func(t *testing.T) {
			inv, err := adcs.CollectWithMembership(t.Context(), membershipTransformDirectory{base: nestedDirectory(false), transform: transform}, configDN, membershipDomainDN)
			if err != nil {
				t.Fatal(err)
			}
			evidence := inv.Templates[0].EnrollmentMembership
			if evidence.State != "incomplete" || len(evidence.Members) != 0 {
				t.Fatalf("unconfirmed link became enrollment access: %+v", evidence)
			}
		})
	}
}
func TestFreshNestedReadDropsARemovedMember(t *testing.T) {
	directory := membershipTransformDirectory{base: nestedDirectory(false), transform: func(request adcs.SearchRequest, entries []adcs.Entry) []adcs.Entry {
		if !strings.Contains(request.Filter, adcs.InChainMatchingRule) {
			return entries
		}
		out := entries[:0]
		for _, entry := range entries {
			if entry.DN != membershipUserDN {
				out = append(out, entry)
			}
		}
		return out
	}}
	inv, err := adcs.CollectWithMembership(t.Context(), directory, configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	evidence := inv.Templates[0].EnrollmentMembership
	if evidence.State != "complete" || len(evidence.Members) != 0 {
		t.Fatalf("fresh read retained stale user: %+v", evidence)
	}
}

func TestNestedDenyGroupSuppressesItsTransitiveUser(t *testing.T) {
	directory := nestedDirectory(false)
	deny := allowACE(0x100, sidBytes(membershipInnerSID))
	deny[0] = 0x01
	for _, entries := range directory.base.byBase {
		for i := range entries {
			if entries[i].BinaryAttributes != nil {
				entries[i].BinaryAttributes["nTSecurityDescriptor"] = [][]byte{securityDescriptor(allowACE(0x100, sidBytes(membershipOuterSID)), deny)}
			}
		}
	}
	inv, err := adcs.CollectWithMembership(t.Context(), directory, configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	evidence := inv.Templates[0].EnrollmentMembership
	if evidence.State != "complete" || len(evidence.Members) != 0 {
		t.Fatalf("nested deny failed to remove the user: %+v", evidence)
	}
}

type wideMembershipDirectory struct{ base *fakeDirectory }

func (d wideMembershipDirectory) Search(ctx context.Context, request adcs.SearchRequest) ([]adcs.Entry, error) {
	if request.BaseDN != membershipDomainDN {
		return d.base.Search(ctx, request)
	}
	var users []adcs.Entry
	var direct []string
	for index := range 100 {
		dn := fmt.Sprintf("CN=User-%03d-%s,OU=People,%s", index, strings.Repeat("n", 80), membershipDomainDN)
		direct = append(direct, dn)
		users = append(users, membershipObject(dn, fmt.Sprintf("S-1-5-21-111-222-333-%d", 2000+index), "user", []string{membershipOuterDN}, nil))
	}
	if strings.Contains(request.Filter, adcs.InChainMatchingRule) {
		return users, nil
	}
	return []adcs.Entry{membershipObject(membershipOuterDN, membershipOuterSID, "group", nil, direct)}, nil
}
func TestNestedReportBudgetIncludesCachedEvidenceAcrossTemplates(t *testing.T) {
	var templates []adcs.Entry
	for index := range 12 {
		templates = append(templates, adcs.Entry{DN: fmt.Sprintf("CN=Template%d,%s", index, configDN), Attributes: map[string][]string{"cn": {fmt.Sprintf("Template%d", index)}}, BinaryAttributes: map[string][][]byte{"nTSecurityDescriptor": {securityDescriptor(allowACE(0x100, sidBytes(membershipOuterSID)))}}})
	}
	inventory, err := adcs.CollectWithMembership(t.Context(), wideMembershipDirectory{base: directoryWith(templates, nil)}, configDN, membershipDomainDN)
	if err != nil {
		t.Fatal(err)
	}
	bytes := 0
	truncated := 0
	for _, template := range inventory.Templates {
		e := template.EnrollmentMembership
		raw, _ := json.Marshal(e)
		bytes += len(raw)
		if e.BudgetExceeded {
			truncated++
			if e.State != "incomplete" || len(e.Members) != 0 {
				t.Fatal("budget-limited evidence claimed complete access")
			}
		}
	}
	if truncated == 0 || bytes > adcs.MaxMembershipEvidenceBytes {
		t.Fatalf("cached duplicate evidence escaped global report budget: truncated=%d bytes=%d", truncated, bytes)
	}
	intent := adcs.InventoryIntent{ID: "run", SourceID: "source", JobKind: adcs.NestedGroupsJobKind, Execution: adcs.ExecutionRelay, RequiredAgentRole: adcs.RequiredRoleNetwork, NestedGroupsEnabled: true, MembershipDomainDN: membershipDomainDN}
	if err := adcs.ValidateInventoryReport(intent, adcs.InventoryReport{Status: "succeeded", Inventory: inventory, Findings: adcs.Findings(inventory)}); err != nil {
		t.Fatal(err)
	}
}
