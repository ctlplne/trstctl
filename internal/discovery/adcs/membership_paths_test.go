// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"testing/quick"
	"time"
)

func TestMembershipPathBoundsAndCycles(t *testing.T) {
	for _, length := range []int{MaxMembershipDepth, MaxMembershipDepth + 1} {
		nodes := map[string]MembershipNode{}
		for index := range length {
			dn := fmt.Sprintf("CN=g%d,DC=example", index)
			node := MembershipNode{SID: fmt.Sprintf("S-1-5-21-1-%d", 1000+index), DN: dn, Kind: "group", SecurityGroup: true}
			if index+1 < length {
				node.Parents = []string{fmt.Sprintf("CN=g%d,DC=example", index+1)}
			}
			nodes[foldMembershipDN(dn)] = node
		}
		first := foldMembershipDN("CN=g0,DC=example")
		last := foldMembershipDN(fmt.Sprintf("CN=g%d,DC=example", length-1))
		root := nodes[last]
		root.Parents = []string{nodes[first].DN}
		nodes[last] = root
		path, ok := membershipPath(nodes, first, last)
		if ok != (length <= MaxMembershipDepth) || (ok && len(path) != length) {
			t.Fatalf("path length %d accepted=%t path=%v", length, ok, path)
		}
	}
}
func TestMembershipPathRequiresSecurityGroupsAndIgnoresInputOrder(t *testing.T) {
	outer := MembershipNode{SID: "S-1-5-21-1-1001", DN: "CN=Outer,DC=example", Kind: "group", SecurityGroup: true}
	inner := MembershipNode{SID: "S-1-5-21-1-1002", DN: "CN=Inner,DC=example", Kind: "group", SecurityGroup: true, Parents: []string{outer.DN}}
	user := MembershipNode{SID: "S-1-5-21-1-1003", DN: "CN=User\\, Nested,DC=example", Kind: "user", Parents: []string{inner.DN}}
	trustee := EnrollmentTrustee{SID: outer.SID, DN: outer.DN, State: "complete", PositiveControl: true, DirectMemberDNs: []string{inner.DN}, Nodes: []MembershipNode{outer, inner, user}}
	want, ok := membersOfTrustee(trustee)
	if !ok || len(want) != 1 || len(want[0].Path) != 3 {
		t.Fatalf("escaped-DN path lost: %v %t", want, ok)
	}
	if err := quick.Check(func(seed int64) bool {
		copy := trustee
		copy.Nodes = slices.Clone(trustee.Nodes)
		rand.New(rand.NewSource(seed)).Shuffle(len(copy.Nodes), func(i, j int) { copy.Nodes[i], copy.Nodes[j] = copy.Nodes[j], copy.Nodes[i] }) // #nosec G404 -- deterministic property-test permutations, never a cryptographic choice (CWE-330).
		got, ok := membersOfTrustee(copy)
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		return ok && string(a) == string(b)
	}, nil); err != nil {
		t.Fatal(err)
	}
	trustee.Nodes[1].SecurityGroup = false
	if members, ok := membersOfTrustee(trustee); ok || len(members) != 0 {
		t.Fatal("distribution-group path was called a security-token grant")
	}
}
func FuzzEnrollmentMembershipEvidence(f *testing.F) {
	f.Add([]byte(`{"status":"succeeded","inventory":{"templates":[{"name":"Unassessed","enrollment_membership":{"state":"incomplete","domain_dn":"DC=example","matching_rule":"1.2.840.113556.1.4.1941","observed_at":"2026-10-28T00:00:00Z"}}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		var report InventoryReport
		if json.Unmarshal(raw, &report) != nil {
			return
		}
		intent := InventoryIntent{ID: "run", SourceID: "source", JobKind: NestedGroupsJobKind, Execution: ExecutionRelay, RequiredAgentRole: RequiredRoleNetwork, NestedGroupsEnabled: true, MembershipDomainDN: "DC=example"}
		_ = ValidateInventoryReport(intent, report)
	})
}
func TestMembershipDriftDoesNotCallMissingEvidenceHardening(t *testing.T) {
	makeTemplate := func(state string, members ...string) Template {
		e := &EnrollmentMembership{State: state, ObservedAt: time.Now()}
		for _, sid := range members {
			e.Members = append(e.Members, EnrollmentMember{SID: sid})
		}
		return Template{Name: "Nested", EnrollmentMembership: e}
	}
	before := []Template{makeTemplate("complete", "S-1-5-21-1-1003")}
	unreadable := DiffTemplates(before, []Template{makeTemplate("incomplete")})
	if len(unreadable.Changes) != 1 || unreadable.Changes[0].Direction != DriftNeutral {
		t.Fatalf("read failure looked like removed enrollment: %+v", unreadable)
	}
	removed := DiffTemplates(before, []Template{makeTemplate("complete")})
	if len(removed.Changes) != 1 || removed.Changes[0].Direction != DriftBetter {
		t.Fatalf("confirmed link removal missing: %+v", removed)
	}
}
