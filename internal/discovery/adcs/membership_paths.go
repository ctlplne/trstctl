// SPDX-License-Identifier: BUSL-1.1
package adcs

import "sort"

// deriveEnrollmentMembers reports only user/computer paths through observed
// security groups. It does not synthesize primary groups, SID history or tokens.
func deriveEnrollmentMembers(acl EnrollmentACL, trustees []EnrollmentTrustee) ([]EnrollmentMember, bool) {
	bySID := map[string]EnrollmentTrustee{}
	for _, trustee := range trustees {
		bySID[trustee.SID] = trustee
		if trustee.State != "complete" {
			return nil, false
		}
	}
	denied := map[string]bool{}
	for _, sid := range acl.Denied {
		denied[sid] = true
		read, ok := bySID[sid]
		if !ok {
			return nil, false
		}
		members, complete := membersOfTrustee(read)
		if !complete {
			return nil, false
		}
		for _, member := range members {
			denied[member.SID] = true
		}
	}
	allowed := map[string]EnrollmentMember{}
	for _, sid := range acl.Allowed {
		if denied[sid] {
			continue
		}
		read, ok := bySID[sid]
		if !ok {
			return nil, false
		}
		members, complete := membersOfTrustee(read)
		if !complete {
			return nil, false
		}
		for _, member := range members {
			if denied[member.SID] {
				continue
			}
			prior, seen := allowed[member.SID]
			if seen && foldMembershipDN(prior.DN) != foldMembershipDN(member.DN) {
				return nil, false
			}
			if !seen {
				prior = member
			}
			prior.ViaTrustees = append(prior.ViaTrustees, sid)
			allowed[member.SID] = prior
		}
	}
	out := make([]EnrollmentMember, 0, len(allowed))
	for _, member := range allowed {
		member.ViaTrustees = membershipUnique(member.ViaTrustees)
		out = append(out, member)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, true
}
func membersOfTrustee(trustee EnrollmentTrustee) ([]EnrollmentMember, bool) {
	if trustee.State != "complete" {
		return nil, false
	}
	nodes := map[string]MembershipNode{}
	rootKey := ""
	for _, node := range trustee.Nodes {
		key := foldMembershipDN(node.DN)
		if key == "" {
			return nil, false
		}
		nodes[key] = node
		if node.SID == trustee.SID {
			rootKey = key
		}
	}
	if rootKey == "" {
		return nil, false
	}
	root := nodes[rootKey]
	if root.Kind != "group" {
		return []EnrollmentMember{{SID: root.SID, DN: root.DN, Kind: root.Kind, Path: []string{root.DN}}}, true
	}
	if !root.SecurityGroup || !trustee.PositiveControl {
		return nil, false
	}
	var out []EnrollmentMember
	for key, node := range nodes {
		if node.Kind != "user" && node.Kind != "computer" {
			continue
		}
		path, ok := membershipPath(nodes, key, rootKey)
		if !ok {
			return nil, false
		}
		out = append(out, EnrollmentMember{SID: node.SID, DN: node.DN, Kind: node.Kind, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, true
}
func membershipPath(nodes map[string]MembershipNode, start, root string) ([]string, bool) {
	type step struct {
		key  string
		path []string
	}
	queue := []step{{key: start, path: []string{nodes[start].DN}}}
	seen := map[string]bool{start: true}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if len(next.path) > MaxMembershipDepth {
			continue
		}
		if next.key == root {
			return next.path, true
		}
		parents := append([]string(nil), nodes[next.key].Parents...)
		sort.Strings(parents)
		for _, parent := range parents {
			key := foldMembershipDN(parent)
			node, ok := nodes[key]
			if !ok || seen[key] || node.Kind != "group" || !node.SecurityGroup {
				continue
			}
			seen[key] = true
			path := append(append([]string(nil), next.path...), node.DN)
			queue = append(queue, step{key: key, path: path})
		}
	}
	return nil, false
}
