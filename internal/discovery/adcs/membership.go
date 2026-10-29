// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"sort"
	"strconv"
	"strings"
	"time"
)

const InChainMatchingRule = "1.2.840.113556.1.4.1941"
const MaxMembershipQueries = 256
const MaxMembershipNodes = 4096
const MaxMembersPerTrustee = 1024
const MaxMembershipTextBytes = 256 << 10
const MaxMembershipDepth = 16
const MaxMembershipEvidenceBytes = 384 << 10

// EnrollmentMembership is account-visible security-group link evidence. A
// complete read is deliberately not a Windows token/AccessCheck assertion.
type EnrollmentMembership struct {
	BudgetExceeded bool                `json:"budget_exceeded,omitempty"`
	State          string              `json:"state"`
	DomainDN       string              `json:"domain_dn"`
	MatchingRule   string              `json:"matching_rule"`
	ObservedAt     time.Time           `json:"observed_at"`
	Trustees       []EnrollmentTrustee `json:"trustees"`
	Members        []EnrollmentMember  `json:"members"`
	Limitations    []string            `json:"limitations"`
}
type EnrollmentMember struct {
	SID         string   `json:"sid"`
	DN          string   `json:"dn"`
	Kind        string   `json:"kind"`
	ViaTrustees []string `json:"via_trustees"`
	Path        []string `json:"path"`
}
type MembershipNode struct {
	SID           string   `json:"sid"`
	DN            string   `json:"dn"`
	Kind          string   `json:"kind"`
	Parents       []string `json:"parents,omitempty"`
	SecurityGroup bool     `json:"security_group,omitempty"`
}
type EnrollmentTrustee struct {
	SID             string           `json:"sid"`
	DN              string           `json:"dn,omitempty"`
	State           string           `json:"state"`
	DirectMemberDNs []string         `json:"direct_member_dns,omitempty"`
	PositiveControl bool             `json:"positive_control"`
	Nodes           []MembershipNode `json:"nodes,omitempty"`
}
type membershipReader struct {
	directory                 Searcher
	domain                    string
	base                      *ldap.DN
	queries, nodes, textBytes int
	cache                     map[string]EnrollmentTrustee
}

// CollectWithMembership adds only explicitly scoped, bounded read-only queries.
// Collect without this call retains the default direct-trustee inventory.
func CollectWithMembership(ctx context.Context, directory Searcher, configurationDN, domainDN string) (Inventory, error) {
	base, err := membershipDomain(domainDN)
	if err != nil {
		return Inventory{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	inventory, err := Collect(bounded, directory, configurationDN)
	if err != nil {
		return Inventory{}, err
	}
	reader := membershipReader{directory: directory, domain: domainDN, base: base, cache: map[string]EnrollmentTrustee{}}
	observedAt := time.Now().UTC()
	evidenceBytes := 0
	for index := range inventory.Templates {
		template := &inventory.Templates[index]
		evidence := &EnrollmentMembership{State: "complete", DomainDN: domainDN, MatchingRule: InChainMatchingRule, ObservedAt: observedAt, Members: []EnrollmentMember{}, Trustees: []EnrollmentTrustee{}, Limitations: membershipLimitations()}
		if template.EnrollmentACL == nil {
			evidence.State = "incomplete"
			raw, _ := json.Marshal(evidence)
			evidenceBytes += len(raw)
			if evidenceBytes > MaxMembershipEvidenceBytes {
				return Inventory{}, errors.New("adcs: nested membership report budget exhausted")
			}
			template.EnrollmentMembership = evidence
			continue
		}
		all := append(append([]string(nil), template.EnrollmentACL.Allowed...), template.EnrollmentACL.Denied...)
		all = membershipUnique(all)
		for _, sid := range all {
			read := reader.trustee(bounded, sid)
			evidence.Trustees = append(evidence.Trustees, read)
			if read.State != "complete" {
				evidence.State = "incomplete"
			}
		}
		if template.EnrollmentACL.UnassessedACEs != 0 {
			evidence.State = "incomplete"
		}
		members, pathsComplete := deriveEnrollmentMembers(*template.EnrollmentACL, evidence.Trustees)
		if !pathsComplete {
			evidence.State = "incomplete"
		}
		if evidence.State == "complete" {
			evidence.Members = members
		}
		raw, err := json.Marshal(evidence)
		if err != nil {
			return Inventory{}, err
		}
		if len(raw)+evidenceBytes > MaxMembershipEvidenceBytes {
			evidence.State, evidence.BudgetExceeded = "incomplete", true
			evidence.Trustees, evidence.Members = []EnrollmentTrustee{}, []EnrollmentMember{}
			raw, err = json.Marshal(evidence)
			if err != nil || len(raw)+evidenceBytes > MaxMembershipEvidenceBytes {
				return Inventory{}, errors.New("adcs: nested membership report budget exhausted")
			}
		}
		evidenceBytes += len(raw)
		template.EnrollmentMembership = evidence
	}
	return inventory, nil
}
func (r *membershipReader) search(ctx context.Context, filter string, max int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.queries >= MaxMembershipQueries || r.nodes >= MaxMembershipNodes || r.textBytes >= MaxMembershipTextBytes {
		return nil, errors.New("membership read budget exhausted")
	}
	r.queries++
	entries, err := r.directory.Search(ctx, SearchRequest{BaseDN: r.domain, Filter: filter, Attributes: []string{"objectSid", "objectClass", "groupType", "member", "memberOf"}, MaxEntries: max, DomainScope: true})
	if err != nil {
		return nil, err
	}
	if len(entries) > max || len(entries)+r.nodes > MaxMembershipNodes {
		return nil, errors.New("membership result count exceeds its bound")
	}
	r.nodes += len(entries)
	for _, entry := range entries {
		r.textBytes += len(entry.DN)
		for key, values := range entry.Attributes {
			r.textBytes += len(key)
			for _, value := range values {
				r.textBytes += len(value)
			}
		}
		for key, values := range entry.BinaryAttributes {
			r.textBytes += len(key)
			for _, value := range values {
				r.textBytes += len(value)
			}
		}
		if r.textBytes > MaxMembershipTextBytes {
			return nil, errors.New("membership attributes exceed their total bound")
		}
	}
	return entries, nil
}
func (r *membershipReader) trustee(ctx context.Context, sid string) EnrollmentTrustee {
	if cached, ok := r.cache[sid]; ok {
		return cached
	}
	out := r.readTrustee(ctx, sid)
	r.cache[sid] = out
	return out
}
func (r *membershipReader) readTrustee(ctx context.Context, sid string) EnrollmentTrustee {
	out := EnrollmentTrustee{SID: sid, State: "unresolved"}
	raw, err := membershipSIDBytes(sid)
	if err != nil {
		return out
	}
	entries, err := r.search(ctx, "(objectSid="+binaryAssertion(raw)+")", 2)
	if err != nil {
		out.State = "read_failed"
		return out
	}
	if len(entries) != 1 {
		return out
	}
	root, err := r.node(entries[0])
	if err != nil || root.SID != sid {
		out.State = "invalid_identity"
		return out
	}
	out.DN = root.DN
	out.Nodes = []MembershipNode{root}
	if root.Kind != "group" {
		out.State = "complete"
		return out
	}
	if !root.SecurityGroup {
		out.State = "non_security_group"
		return out
	}
	direct := membershipAttribute(entries[0], "member")
	if len(direct) == 0 || len(direct) > MaxMembersPerTrustee || hasRangedMembership(entries[0]) {
		out.State = "membership_unconfirmed"
		return out
	}
	matches, err := r.search(ctx, "(memberOf:"+InChainMatchingRule+":="+ldap.EscapeFilter(root.DN)+")", MaxMembersPerTrustee+1)
	if err != nil || len(matches) > MaxMembersPerTrustee {
		out.State = "incomplete_search"
		return out
	}
	out.DirectMemberDNs = membershipUnique(direct)
	byDN := map[string]bool{}
	seenSID := map[string]string{root.SID: root.DN}
	for _, entry := range matches {
		node, err := r.node(entry)
		if err != nil || hasRangedMembership(entry) {
			out.State = "incomplete_attributes"
			return out
		}
		if prior, ok := seenSID[node.SID]; ok {
			if prior != node.DN {
				out.State = "ambiguous_identity"
				return out
			}
			continue
		}
		seenSID[node.SID] = node.DN
		out.Nodes = append(out.Nodes, node)
		byDN[foldMembershipDN(node.DN)] = true
	}
	// A server that treats an unknown extensible match as empty cannot turn
	// that into a verified empty group: check its known direct links positively.
	for _, dn := range direct {
		if !byDN[foldMembershipDN(dn)] {
			out.State = "matching_rule_unconfirmed"
			return out
		}
	}
	out.PositiveControl = true
	out.State = "complete"
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].SID < out.Nodes[j].SID })
	return out
}
func (r *membershipReader) node(entry Entry) (MembershipNode, error) {
	parsed, err := ldap.ParseDN(entry.DN)
	if err != nil || !r.base.AncestorOfFold(parsed) || len(entry.DN) > maxIntentTextBytes {
		return MembershipNode{}, errors.New("member DN is outside the declared domain")
	}
	values := membershipBinaryAttribute(entry, "objectSid")
	if len(values) != 1 {
		return MembershipNode{}, errors.New("member has no unique SID")
	}
	sid, err := canonicalSID(values[0])
	if err != nil {
		return MembershipNode{}, err
	}
	node := MembershipNode{SID: sid, DN: entry.DN}
	classes := membershipAttribute(entry, "objectClass")
	for _, class := range classes {
		switch strings.ToLower(class) {
		case "group":
			node.Kind = "group"
		case "computer":
			node.Kind = "computer"
		case "user":
			if node.Kind == "" {
				node.Kind = "user"
			}
		}
	}
	if node.Kind == "" {
		return MembershipNode{}, errors.New("membership object type is unassessed")
	}
	if node.Kind == "group" {
		values := membershipAttribute(entry, "groupType")
		if len(values) != 1 {
			return MembershipNode{}, errors.New("group security type is absent")
		}
		value, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil || value < -2147483648 || value > 4294967295 {
			return MembershipNode{}, errors.New("group security type is invalid")
		}
		node.SecurityGroup = uint64(value)&0x80000000 != 0 // #nosec G115 -- the signed LDAP groupType bitfield is range-checked as signed/unsigned 32-bit above (CWE-190).
	}
	node.Parents = membershipAttribute(entry, "memberOf")
	if len(node.Parents) > 64 {
		return MembershipNode{}, errors.New("membership parent count exceeds its bound")
	}
	for _, parent := range node.Parents {
		if len(parent) > maxIntentTextBytes {
			return MembershipNode{}, errors.New("parent DN exceeds its bound")
		}
		if parsed, err := ldap.ParseDN(parent); err != nil || !r.base.AncestorOfFold(parsed) {
			return MembershipNode{}, errors.New("membership parent escapes the declared domain")
		}
	}
	node.Parents = membershipUnique(node.Parents)
	return node, nil
}
func membershipAttribute(entry Entry, name string) []string {
	for key, values := range entry.Attributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}
func membershipBinaryAttribute(entry Entry, name string) [][]byte {
	for key, values := range entry.BinaryAttributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}
func hasRangedMembership(entry Entry) bool {
	for key := range entry.Attributes {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "member;range=") || strings.HasPrefix(lower, "memberof;range=") {
			return true
		}
	}
	return false
}
func foldMembershipDN(raw string) string {
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.String())
}
func binaryAssertion(raw []byte) string {
	var out strings.Builder
	for _, value := range raw {
		fmt.Fprintf(&out, "\\%02x", value)
	}
	return out.String()
}
func membershipSIDBytes(raw string) ([]byte, error) {
	if err := validateCanonicalSIDText(raw); err != nil {
		return nil, err
	}
	fields := strings.Split(raw, "-")
	if len(fields) < 3 || len(fields) > 18 {
		return nil, errors.New("SID subauthority count exceeds its bound")
	}
	authority, err := strconv.ParseUint(fields[2], 10, 48)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8+4*(len(fields)-3))
	out[0] = 1
	out[1] = byte(len(fields) - 3) // #nosec G115 -- the checked 3..18 field count makes this 0..15 (CWE-190).
	for index := 7; index >= 2; index-- {
		out[index] = byte(authority & 0xff)
		authority >>= 8
	}
	for index, value := range fields[3:] {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(out[8+index*4:], uint32(n))
	} // #nosec G115 -- ParseUint's 32-bit bound proves the conversion (CWE-190).
	return out, nil
}

func membershipUnique(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func membershipDomain(domainDN string) (*ldap.DN, error) {
	base, err := ldap.ParseDN(domainDN)
	if err != nil || len(base.RDNs) == 0 || len(domainDN) > maxIntentTextBytes {
		return nil, errors.New("adcs: provide an explicit valid domain naming context for membership reads")
	}
	for _, rdn := range base.RDNs {
		if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, "DC") {
			return nil, errors.New("adcs: membership scope must be a domain naming context, not an OU or Configuration partition")
		}
	}
	return base, nil
}

func membershipLimitations() []string {
	return []string{"account_visible_links_only", "conditional_aces_unassessed", "primary_groups_unassessed", "sid_history_unassessed", "cross_forest_tokens_unassessed", "windows_access_check_unassessed"}
}
