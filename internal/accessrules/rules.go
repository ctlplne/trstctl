// SPDX-License-Identifier: BUSL-1.1

// Package accessrules describes credential-free command guardrails. A relay's
// classifier emits known operation names; the matcher never receives sign-in
// material, statement text, command arguments or bound values.
package accessrules

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	Version           = 1
	MaxRules          = 32
	MaxOperations     = 32
	MaxStatementBytes = 1 << 20
	EffectBlock       = "block"
	EffectReview      = "require_approval"
)

// Rule is one template-owned guardrail. Its identifiers and operation names are
// public configuration. Revision belongs to its containing template.
type Rule struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Protocol          string   `json:"protocol"`
	Operations        []string `json:"operations"`
	Effect            string   `json:"effect"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
	ReviewTTLSeconds  int      `json:"review_ttl_seconds,omitempty"`
}

// PolicyRule contains enforcement facts only. Display names stay outside the
// frozen authority, so privacy erasure cannot change a live rule predicate.
type PolicyRule struct {
	ID                string   `json:"id"`
	Protocol          string   `json:"protocol"`
	Operations        []string `json:"operations"`
	Effect            string   `json:"effect"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
	ReviewTTLSeconds  int      `json:"review_ttl_seconds,omitempty"`
}

// Policy is the exact template revision approved for a session. Editing the
// template affects new sessions; recalling an old session ends its old policy.
type Policy struct {
	Version          int          `json:"version"`
	TemplateID       string       `json:"template_id"`
	TemplateRevision int64        `json:"template_revision"`
	Rules            []PolicyRule `json:"rules"`
}

// CanonicalRules validates and copies administrator configuration. Only protocols
// with an enforcing relay are accepted; an unsupported rule cannot look active.
func CanonicalRules(in []Rule) ([]Rule, error) {
	if len(in) > MaxRules {
		return nil, fmt.Errorf("command rules: at most %d rules per template", MaxRules)
	}
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Rule, 0, len(in))
	seen := map[string]bool{}
	for _, r := range in {
		id, err := uuid.Parse(r.ID)
		if err != nil || id == uuid.Nil {
			return nil, errors.New("command rules: every rule needs a nonzero UUID")
		}
		r.ID = id.String()
		if seen[r.ID] {
			return nil, errors.New("command rules: duplicate rule UUID")
		}
		seen[r.ID] = true
		r.Name = strings.TrimSpace(r.Name)
		if !utf8.ValidString(r.Name) || utf8.RuneCountInString(r.Name) < 1 || utf8.RuneCountInString(r.Name) > 80 || strings.ContainsFunc(r.Name, unicode.IsControl) {
			return nil, errors.New("command rules: name must be 1-80 characters without control characters")
		}
		if r.Protocol != "postgres" && r.Protocol != "ssh" && r.Protocol != "mysql" {
			return nil, errors.New("command rules: choose a supported enforcing protocol: postgres, mysql or ssh")
		}
		switch r.Effect {
		case EffectBlock:
			if r.RequiredApprovals != 0 || r.ReviewTTLSeconds != 0 {
				return nil, errors.New("command rules: block rules have no review quorum or deadline")
			}
		case EffectReview:
			if r.RequiredApprovals < 1 || r.RequiredApprovals > 3 || r.ReviewTTLSeconds < 5 || r.ReviewTTLSeconds > 45 {
				return nil, errors.New("command rules: review needs 1-3 distinct humans and a 5-45 second deadline")
			}
		default:
			return nil, errors.New("command rules: choose block or require_approval")
		}
		if len(r.Operations) < 1 || len(r.Operations) > MaxOperations {
			return nil, fmt.Errorf("command rules: 1-%d operation names are required", MaxOperations)
		}
		ops := make([]string, 0, len(r.Operations))
		for _, op := range r.Operations {
			op = strings.TrimSpace(op)
			if r.Protocol == "ssh" {
				op = strings.ToLower(op)
			} else {
				op = strings.ToUpper(op)
			}
			if !KnownOperation(r.Protocol, op) {
				return nil, errors.New("command rules: choose a supported operation for this protocol")
			}
			ops = append(ops, op)
		}
		slices.Sort(ops)
		r.Operations = slices.Compact(ops)
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// ForTarget selects only enabled rules applying to this session's protocol.
func ForTarget(templateID string, revision int64, rules []Rule, target string) *Policy {
	var selected []PolicyRule
	for _, r := range rules {
		if r.Enabled && r.Protocol == target {
			r.Operations = slices.Clone(r.Operations)
			selected = append(selected, PolicyRule{ID: r.ID, Protocol: r.Protocol, Operations: r.Operations, Effect: r.Effect, RequiredApprovals: r.RequiredApprovals, ReviewTTLSeconds: r.ReviewTTLSeconds})
		}
	}
	if len(selected) == 0 {
		return nil
	}
	return &Policy{Version: Version, TemplateID: templateID, TemplateRevision: revision, Rules: selected}
}

// ValidatePolicy refuses a noncanonical or unsupported frozen intent. A newer
// policy format must not be silently interpreted as this one.
func ValidatePolicy(p *Policy, target string) error {
	if p == nil {
		return nil
	}
	id, err := uuid.Parse(p.TemplateID)
	if err != nil || id == uuid.Nil || id.String() != p.TemplateID || p.Version != Version || p.TemplateRevision < 1 || len(p.Rules) == 0 {
		return errors.New("command rules: malformed policy snapshot")
	}
	source := make([]Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		source = append(source, Rule{ID: r.ID, Name: "frozen operation rule", Enabled: true, Protocol: r.Protocol, Operations: r.Operations, Effect: r.Effect, RequiredApprovals: r.RequiredApprovals, ReviewTTLSeconds: r.ReviewTTLSeconds})
	}
	canonical, err := CanonicalRules(source)
	if err != nil {
		return err
	}
	for i, r := range canonical {
		want := PolicyRule{ID: r.ID, Protocol: r.Protocol, Operations: r.Operations, Effect: r.Effect, RequiredApprovals: r.RequiredApprovals, ReviewTTLSeconds: r.ReviewTTLSeconds}
		if !reflect.DeepEqual(want, p.Rules[i]) || r.Protocol != target {
			return errors.New("command rules: policy snapshot is not canonical for this protocol")
		}
	}
	return nil
}

// Match returns configured rule UUIDs only. Unknown words cannot become policy
// evidence, even if an untrusted caller supplies them as an operation name.
func Match(p *Policy, operations []string) []string {
	if p == nil {
		return nil
	}
	var ids []string
	for _, r := range p.Rules {
		for _, op := range operations {
			if KnownOperation(r.Protocol, op) && slices.Contains(r.Operations, op) {
				ids = append(ids, r.ID)
				break
			}
		}
	}
	return ids
}

var postgresOperationNames = [...]string{"ALTER", "ANALYZE", "BEGIN", "CALL", "CLUSTER", "COMMENT", "COMMIT", "COPY", "CREATE", "DELETE", "DISCARD", "DO", "DROP", "EXECUTE", "EXPLAIN", "GRANT", "INSERT", "LOCK", "MERGE", "PREPARE", "REFRESH", "REINDEX", "RESET", "REVOKE", "ROLLBACK", "SELECT", "SET", "TRUNCATE", "UPDATE", "VACUUM", "WITH"}

// PostgresOperationNames returns a copy of the finite public selector vocabulary.
func PostgresOperationNames() []string {
	out := []string{}
	for _, op := range postgresOperationNames {
		if knownPostgresRuleOperation(op) {
			out = append(out, op)
		}
	}
	return out
}
func knownPostgresRuleOperation(op string) bool {
	return knownPostgresOperation(op) && op != "PREPARE" && op != "EXECUTE"
}
func knownPostgresOperation(op string) bool { return postgresOperationIndex(op) >= 0 }
func postgresOperationIndex(op string) int {
	switch op {
	case "ALTER":
		return 0
	case "ANALYZE":
		return 1
	case "BEGIN":
		return 2
	case "CALL":
		return 3
	case "CLUSTER":
		return 4
	case "COMMENT":
		return 5
	case "COMMIT":
		return 6
	case "COPY":
		return 7
	case "CREATE":
		return 8
	case "DELETE":
		return 9
	case "DISCARD":
		return 10
	case "DO":
		return 11
	case "DROP":
		return 12
	case "EXECUTE":
		return 13
	case "EXPLAIN":
		return 14
	case "GRANT":
		return 15
	case "INSERT":
		return 16
	case "LOCK":
		return 17
	case "MERGE":
		return 18
	case "PREPARE":
		return 19
	case "REFRESH":
		return 20
	case "REINDEX":
		return 21
	case "RESET":
		return 22
	case "REVOKE":
		return 23
	case "ROLLBACK":
		return 24
	case "SELECT":
		return 25
	case "SET":
		return 26
	case "TRUNCATE":
		return 27
	case "UPDATE":
		return 28
	case "VACUUM":
		return 29
	case "WITH":
		return 30
	}
	return -1
}

// MatchedOperations retains only known operation names that actually matched a
// configured rule. Unknown words, identifiers and values cannot leave the relay.
func MatchedOperations(p *Policy, operations []string) []string {
	if p == nil {
		return nil
	}
	out := []string{}
	for _, op := range operations {
		if !KnownAnyOperation(op) {
			continue
		}
		for _, r := range p.Rules {
			if slices.Contains(r.Operations, op) {
				out = append(out, op)
				break
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var sshOperationNames = []string{"bash", "chmod", "chown", "chpasswd", "command", "dd", "env", "exec", "iptables", "kill", "mkfs", "mount", "nft", "node", "passwd", "perl", "python", "python3", "reboot", "rm", "rmdir", "ruby", "scp", "sftp", "sh", "ssh", "su", "sudo", "systemctl", "umount", "useradd", "userdel"}

func OperationNames(protocol string) []string {
	if protocol == "ssh" {
		return slices.Clone(sshOperationNames)
	}
	if protocol == "mysql" {
		return slices.Clone(mysqlOperationNames)
	}
	if protocol == "postgres" {
		return PostgresOperationNames()
	}
	return nil
}
func KnownOperation(protocol, operation string) bool {
	if protocol == "ssh" {
		return slices.Contains(sshOperationNames, operation)
	}
	if protocol == "mysql" {
		return slices.Contains(mysqlOperationNames, operation)
	}
	return protocol == "postgres" && knownPostgresRuleOperation(operation)
}
func KnownAnyOperation(operation string) bool {
	return knownPostgresRuleOperation(operation) || slices.Contains(sshOperationNames, operation) || slices.Contains(mysqlOperationNames, operation)
}
func AllOperationNames() []string {
	out := append(PostgresOperationNames(), sshOperationNames...)
	out = append(out, mysqlOperationNames...)
	slices.Sort(out)
	return slices.Compact(out)
}

var mysqlOperationNames = []string{"ALTER", "ANALYZE", "BEGIN", "CALL", "COMMIT", "CREATE", "DELETE", "DO", "DROP", "EXPLAIN", "FLUSH", "GRANT", "INSERT", "KILL", "LOCK", "OPTIMIZE", "RENAME", "REPAIR", "REPLACE", "RESET", "REVOKE", "ROLLBACK", "SELECT", "SET", "SHOW", "START", "TRUNCATE", "UNLOCK", "UPDATE", "USE"}
