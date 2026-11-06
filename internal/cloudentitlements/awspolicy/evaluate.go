// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"bytes"
	"fmt"
	"strings"
)

type truth uint8

const (
	no truth = iota
	yes
	unknown
)

func and(a, b truth) truth {
	if a == no || b == no {
		return no
	}
	if a == unknown || b == unknown {
		return unknown
	}
	return yes
}
func or(a, b truth) truth {
	if a == yes || b == yes {
		return yes
	}
	if a == unknown || b == unknown {
		return unknown
	}
	return no
}
func not(a truth) truth {
	if a == unknown {
		return unknown
	}
	if a == yes {
		return no
	}
	return yes
}

type grants struct{ allow, deny, direct, restricted, account truth }
type evaluation struct {
	request          Request
	context          map[string][]string
	absent           map[string]bool
	steps            int
	exhausted        bool
	reasons          []Reason
	statements       int
	boundaryCoverage Coverage
}

// Evaluate combines applicable policy categories for a single-account machine
// identity. It never substitutes absent evidence for a verified absence.
func Evaluate(request Request, evidence Evidence) Result {
	e := evaluation{request: request, context: map[string][]string{}, absent: map[string]bool{}, steps: 1000000, boundaryCoverage: evidence.Boundary.Coverage}
	if reason := e.validate(); reason != "" {
		return Result{Decision: Indeterminate, Reasons: []Reason{{Detail: reason}}}
	}
	identity := e.category("identity", evidence.Identity, false)
	resource := e.category("resource", evidence.Resource, true)
	boundary := e.category("boundary", evidence.Boundary, false)
	session := e.category("session", evidence.Session, false)
	scp, scpDeny := e.hierarchy("scp", evidence.SCPCoverage, evidence.SCP)
	rcp, rcpDeny := e.hierarchy("rcp", evidence.RCPCoverage, evidence.RCP)
	deny := or(or(or(identity.deny, resource.deny), or(boundary.deny, session.deny)), or(scpDeny, rcpDeny))
	if deny == yes {
		return e.result(ExplicitDeny, "an applicable policy explicitly denies this request")
	}
	if e.exhausted {
		return e.result(Indeterminate, "AWS policy evaluation exceeded its bounded work budget")
	}
	// KMS grants and role trust evaluation need additional source evidence. A
	// general IAM allow alone is never sufficient evidence for these requests.
	action := strings.ToLower(request.Action)
	if request.Principal.AccountID != request.ResourceAccountID || strings.HasPrefix(action, "kms:") || strings.HasPrefix(action, "sts:assumerole") {
		return e.result(Indeterminate, "cross-account, KMS grant or role trust authorization is outside this captured model")
	}
	bounds := and(boundary.allow, session.allow)
	identityPath := and(identity.allow, bounds)
	resourcePath := or(resource.direct, and(resource.restricted, bounds))
	// An account principal delegates authority to that account's identity policy.
	resourcePath = or(resourcePath, and(resource.account, identityPath))
	permitted := and(or(identityPath, resourcePath), and(scp, rcp))
	if deny == unknown {
		return e.result(Indeterminate, "unread policy evidence or an unresolved Deny can change the final decision")
	}
	if permitted == no {
		return e.result(ImplicitDeny, "the complete applicable policy sets do not grant this request")
	}
	if deny == unknown || permitted == unknown {
		return e.result(Indeterminate, "unread policy evidence or unknown matching context can change this request")
	}
	return e.result(Allowed, "the captured policy sets grant this request in the stated context")
}
func (e *evaluation) result(decision Decision, detail string) Result {
	reasons := append([]Reason(nil), e.reasons...)
	reasons = append(reasons, Reason{Detail: detail})
	return Result{Decision: decision, Reasons: reasons}
}
func (e *evaluation) reason(source, statement, detail string) {
	if len(e.reasons) < 128 {
		e.reasons = append(e.reasons, Reason{Source: source, Statement: statement, Detail: detail})
	}
}
func (e *evaluation) validate() string {
	r := e.request
	if len(r.Action) == 0 || len(r.Action) > 256 || !strings.Contains(r.Action, ":") || strings.ContainsAny(r.Action, "*?${}\x00\r\n ") || len(r.Resource) == 0 || len(r.Resource) > 2048 || strings.ContainsAny(r.Resource, "\x00\r\n") || !accountID(r.Principal.AccountID) || !accountID(r.ResourceAccountID) {
		return "invalid bounded AWS action, resource or account identity"
	}
	if len(r.Principal.ARN) > 2048 || len(r.Principal.RoleARN) > 2048 || !validAction(r.Action) {
		return "invalid bounded AWS action or principal ARN"
	}
	resource := strings.SplitN(r.Resource, ":", 6)
	if r.Resource != "*" {
		if len(resource) != 6 || resource[0] != "arn" || !partition(resource[1]) || resource[2] == "" || resource[5] == "" {
			return "resource must be an exact ARN or the AWS global resource marker"
		}
		if resource[4] != "" && resource[4] != r.ResourceAccountID {
			return "resource ARN and declared owner account disagree"
		}
	}
	if strings.ContainsAny(r.Principal.RoleARN, "*?\x00\r\n") || (r.Principal.Kind != RoleSession && r.Principal.RoleARN != "") {
		return "invalid or unexpected role-session issuer"
	}
	p := strings.SplitN(r.Principal.ARN, ":", 6)
	if len(p) != 6 || p[0] != "arn" || !partition(p[1]) || p[3] != "" || p[4] != r.Principal.AccountID || strings.ContainsAny(p[5], "*?\x00\r\n") {
		return "principal ARN is not bound to its account"
	}
	if r.Resource != "*" && resource[1] != p[1] {
		return "principal and resource partitions disagree"
	}
	switch r.Principal.Kind {
	case IAMUser:
		if p[2] != "iam" || !strings.HasPrefix(p[5], "user/") || len(p[5]) <= 5 || strings.HasSuffix(p[5], "/") {
			return "invalid IAM user principal"
		}
	case IAMRole:
		if p[2] != "iam" || !strings.HasPrefix(p[5], "role/") || len(p[5]) <= 5 || strings.HasSuffix(p[5], "/") {
			return "invalid IAM role principal"
		}
	case RoleSession:
		role := strings.SplitN(r.Principal.RoleARN, ":", 6)
		parts := strings.Split(p[5], "/")
		if p[2] != "sts" || len(parts) != 3 || parts[0] != "assumed-role" || parts[1] == "" || parts[2] == "" || len(role) != 6 || role[0] != "arn" || role[1] != p[1] || role[2] != "iam" || role[3] != "" || role[4] != p[4] || !strings.HasPrefix(role[5], "role/") {
			return "role session needs its exact same-account issuer ARN"
		}
		names := strings.Split(role[5], "/")
		if names[len(names)-1] != parts[1] {
			return "role session and issuer names disagree"
		}
	default:
		return "principal class is outside the captured AWS model"
	}
	if strings.Contains(r.Principal.ARN, ":role/aws-service-role/") || strings.Contains(r.Principal.RoleARN, ":role/aws-service-role/") {
		return "service-linked-role organization exceptions are not modeled"
	}
	if len(r.Context.Values) > 128 || len(r.Context.AbsentKeys) > 128 {
		return "request context exceeds its key bound"
	}
	for key, values := range r.Context.Values {
		folded := strings.ToLower(key)
		if len(key) == 0 || len(key) > 256 || len(values) == 0 || len(values) > 32 {
			return "invalid context key or values"
		}
		if _, found := e.context[folded]; found {
			return "context keys collide after case folding"
		}
		for _, v := range values {
			if len(v) > 2048 {
				return "context value exceeds its byte bound"
			}
		}
		e.context[folded] = append([]string(nil), values...)
	}
	for _, key := range r.Context.AbsentKeys {
		folded := strings.ToLower(key)
		if len(key) == 0 || len(key) > 256 {
			return "invalid absent context key"
		}
		if _, found := e.context[folded]; found {
			return "context key is both present and absent"
		}
		e.absent[folded] = true
	}
	principalARN := r.Principal.ARN
	if r.Principal.Kind == RoleSession {
		principalARN = r.Principal.RoleARN
	}
	for key, value := range map[string]string{"aws:principalarn": principalARN, "aws:principalaccount": r.Principal.AccountID} {
		if values, found := e.context[key]; found && (len(values) != 1 || values[0] != value) {
			return "context attempts to replace a verified principal fact"
		}
		if e.absent[key] {
			return "context removes a verified principal fact"
		}
		e.context[key] = []string{value}
	}
	return ""
}
func accountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, v := range value {
		if v < '0' || v > '9' {
			return false
		}
	}
	return true
}
func partition(value string) bool {
	return value == "aws" || value == "aws-us-gov" || value == "aws-cn"
}
func (e *evaluation) hierarchy(name string, coverage Coverage, layers []PolicySet) (truth, truth) {
	switch coverage {
	case Absent:
		if len(layers) == 0 {
			return yes, no
		}
	case Complete:
		if len(layers) == 0 {
			return unknown, unknown
		}
		allow, deny := yes, no
		if len(layers) > 16 {
			return unknown, unknown
		}
		for i, layer := range layers {
			g := e.category(fmt.Sprintf("%s[%d]", name, i), layer, name == "rcp")
			allow = and(allow, g.allow)
			deny = or(deny, g.deny)
		}
		return allow, deny
	}
	e.reason(name, "", "organization evidence is unavailable or inconsistent")
	return unknown, unknown
}
func (e *evaluation) category(name string, set PolicySet, resource bool) grants {
	optional := name == "boundary" || name == "session"
	if set.Coverage == Absent && len(set.Documents) == 0 {
		if optional {
			return grants{allow: yes}
		}
		return grants{}
	}
	if set.Coverage != Complete || len(set.Documents) > 64 {
		e.reason(name, "", "policy evidence is unavailable or inconsistent")
		return grants{allow: unknown, deny: unknown, direct: unknown, restricted: unknown, account: unknown}
	}
	var out grants
	for _, doc := range set.Documents {
		if doc.id == "" || len(doc.statements) == 0 {
			out.allow = unknown
			out.deny = unknown
			continue
		}
		for i, rule := range doc.statements {
			if strings.HasPrefix(name, "rcp[") && !supportedRCP(rule) {
				out.allow = or(out.allow, unknown)
				out.deny = or(out.deny, unknown)
				e.reason(name+":"+doc.id, statementName(rule, i), "unsupported resource control policy syntax")
				continue
			}
			if e.exhausted {
				out.allow = or(out.allow, unknown)
				out.deny = or(out.deny, unknown)
				return out
			}
			e.statements++
			if e.statements > 2048 {
				e.exhausted = true
				out.allow = unknown
				out.deny = unknown
				return out
			}
			applies := and(e.selectors(rule.Action, rule.NotAction, e.request.Action, true), e.selectors(rule.Resource, rule.NotResource, e.request.Resource, false))
			if applies == no {
				continue
			}
			direct, restricted, account := no, no, no
			if resource {
				direct, restricted, account = e.principal(rule)
				applies = and(applies, or(direct, or(restricted, account)))
			} else if len(rule.Principal) > 0 || len(rule.NotPrincipal) > 0 {
				applies = and(applies, unknown)
			}
			applies = and(applies, e.conditions(rule.Condition))
			if applies == no {
				continue
			}
			source := name + ":" + doc.id
			sid := statementName(rule, i)
			if rule.Effect == "Deny" {
				out.deny = or(out.deny, applies)
				e.reason(source, sid, "Deny statement matches or needs unavailable context")
				continue
			}
			out.allow = or(out.allow, applies)
			if resource {
				out.direct = or(out.direct, and(applies, direct))
				out.restricted = or(out.restricted, and(applies, restricted))
				out.account = or(out.account, and(applies, account))
			}
			e.reason(source, sid, "Allow statement matches or needs unavailable context")
		}
	}
	return out
}
func (e *evaluation) selectors(positive, negative []string, value string, fold bool) truth {
	values := positive
	negated := false
	if len(negative) > 0 {
		values = negative
		negated = true
	}
	if len(values) == 0 {
		return unknown
	}
	result := no
	for _, pattern := range values {
		result = or(result, e.glob(pattern, value, fold))
	}
	if negated {
		return not(result)
	}
	return result
}

// glob uses bounded greedy wildcard matching. The shared step budget bounds
// repeated-star work across all policy documents and condition comparisons.
func (e *evaluation) glob(pattern, value string, fold bool) truth {
	if strings.Contains(pattern, "${") {
		return unknown
	}
	if fold {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	p, v := []rune(pattern), []rune(value)
	i, j, star, mark := 0, 0, -1, 0
	for j < len(v) {
		e.steps--
		if e.steps < 0 {
			e.exhausted = true
			return unknown
		}
		if i < len(p) && (p[i] == '?' || p[i] == v[j]) {
			i++
			j++
		} else if i < len(p) && p[i] == '*' {
			star = i
			i++
			mark = j
		} else if star >= 0 {
			mark++
			j = mark
			i = star + 1
		} else {
			return no
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	if i == len(p) {
		return yes
	}
	return no
}
func (e *evaluation) principal(rule statement) (truth, truth, truth) {
	raw := rule.Principal
	negated := false
	if len(rule.NotPrincipal) > 0 {
		raw = rule.NotPrincipal
		negated = true
	}
	if len(raw) == 0 {
		return unknown, unknown, unknown
	}
	selector, err := parsePrincipal(raw)
	if err != nil {
		return unknown, unknown, unknown
	}
	direct, restricted, account := no, no, no
	if selector.all {
		direct = yes
	}
	for _, name := range selector.aws {
		if !e.spend(1 + len(name) + len(e.request.Principal.ARN) + len(e.request.Principal.RoleARN)) {
			return unknown, unknown, unknown
		}
		switch {
		case name == "*":
			direct = yes
		case name == e.request.Principal.ARN:
			if e.request.Principal.Kind == IAMRole {
				restricted = yes
			} else {
				direct = yes
			}
		case name == e.request.Principal.RoleARN && e.request.Principal.Kind == RoleSession:
			restricted = yes
		case name == e.request.Principal.AccountID || name == "arn:"+strings.Split(e.request.Principal.ARN, ":")[1]+":iam::"+e.request.Principal.AccountID+":root":
			account = yes
		case strings.ContainsAny(name, "*?"):
			direct = or(direct, unknown)
		default:
			if !strings.HasPrefix(name, "arn:") && !accountID(name) {
				direct = or(direct, unknown)
			}
		}
	}
	if selector.unsupported {
		direct = or(direct, unknown)
	}
	if negated {
		// Deny/NotPrincipal with boundaries has special AWS behavior. Until its
		// category presence is resolved, it must not permit a guessed Allow.
		if rule.Effect == "Deny" {
			if e.boundaryCoverage == Complete {
				return yes, no, no
			}
			if e.boundaryCoverage != Absent {
				return unknown, no, no
			}
		}
		return not(or(direct, or(restricted, account))), no, no
	}
	return direct, restricted, account
}

func validAction(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	for _, part := range parts {
		for _, v := range part {
			if (v < 'a' || v > 'z') && (v < 'A' || v > 'Z') && (v < '0' || v > '9') && v != '-' {
				return false
			}
		}
	}
	return true
}
func (e *evaluation) spend(count int) bool {
	if e.exhausted || count > e.steps {
		e.exhausted = true
		return false
	}
	e.steps -= count
	return true
}

// RCPs require the literal wildcard principal, prohibit inverse principals and
// actions, and only permit the built-in full-access Allow. Unsupported source
// forms cannot establish a permission or discard a potential Deny.
func supportedRCP(rule statement) bool {
	if !bytes.Equal(bytes.TrimSpace(rule.Principal), []byte(`"*"`)) || len(rule.NotPrincipal) != 0 || len(rule.NotAction) != 0 {
		return false
	}
	if rule.Effect == "Allow" {
		return len(rule.Action) == 1 && rule.Action[0] == "*" && len(rule.Resource) == 1 && rule.Resource[0] == "*" && len(rule.NotResource) == 0 && len(rule.Condition) == 0
	}
	return true
}
