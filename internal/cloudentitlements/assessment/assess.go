// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto"
)

// Validate bounds imported evidence. Its declared coverage is an operator
// assertion, never proof that a cloud logging service captured every event.
func Validate(input Input) error {
	if len(input.Checks) > 128 || len(input.Supplemental) > 128 || len(input.Activity.Scopes) > 512 || len(input.Activity.Events) > 10000 {
		return errors.New("cloud assessment input exceeds count bounds")
	}
	if len(input.Checks) == 0 {
		return errors.New("select at least one exact permission check")
	}
	seen := map[string]bool{}
	for _, check := range input.Checks {
		if !validARN(check.PrincipalARN) || !actionName(check.Action) || !resourceName(check.Resource) || len(check.ResourceAccountID) != 12 {
			return errors.New("invalid exact permission check")
		}
		key := check.PrincipalARN + "\x00" + strings.ToLower(check.Action) + "\x00" + check.Resource
		if seen[key] {
			return errors.New("duplicate exact permission check")
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	for _, e := range input.Supplemental {
		if !validARN(e.PrincipalARN) || !resourceName(e.Resource) || len(e.ResourceAccountID) != 12 || !recordedRef(e.SourceRef) {
			return errors.New("recorded policy evidence needs exact scope and recorded: provenance")
		}
		key := e.PrincipalARN + "\x00" + e.Resource + "\x00" + e.ResourceAccountID
		if seen[key] {
			return errors.New("duplicate recorded policy scope")
		}
		seen[key] = true
		if len(e.SCP) > 16 || len(e.RCP) > 16 {
			return errors.New("organization hierarchy exceeds bound")
		}
		if _, err := parseSet(e.ResourcePolicies); err != nil {
			return err
		}
		for _, set := range append(append([]PolicySet(nil), e.SCP...), e.RCP...) {
			if _, err := parseSet(set); err != nil {
				return err
			}
		}
		if !coverage(e.SCPCoverage) || !coverage(e.RCPCoverage) {
			return errors.New("invalid organization evidence coverage")
		}
	}
	a := input.Activity
	if len(a.Scopes) > 0 || len(a.Events) > 0 || a.SourceRef != "" || !a.Start.IsZero() || !a.End.IsZero() {
		if !recordedRef(a.SourceRef) || a.Start.IsZero() || !a.Start.Before(a.End) || a.End.Sub(a.Start) > 366*24*time.Hour {
			return errors.New("recorded activity needs provenance and a bounded nonempty window")
		}
	}
	seen = map[string]bool{}
	for _, scope := range a.Scopes {
		if !validARN(scope.PrincipalARN) || !actionName(scope.Action) || !resourceName(scope.Resource) {
			return errors.New("invalid activity coverage scope")
		}
		key := scope.PrincipalARN + "\x00" + strings.ToLower(scope.Action) + "\x00" + scope.Resource
		if seen[key] {
			return errors.New("duplicate activity coverage scope")
		}
		seen[key] = true
	}
	for _, event := range a.Events {
		if !validARN(event.PrincipalARN) || !actionName(event.Action) || (event.Resource != "" && !resourceName(event.Resource)) || event.At.IsZero() {
			return errors.New("invalid normalized activity event")
		}
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 512<<10 {
		return errors.New("recorded assessment input exceeds 512KiB")
	}
	return nil
}
func Assess(identity awsiam.Identity, input Input, now time.Time) (Assessment, error) {
	if err := Validate(input); err != nil {
		return Assessment{}, err
	}
	if input.Activity.End.After(now) {
		return Assessment{}, errors.New("activity coverage extends beyond capture time")
	}
	out := Assessment{Version: 1, Provider: "aws-iam", CollectedAt: now.UTC(), Identity: identity, ActivityStart: input.Activity.Start, ActivityEnd: input.Activity.End, RiskScore: 20, Limitations: []string{"Only explicitly checked actions/resources/context are evaluated; this is not an exhaustive AWS permission inventory.", "Imported policy/activity coverage is operator-supplied recorded evidence, not native completeness proof.", "Self-escalation candidates require additional trust/dependency and live authority checks; no exploit is proven.", "Findings do not authorize or execute a cloud mutation."}}
	sourceInput, err := json.Marshal(input)
	if err != nil {
		return Assessment{}, err
	}
	canonicalInput, err := canonicalJSON(sourceInput)
	if err != nil {
		return Assessment{}, err
	}
	out.InputSHA256 = crypto.SHA256Hex(canonicalInput)
	out.CapturedInput.Activity = ActivityEvidence{SourceRef: input.Activity.SourceRef, Start: input.Activity.Start, End: input.Activity.End}
	for _, check := range input.Checks {
		if check.PrincipalARN == identity.Principal.ARN {
			out.CapturedInput.Checks = append(out.CapturedInput.Checks, check)
		}
	}
	for _, extra := range input.Supplemental {
		if extra.PrincipalARN == identity.Principal.ARN {
			out.CapturedInput.Supplemental = append(out.CapturedInput.Supplemental, extra)
		}
	}
	for _, scope := range input.Activity.Scopes {
		if scope.PrincipalARN == identity.Principal.ARN {
			out.CapturedInput.Activity.Scopes = append(out.CapturedInput.Activity.Scopes, scope)
		}
	}
	for _, event := range input.Activity.Events {
		if event.PrincipalARN == identity.Principal.ARN {
			out.CapturedInput.Activity.Events = append(out.CapturedInput.Activity.Events, event)
		}
	}
	matched := 0
	for _, check := range input.Checks {
		if check.PrincipalARN != identity.Principal.ARN {
			continue
		}
		matched++
		evidence := identity.Evidence
		policySource := "native IAM; organization/resource evidence unavailable"
		for _, extra := range input.Supplemental {
			if extra.PrincipalARN != check.PrincipalARN || extra.Resource != check.Resource || extra.ResourceAccountID != check.ResourceAccountID {
				continue
			}
			var err error
			evidence.Resource, err = parseSet(extra.ResourcePolicies)
			if err != nil {
				return Assessment{}, err
			}
			evidence.SCPCoverage = extra.SCPCoverage
			evidence.RCPCoverage = extra.RCPCoverage
			evidence.SCP = nil
			evidence.RCP = nil
			for _, set := range extra.SCP {
				parsed, err := parseSet(set)
				if err != nil {
					return Assessment{}, err
				}
				evidence.SCP = append(evidence.SCP, parsed)
			}
			for _, set := range extra.RCP {
				parsed, err := parseSet(set)
				if err != nil {
					return Assessment{}, err
				}
				evidence.RCP = append(evidence.RCP, parsed)
			}
			policySource = "native IAM plus operator-supplied " + extra.SourceRef
		}
		result := awspolicy.Evaluate(awspolicy.Request{Principal: identity.Principal, Action: check.Action, Resource: check.Resource, ResourceAccountID: check.ResourceAccountID, Context: check.Context}, evidence)
		evaluation := Evaluation{Check: check, Result: result, PolicySource: policySource, ActivitySource: input.Activity.SourceRef, ActivityCoverage: awspolicy.Unavailable}
		for _, scope := range input.Activity.Scopes {
			if scope.Complete && scope.PrincipalARN == check.PrincipalARN && strings.EqualFold(scope.Action, check.Action) && scope.Resource == check.Resource {
				evaluation.ActivityCoverage = awspolicy.Complete
			}
		}
		for _, event := range input.Activity.Events {
			if event.PrincipalARN != check.PrincipalARN || !strings.EqualFold(event.Action, check.Action) || event.At.Before(input.Activity.Start) || !event.At.Before(input.Activity.End) {
				continue
			}
			switch event.Resource {
			case check.Resource:
				evaluation.ObservedUses++
			case "":
				evaluation.ResourceUnboundUses++
			}
		}
		evaluation.Unused = result.Decision == awspolicy.Allowed && evaluation.ActivityCoverage == awspolicy.Complete && evaluation.ObservedUses == 0 && evaluation.ResourceUnboundUses == 0
		if evaluation.Unused {
			out.RiskScore = max(out.RiskScore, 65)
		}
		if result.Decision == awspolicy.Allowed {
			if reason := escalationReason(identity.Principal, check); reason != "" {
				out.Escalation = append(out.Escalation, Escalation{Action: check.Action, Resource: check.Resource, Reason: reason, Confidence: "policy_candidate"})
				out.RiskScore = max(out.RiskScore, 85)
			}
		}
		out.Evaluations = append(out.Evaluations, evaluation)
	}
	if matched == 0 {
		return Assessment{}, errors.New("selected identity has no exact permission checks")
	}
	if len(identity.Keys) > 2 {
		return Assessment{}, errors.New("IAM key finding exceeds native key count")
	}
	for _, key := range identity.Keys {
		age := days(now.Sub(key.Created))
		if key.Created.IsZero() || key.Created.After(now) {
			age = 0
		}
		since := key.Created
		if key.LastUsed != nil {
			since = *key.LastUsed
		}
		unused := days(now.Sub(since))
		if since.IsZero() || since.After(now) {
			unused = 0
		}
		finding := KeyFinding{Key: key, AgeDays: age, UnusedDays: unused, LongLived: age >= 90, Stale: key.Status == "Active" && key.LastUseCoverage == awspolicy.Complete && unused >= 90}
		if finding.Stale {
			out.RiskScore = max(out.RiskScore, 80)
		} else if finding.LongLived && key.Status == "Active" {
			out.RiskScore = max(out.RiskScore, 60)
		}
		out.Keys = append(out.Keys, finding)
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > 512<<10 {
		return Assessment{}, errors.New("captured assessment exceeds 512KiB event limit")
	}
	if _, err := Fingerprint(out); err != nil {
		return Assessment{}, err
	}
	return out, nil
}
func days(duration time.Duration) int {
	if duration <= 0 {
		return 0
	}
	return int(duration / (24 * time.Hour))
}
func validARN(v string) bool {
	return len(v) > 4 && len(v) <= 2048 && strings.HasPrefix(v, "arn:") && !strings.ContainsAny(v, "\x00\r\n*?")
}
func resourceName(v string) bool { return v == "*" || validARN(v) }
func actionName(v string) bool {
	if len(v) == 0 || len(v) > 256 || strings.ContainsAny(v, "*?\x00\r\n ") {
		return false
	}
	parts := strings.Split(v, ":")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}
func recordedRef(v string) bool {
	return strings.HasPrefix(v, "recorded:") && len(v) > 9 && len(v) <= 1024 && !strings.ContainsAny(v, "\x00\r\n")
}
func coverage(v awspolicy.Coverage) bool {
	return v == awspolicy.Complete || v == awspolicy.Absent || v == awspolicy.Unavailable
}
func parseSet(set PolicySet) (awspolicy.PolicySet, error) {
	out := awspolicy.PolicySet{Coverage: set.Coverage}
	if !coverage(set.Coverage) || len(set.Documents) > 64 || (set.Coverage != awspolicy.Complete && len(set.Documents) != 0) {
		return out, errors.New("invalid recorded policy coverage")
	}
	for _, raw := range set.Documents {
		canonical, err := canonicalJSON(raw)
		if err != nil {
			return out, err
		}
		doc, err := awspolicy.Parse(crypto.SHA256Hex(canonical), raw)
		if err != nil {
			return out, fmt.Errorf("recorded policy rejected: %w", err)
		}
		out.Documents = append(out.Documents, doc)
	}
	return out, nil
}
func escalationReason(principal awspolicy.Principal, check Check) string {
	action := strings.ToLower(check.Action)
	switch action {
	case "iam:putuserpolicy", "iam:attachuserpolicy", "iam:deleteuserpermissionsboundary":
		if principal.Kind == awspolicy.IAMUser && check.Resource == principal.ARN {
			return "An allowed checked action can change this same user's policy limit; another policy/attachment and native enforcement must still be checked."
		}
	case "iam:putrolepolicy", "iam:attachrolepolicy", "iam:deleterolepermissionsboundary", "iam:updateassumerolepolicy":
		if principal.Kind == awspolicy.IAMRole && check.Resource == principal.ARN {
			return "An allowed checked action can change this same role's policy/trust limit; session and native enforcement must still be checked."
		}
	case "iam:createpolicyversion", "iam:setdefaultpolicyversion":
		for _, policy := range []string{":policy/"} {
			if strings.Contains(check.Resource, policy) {
				return "An allowed checked action can change a managed policy version; attachment to this identity must be independently verified."
			}
		}
	}
	return ""
}

// Fingerprint binds the typed assessment facts. Unknown triage fields cannot
// change a grant; modifying any typed fact invalidates the graph evidence hash.
func Fingerprint(value Assessment) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return "cloud-machine-v1:" + crypto.SHA256Hex(canonical), nil
}
