// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"testing/quick"
)

func TestAWSExplicitDenySurvivesExtraAllowsAndUnreadSources(t *testing.T) {
	allow := parsed(t, "allow", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	deny := parsed(t, "deny", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`)
	if err := quick.Check(func(data []byte, order bool) bool {
		if len(data) > 64 {
			data = data[:64]
		}
		request := basicRequest()
		request.Resource = "arn:aws:s3:::owned/" + hex.EncodeToString(data)
		evidence := knownEvidence()
		evidence.Identity.Documents = []Document{allow, deny}
		if order {
			evidence.Identity.Documents = []Document{deny, allow}
		}
		evidence.Boundary = PolicySet{Coverage: Unavailable}
		return Evaluate(request, evidence).Decision == ExplicitDeny
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func TestAWSUnreadPolicyCategoryCannotJustifyAllow(t *testing.T) {
	allow := parsed(t, "allow", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	for _, change := range []func(*Evidence){func(e *Evidence) { e.Identity = PolicySet{Coverage: Unavailable} }, func(e *Evidence) { e.Resource = PolicySet{Coverage: Unavailable} }, func(e *Evidence) { e.Boundary = PolicySet{Coverage: Unavailable} }, func(e *Evidence) { e.Session = PolicySet{Coverage: Unavailable} }, func(e *Evidence) { e.SCPCoverage = Unavailable }, func(e *Evidence) { e.RCPCoverage = Unavailable }} {
		evidence := knownEvidence()
		evidence.Identity.Documents = []Document{allow}
		change(&evidence)
		if result := Evaluate(basicRequest(), evidence); result.Decision == Allowed {
			t.Fatal("unread policy category became an Allow")
		}
	}
}
func TestAWSWildcardMatcherMatchesBoundedReference(t *testing.T) {
	if err := quick.Check(func(pattern, subject []byte) bool {
		alphabet := "abCD*?"
		if len(pattern) > 32 {
			pattern = pattern[:32]
		}
		if len(subject) > 32 {
			subject = subject[:32]
		}
		for i, v := range pattern {
			pattern[i] = alphabet[int(v)%len(alphabet)]
		}
		for i, v := range subject {
			subject[i] = alphabet[int(v)%4]
		}
		p, s := string(pattern), string(subject)
		source := regexp.QuoteMeta(p)
		source = strings.ReplaceAll(source, `\*`, ".*")
		source = strings.ReplaceAll(source, `\?`, ".")
		want, err := regexp.MatchString("^"+source+"$", s)
		if err != nil {
			return false
		}
		e := evaluation{steps: 100000}
		return (e.glob(p, s, false) == yes) == want
	}, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}
func FuzzAWSPolicyWildcard(f *testing.F) {
	f.Add("arn:aws:s3:::owned/*", "arn:aws:s3:::owned/report")
	f.Fuzz(func(t *testing.T, pattern, value string) {
		if len(pattern) > 2048 || len(value) > 2048 {
			return
		}
		e := evaluation{steps: 100000}
		result := e.glob(pattern, value, false)
		if result != yes && result != no && result != unknown {
			t.Fatal("invalid wildcard result")
		}
	})
}

func FuzzAWSConditionComparison(f *testing.F) {
	f.Add(byte(0), "operations", "operations")
	f.Add(byte(1), "192.0.2.24", "192.0.2.0/24")
	f.Add(byte(2), "2800", "3600")
	f.Add(byte(3), "2026-11-06T01:00:00Z", "2030-01-01T00:00:00Z")
	operators := []string{"StringEquals", "IpAddress", "NumericLessThanEquals", "DateLessThan", "StringLike", "ArnEquals", "Bool"}
	f.Fuzz(func(t *testing.T, kind byte, actual, wanted string) {
		if len(actual) > 2048 || len(wanted) > 2048 {
			return
		}
		e := evaluation{steps: 100000}
		result := e.compareCondition(operators[int(kind)%len(operators)], actual, wanted)
		if result != yes && result != no && result != unknown {
			t.Fatal("invalid condition outcome")
		}
	})
}
