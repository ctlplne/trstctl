// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"bytes"
	"testing"
)

func TestAWSParserRejectsAmbiguousOrUnboundedPolicies(t *testing.T) {
	for _, body := range []string{
		`{"Version":"2012-10-17","Version":"2008-10-17","Statement":[]}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","NotResource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":null}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:Tag":"one","AWS:TAG":"two"}}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Unexpected":"value"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":null,"Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}} {}`,
	} {
		if _, err := Parse("invalid", []byte(body)); err == nil {
			t.Fatalf("ambiguous policy accepted: %s", body)
		}
	}
	if _, err := Parse("oversized", bytes.Repeat([]byte{' '}, maxPolicyBytes+1)); err == nil {
		t.Fatal("oversized body accepted")
	}
}
func TestAWSParsedDocumentOwnsItsPolicyBytes(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	document, err := Parse("owned", raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	copy := document.RawJSON()
	for i := range copy {
		copy[i] = 0
	}
	if bytes.Equal(copy, document.RawJSON()) {
		t.Fatal("raw policy receipt aliases its caller")
	}
	evidence := knownEvidence()
	evidence.Identity.Documents = []Document{document}
	if result := Evaluate(basicRequest(), evidence); result.Decision != Allowed {
		t.Fatal("caller changed a parsed policy through its original buffer")
	}
}
func FuzzAWSParsePolicy(f *testing.F) {
	f.Add([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		document, err := Parse("fuzz", raw)
		if err != nil {
			return
		}
		evidence := knownEvidence()
		evidence.Identity.Documents = []Document{document}
		result := Evaluate(basicRequest(), evidence)
		switch result.Decision {
		case Allowed, ExplicitDeny, ImplicitDeny, Indeterminate:
		default:
			t.Fatal("invalid evaluator outcome")
		}
		if len(result.Reasons) > 129 {
			t.Fatal("unbounded explanation")
		}
	})
}
