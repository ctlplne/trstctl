// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func basicRequest() Request {
	return Request{Principal: Principal{Kind: IAMUser, ARN: "arn:aws:iam::111122223333:user/workload", AccountID: "111122223333"}, Action: "s3:GetObject", Resource: "arn:aws:s3:::owned/report", ResourceAccountID: "111122223333", Context: Context{Complete: true}}
}
func knownEvidence() Evidence {
	return Evidence{Identity: PolicySet{Coverage: Complete}, Resource: PolicySet{Coverage: Complete}, Boundary: PolicySet{Coverage: Absent}, Session: PolicySet{Coverage: Absent}, SCPCoverage: Absent, RCPCoverage: Absent}
}
func parsed(t *testing.T, id, body string) Document {
	t.Helper()
	doc, err := Parse(id, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
func TestAWSRequestRejectsMalformedIdentityActionAndResource(t *testing.T) {
	document := parsed(t, "all", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	for _, change := range []func(*Request){func(r *Request) { r.Action = "s3:GetObject:extra" }, func(r *Request) { r.Action = "s3:💥" }, func(r *Request) { r.Resource = "unbound-resource" }, func(r *Request) { r.Resource = "arn:aws:s3:us-east-1:444455556666:bucket/object" }, func(r *Request) { r.Principal.ARN = "arn:aws:iam::111122223333:user/" + strings.Repeat("a", 4096) }} {
		request := basicRequest()
		change(&request)
		evidence := knownEvidence()
		evidence.Identity.Documents = []Document{document}
		if got := Evaluate(request, evidence); got.Decision != Indeterminate {
			t.Fatalf("malformed request became %s", got.Decision)
		}
	}
}
func TestAWSResourcePrincipalUnionIsOrderIndependent(t *testing.T) {
	request := basicRequest()
	request.Principal.Kind = IAMRole
	request.Principal.ARN = "arn:aws:iam::111122223333:role/workload"
	boundary := parsed(t, "write", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}}`)
	for _, names := range [][]string{{"*", request.Principal.ARN}, {request.Principal.ARN, "*"}} {
		body, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": names}, "Action": "s3:GetObject", "Resource": "*"}})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := Parse("resource", body)
		if err != nil {
			t.Fatal(err)
		}
		evidence := knownEvidence()
		evidence.Resource.Documents = []Document{doc}
		evidence.Boundary = PolicySet{Coverage: Complete, Documents: []Document{boundary}}
		if got := Evaluate(request, evidence); got.Decision != Allowed {
			t.Fatalf("principal order changed effective union: %s", got.Decision)
		}
	}
}
func TestAWSConditionComparisonsConsumeSharedWorkBudget(t *testing.T) {
	evaluation := evaluation{steps: 1}
	result := evaluation.compareCondition("StringEquals", strings.Repeat("a", 2048), strings.Repeat("a", 2048))
	if result != unknown || !evaluation.exhausted {
		t.Fatal("large condition comparisons bypassed the shared work budget")
	}
}
