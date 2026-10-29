// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"strings"
	"testing"
)

func protectionDigestPolicy() PrivacyEventPolicy {
	type payload struct {
		Subject string            `json:"subject"`
		Labels  map[string]string `json:"labels,omitempty"`
		Proof   []byte            `json:"proof,omitempty"`
	}
	return PrivacyEventPolicy{PayloadShape: PrivacyPayloadShapeOf[payload](), Rules: []PrivacyFieldRule{
		{Path: "/subject", Mode: PrivacyFieldIdentityExact},
		{Path: "/labels", Mode: PrivacyFieldJSONIdentityValues},
		{Path: "/proof", Mode: PrivacyFieldOpaqueExact},
	}}
}

func TestProtectionPolicyDigestUsesRegisteredImmutableDeclaration(t *testing.T) {
	const kind = "test.a233.protection.policy"
	policy := protectionDigestPolicy()
	if err := RegisterPrivacyEventPolicy(kind, 1, policy); err != nil {
		t.Fatal(err)
	}
	first, err := PrivacyEventPolicyDigest(kind, 1)
	if err != nil || len(first) != 64 || strings.ToLower(first) != first {
		t.Fatalf("declared policy has no stable SHA256 identity: %v", err)
	}
	policy.Rules[0] = PrivacyFieldRule{Path: "/caller-change", Mode: PrivacyFieldOpaqueExact}
	for range 20 {
		again, err := PrivacyEventPolicyDigest(kind, 1)
		if err != nil || again != first {
			t.Fatalf("registered declaration changed through caller mutation or map iteration: %v", err)
		}
	}
	if _, err := PrivacyEventPolicyDigest(kind, 2); err == nil {
		t.Fatal("unknown schema version inherited another version's protection policy")
	}
	if _, err := PrivacyEventPolicyDigest("unregistered.a233", 1); err == nil {
		t.Fatal("unknown event type acquired an undeclared protection policy")
	}
}

func TestProtectionPolicyDigestCommitsFieldClassesAndClosedShapes(t *testing.T) {
	policy := protectionDigestPolicy()
	base, err := protectionPolicyDigest("test.a233.shape", 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PrivacyEventPolicy){
		"field class":         func(p *PrivacyEventPolicy) { p.Rules[0].Mode = PrivacyFieldSubjectToken },
		"field path":          func(p *PrivacyEventPolicy) { p.Rules[0].Path = "/other" },
		"subject disposition": func(p *PrivacyEventPolicy) { p.RejectSubjectData = !p.RejectSubjectData },
		"nullable":            func(p *PrivacyEventPolicy) { p.PayloadShape.root.fields["subject"].nullable = true },
		"scalar type": func(p *PrivacyEventPolicy) {
			p.PayloadShape.root.fields["subject"].scalar = privacyPayloadScalarBoolean
		},
		"required field": func(p *PrivacyEventPolicy) {
			if _, required := p.PayloadShape.root.requiredFields["subject"]; required {
				delete(p.PayloadShape.root.requiredFields, "subject")
			} else {
				if p.PayloadShape.root.requiredFields == nil {
					p.PayloadShape.root.requiredFields = map[string]struct{}{}
				}
				p.PayloadShape.root.requiredFields["subject"] = struct{}{}
			}
		},
		"closed field": func(p *PrivacyEventPolicy) {
			p.PayloadShape.root.fields["extra"] = &privacyPayloadShapeNode{kind: privacyPayloadShapeScalar, scalar: privacyPayloadScalarString}
		},
		"container": func(p *PrivacyEventPolicy) { p.PayloadShape.root.fields["labels"].kind = privacyPayloadShapeArray },
	} {
		t.Run(name, func(t *testing.T) {
			changed := protectionDigestPolicy()
			mutate(&changed)
			digest, err := protectionPolicyDigest("test.a233.shape", 1, changed)
			if err != nil || digest == base {
				t.Fatalf("protection identity omitted %s: %v", name, err)
			}
		})
	}
	for _, input := range []struct {
		kind    string
		version int
	}{{"test.a233.other", 1}, {"test.a233.shape", 2}} {
		if digest, err := protectionPolicyDigest(input.kind, input.version, protectionDigestPolicy()); err != nil || digest == base {
			t.Fatal("protection policy failed to commit event type and version")
		}
	}
}
