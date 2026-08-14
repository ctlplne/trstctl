// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/privacyref"
)

func init() {
	ownerPolicy := PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/id", Mode: PrivacyFieldOpaqueExact},
		{Path: "/kind", Mode: PrivacyFieldOpaqueExact},
		{Path: "/name", Mode: PrivacyFieldSubjectToken},
		{Path: "/email", Mode: PrivacyFieldIdentityExact},
		{Path: "/subject", Mode: PrivacyFieldIdentityExact},
		{Path: "/z", Mode: PrivacyFieldOpaqueExact},
	}}
	approvalPolicy := PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}
	for eventType, policy := range map[string]PrivacyEventPolicy{
		"owner.created":      ownerPolicy,
		"approval.requested": approvalPolicy,
	} {
		if err := RegisterPrivacyEventPolicy(eventType, 1, policy); err != nil {
			panic(err)
		}
	}
}

func TestPseudonymizeLegacyCodeSigningKeyUsesOperationBoundMapping(t *testing.T) {
	const (
		tenantID    = "11111111-1111-1111-1111-111111111111"
		subject     = "alice@example.com"
		operationID = "codesign-22222222-2222-4222-8222-222222222222"
	)
	input := []byte(`{"operation_id":"` + operationID + `","idempotency_key":"release/alice@example.com/42","mode":"key","request_hash":"` + strings.Repeat("a", 64) + `","sealed_command":"Y2lwaGVydGV4dA==","approval":{"request_id":"request-a","intent_digest":"` + strings.Repeat("e", 64) + `","requester":"alice@example.com","resource_kind":"code_signing","resource_id":"codesign:` + strings.Repeat("b", 64) + `","action":"sign","target_version":0,"required_approvals":1,"reason":"requested by alice@example.com","evidence_refs":["ticket:alice@example.com"]}}`)

	rewritten, changed, err := PseudonymizeEventDataForSubject(
		input, tenantID, subject, privacyCodeSigningCommandedEvent, 2,
	)
	if err != nil || !changed {
		t.Fatalf("legacy code-signing rewrite changed=%t err=%v", changed, err)
	}
	if bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("legacy code-signing rewrite retained subject: %s", rewritten)
	}
	var got struct {
		OperationID    string `json:"operation_id"`
		IdempotencyKey string `json:"idempotency_key"`
		Approval       struct {
			Requester    string   `json:"requester"`
			Reason       string   `json:"reason"`
			EvidenceRefs []string `json:"evidence_refs"`
			ResourceID   string   `json:"resource_id"`
		} `json:"approval"`
	}
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	if got.OperationID != operationID ||
		got.IdempotencyKey != codesigningref.LegacyStorageKeyForRaw(operationID, "release/alice@example.com/42") ||
		got.Approval.ResourceID != "codesign:"+strings.Repeat("b", 64) ||
		len(got.Approval.EvidenceRefs) != 1 || got.Approval.EvidenceRefs[0] != "" {
		t.Fatalf("legacy identity rewrite = %+v", got)
	}
	again, changed, err := PseudonymizeEventDataForSubject(
		rewritten, tenantID, subject, privacyCodeSigningCommandedEvent, 2,
	)
	if err != nil || changed || !bytes.Equal(again, rewritten) {
		t.Fatalf("legacy mapping replay changed=%t err=%v\nfirst=%s\nagain=%s", changed, err, rewritten, again)
	}
}

func TestPseudonymizeLegacyCodeSigningRejectsDuplicateIdentityBeforeTransform(t *testing.T) {
	input := []byte(`{"operation_id":"codesign-22222222-2222-4222-8222-222222222222","operation_id":"codesign-33333333-3333-4333-8333-333333333333","idempotency_key":"release/alice@example.com/42","idempotency_key":"safe-key","mode":"key","request_hash":"` + strings.Repeat("a", 64) + `","sealed_command":"Y2lwaGVydGV4dA=="}`)
	if _, _, err := PseudonymizeEventDataForSubject(
		input, "11111111-1111-1111-1111-111111111111", "alice@example.com",
		privacyCodeSigningCommandedEvent, 2,
	); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate legacy identity error = %v", err)
	}
}

func TestPseudonymizePrivacySafeCodeSigningPreservesOneWayIdentityFields(t *testing.T) {
	const subject = "alice@example.com"
	keyRef := "sha256:" + strings.Repeat("a", 64)
	binding := strings.Repeat("b", 64)
	input := []byte(`{"operation_id":"codesign-33333333-3333-4333-8333-333333333333","idempotency_key_ref":"` + keyRef + `","request_binding":"` + binding + `","mode":"key","request_hash":"` + strings.Repeat("c", 64) + `","sealed_command":"Y2lwaGVydGV4dA==","approval":{"request_id":"request-a","intent_digest":"` + strings.Repeat("e", 64) + `","requester":"alice@example.com","resource_kind":"code_signing","resource_id":"codesign:` + strings.Repeat("d", 64) + `","action":"sign","target_version":0,"required_approvals":1,"reason":"requested by alice@example.com","evidence_refs":["ticket:alice@example.com"]}}`)
	rewritten, changed, err := PseudonymizeEventDataForSubject(
		input, "11111111-1111-1111-1111-111111111111", subject,
		privacyCodeSigningCommandedEvent, 3,
	)
	if err != nil || !changed {
		t.Fatalf("v3 code-signing rewrite changed=%t err=%v", changed, err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	var gotRef, gotBinding string
	_ = json.Unmarshal(got["idempotency_key_ref"], &gotRef)
	_ = json.Unmarshal(got["request_binding"], &gotBinding)
	var approval struct {
		EvidenceRefs []string `json:"evidence_refs"`
	}
	_ = json.Unmarshal(got["approval"], &approval)
	if gotRef != keyRef || gotBinding != binding || bytes.Contains(rewritten, []byte(subject)) ||
		len(approval.EvidenceRefs) != 1 || approval.EvidenceRefs[0] != "" {
		t.Fatalf("v3 one-way identity changed: ref=%q binding=%q", gotRef, gotBinding)
	}
}

func TestPseudonymizeActorPreservesNilVersusEmptyRoleShape(t *testing.T) {
	for _, roles := range [][]string{nil, {}} {
		actor := &Actor{Subject: "alice", Roles: roles}
		rewritten, changed := PseudonymizeActorForSubject(actor, "tenant-a", "alice")
		if !changed || (roles == nil) != (rewritten.Roles == nil) || len(rewritten.Roles) != 0 {
			t.Fatalf("roles before=%#v after=%#v changed=%t", roles, rewritten.Roles, changed)
		}
	}
}

func TestPseudonymizeActorUsesWholeIdentityAndStructuredRoleTokens(t *testing.T) {
	actor := &Actor{
		Subject: "a",
		Roles: []string{
			"admin", "delegate:a", "a:release", "data", "team/a/release", "operator",
		},
	}
	rewritten, changed := PseudonymizeActorForSubject(actor, "tenant-a", "a")
	if !changed {
		t.Fatal("actor rewrite reported no change")
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", "a"))
	want := []string{
		"admin", "delegate:" + placeholder, placeholder + ":release",
		"data", "team/" + placeholder + "/release", "operator",
	}
	if rewritten.Subject != placeholder || !reflect.DeepEqual(rewritten.Roles, want) {
		t.Fatalf("actor rewrite = %+v, want subject %q roles %#v", rewritten, placeholder, want)
	}
	if !reflect.DeepEqual(actor.Roles, []string{
		"admin", "delegate:a", "a:release", "data", "team/a/release", "operator",
	}) {
		t.Fatalf("actor input was mutated: %#v", actor.Roles)
	}
}

func TestPseudonymizeActorTreatsExistingPlaceholderSpansAsOpaqueOnRetry(t *testing.T) {
	const subject = "erased"
	existing := privacyref.Placeholder(privacyref.SubjectRef("tenant-other", "someone"))
	actor := &Actor{Subject: subject, Roles: []string{
		"delegate:" + subject,
		"delegate:" + existing + ":release",
		"path/" + subject + "/end",
		"literal:" + subject,
		"noterased",
	}}
	first, changed := PseudonymizeActorForSubject(actor, "tenant-a", subject)
	if !changed {
		t.Fatal("first placeholder-vocabulary rewrite reported no change")
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", subject))
	want := &Actor{Subject: placeholder, Roles: []string{
		"delegate:" + placeholder,
		"delegate:" + existing + ":release",
		"path/" + placeholder + "/end",
		"literal:" + placeholder,
		"noterased",
	}}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("first placeholder-vocabulary rewrite = %+v, want %+v", first, want)
	}
	second, changed := PseudonymizeActorForSubject(first, "tenant-a", subject)
	if changed || !reflect.DeepEqual(second, first) {
		t.Fatalf("placeholder retry changed=%t second=%+v first=%+v", changed, second, first)
	}
}

func TestPseudonymizeEventPolicyPreservesOpaqueShortSubjectBytes(t *testing.T) {
	const eventType = "privacy.policy.opaque.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
		{Path: "/reason", Mode: PrivacyFieldFreeTextClear},
		{Path: "/evidence_refs", Mode: PrivacyFieldFreeTextClear},
		{Path: "/operation_id", Mode: PrivacyFieldOpaqueExact},
		{Path: "/request_binding_hmac_sha256", Mode: PrivacyFieldOpaqueExact},
		{Path: "/sealed", Mode: PrivacyFieldOpaqueExact},
		{Path: "/protocol", Mode: PrivacyFieldOpaqueExact},
	}}); err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"requester":"a","reason":"requested by a","evidence_refs":["ticket:a"],"operation_id":"aa4a","request_binding_hmac_sha256":"aabb","sealed":"YQ==","protocol":"saml"}`)
	rewritten, changed, err := PseudonymizeEventDataForSubject(input, "tenant-a", "a", eventType, 1)
	if err != nil || !changed {
		t.Fatalf("typed rewrite changed=%t err=%v", changed, err)
	}
	var got struct {
		Requester string   `json:"requester"`
		Reason    string   `json:"reason"`
		Evidence  []string `json:"evidence_refs"`
		Operation string   `json:"operation_id"`
		Binding   string   `json:"request_binding_hmac_sha256"`
		Sealed    string   `json:"sealed"`
		Protocol  string   `json:"protocol"`
	}
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", "a"))
	if got.Requester != placeholder || got.Reason != "" || got.Evidence == nil || len(got.Evidence) != 0 {
		t.Fatalf("personal fields were not sanitized with their declared modes: %+v", got)
	}
	if got.Operation != "aa4a" || got.Binding != "aabb" || got.Sealed != "YQ==" || got.Protocol != "saml" {
		t.Fatalf("opaque fields changed for short subject: %+v", got)
	}
}

func TestPseudonymizeEventPolicyRejectsUnknownSubjectFieldAndSchema(t *testing.T) {
	const eventType = "privacy.policy.closed.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		version int
		data    []byte
	}{
		{name: "unknown field", version: 1, data: []byte(`{"requester":"alice","surprise":"alice"}`)},
		{name: "unknown schema", version: 2, data: []byte(`{"requester":"alice"}`)},
		{name: "invalid json", version: 1, data: []byte(`{"requester":"alice"`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := PseudonymizeEventDataForSubject(
				test.data, "tenant-a", "alice", eventType, test.version,
			); err == nil {
				t.Fatal("closed privacy policy accepted raw subject outside its exact schema")
			}
		})
	}
}

func TestPrivacyEventPolicyRejectsOverlappingModes(t *testing.T) {
	tests := []struct {
		name  string
		rules []PrivacyFieldRule
	}{
		{name: "same depth wildcard", rules: []PrivacyFieldRule{
			{Path: "/roles/*", Mode: PrivacyFieldSubjectToken},
			{Path: "/*/*", Mode: PrivacyFieldOpaqueExact},
		}},
		{name: "opaque ancestor first", rules: []PrivacyFieldRule{
			{Path: "/approval", Mode: PrivacyFieldOpaqueExact},
			{Path: "/approval/requester", Mode: PrivacyFieldIdentityExact},
		}},
		{name: "identity descendant first", rules: []PrivacyFieldRule{
			{Path: "/approval/requester", Mode: PrivacyFieldIdentityExact},
			{Path: "/approval", Mode: PrivacyFieldOpaqueExact},
		}},
		{name: "wildcard ancestor", rules: []PrivacyFieldRule{
			{Path: "/items/*", Mode: PrivacyFieldOpaqueExact},
			{Path: "/items/0/requester", Mode: PrivacyFieldIdentityExact},
		}},
	}
	for i, test := range tests {
		err := RegisterPrivacyEventPolicy(fmt.Sprintf("privacy.policy.overlap.test.%d", i), 1,
			PrivacyEventPolicy{Rules: test.rules})
		if err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Errorf("%s: overlapping policy error = %v, want closed overlap refusal", test.name, err)
		}
	}
}

func TestPrivacyEventPolicyRejectsConflictingDuplicateRegistration(t *testing.T) {
	const eventType = "privacy.policy.conflicting-registration.test"
	first := PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}
	if err := RegisterPrivacyEventPolicy(eventType, 1, first); err != nil {
		t.Fatal(err)
	}
	if err := RegisterPrivacyEventPolicy(eventType, 1, first); err != nil {
		t.Fatalf("byte-identical registration was not idempotent: %v", err)
	}
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldOpaqueExact},
	}}); err == nil || !strings.Contains(err.Error(), "already registered differently") {
		t.Fatalf("conflicting registration error = %v", err)
	}
}

func TestTypedPrivacyEventPolicyRejectsAbsentAndIncompatibleRulePaths(t *testing.T) {
	type payload struct {
		Requester string          `json:"requester"`
		Count     int             `json:"count"`
		Metadata  json.RawMessage `json:"metadata"`
	}
	shape := PrivacyPayloadShapeOf[payload]()
	for _, test := range []struct {
		name  string
		rules []PrivacyFieldRule
	}{
		{name: "absent", rules: []PrivacyFieldRule{
			{Path: "/requestor", Mode: PrivacyFieldIdentityExact},
			{Path: "/metadata", Mode: PrivacyFieldOpaqueExact},
		}},
		{name: "identity number", rules: []PrivacyFieldRule{
			{Path: "/requester", Mode: PrivacyFieldIdentityExact},
			{Path: "/count", Mode: PrivacyFieldIdentityExact},
			{Path: "/metadata", Mode: PrivacyFieldOpaqueExact},
		}},
		{name: "open subtree not closed", rules: []PrivacyFieldRule{
			{Path: "/requester", Mode: PrivacyFieldIdentityExact},
			{Path: "/count", Mode: PrivacyFieldOpaqueExact},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := RegisterPrivacyEventPolicy(
				"privacy.policy.typed-rule-shape."+strings.ReplaceAll(test.name, " ", "-"),
				1,
				PrivacyEventPolicy{Rules: test.rules, PayloadShape: shape},
			)
			if err == nil {
				t.Fatal("typed policy accepted a rule/shape mismatch")
			}
		})
	}
}

func TestPrivacyPayloadShapeOneOfRequiresExclusiveClosedAlternatives(t *testing.T) {
	type pathVariant struct {
		Path     string          `json:"path"`
		Version  int             `json:"version"`
		Sealed   []byte          `json:"sealed,omitempty"`
		Envelope json.RawMessage `json:"envelope,omitempty"`
	}
	type nameVariant struct {
		Name                 string    `json:"name"`
		Version              int       `json:"version"`
		Sealed               []byte    `json:"sealed"`
		WrittenAt            time.Time `json:"written_at"`
		RecoveredFromVersion *int      `json:"recovered_from_version,omitempty"`
	}
	const eventType = "privacy.policy.one-of.test"
	policy := PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{
			{Path: "/path", Mode: PrivacyFieldSubjectToken},
			{Path: "/name", Mode: PrivacyFieldSubjectToken},
			{Path: "/version", Mode: PrivacyFieldOpaqueExact},
			{Path: "/sealed", Mode: PrivacyFieldOpaqueExact},
			{Path: "/envelope", Mode: PrivacyFieldOpaqueExact},
			{Path: "/written_at", Mode: PrivacyFieldOpaqueExact},
			{Path: "/recovered_from_version", Mode: PrivacyFieldOpaqueExact},
		},
		PayloadShape: PrivacyPayloadShapeOneOf(
			PrivacyPayloadShapeOf[pathVariant](),
			PrivacyPayloadShapeOf[nameVariant](),
		),
	}
	if err := RegisterPrivacyEventPolicy(eventType, 1, policy); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"path":"secret/privacy-fixture-subject@example.test","version":1,"sealed":"YQ=="}`),
		[]byte(`{"name":"secret/privacy-fixture-subject@example.test","version":1,"sealed":"YQ==","written_at":"2026-08-11T00:00:00Z"}`),
	} {
		if err := validateRegisteredPrivacyEventPayload(data, eventType, 1); err != nil {
			t.Errorf("closed one-of alternative rejected: %v", err)
		}
	}
	for _, data := range [][]byte{
		[]byte(`{"version":1,"sealed":"YQ=="}`),
		[]byte(`{"path":"a","name":"b","version":1,"sealed":"YQ==","written_at":"2026-08-11T00:00:00Z"}`),
		[]byte(`{"name":"a","version":1,"sealed":"YQ==","written_at":"2026-08-11T00:00:00Z","extra":true}`),
	} {
		if err := validateRegisteredPrivacyEventPayload(data, eventType, 1); err == nil {
			t.Errorf("closed one-of accepted zero/mixed/drifted alternative: %s", data)
		}
	}
	if count, err := ValidatePrivacyEventPolicySubjectFixtures(eventType, 1); err != nil || count != 2 {
		t.Fatalf("one-of subject fixture count=%d err=%v, want both discriminated personal paths", count, err)
	}

	type ambiguousA struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
	}
	type ambiguousB struct {
		ID   string `json:"id"`
		Path string `json:"path,omitempty"`
	}
	if err := RegisterPrivacyEventPolicy("privacy.policy.one-of.ambiguous.test", 1, PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{{Path: "/id", Mode: PrivacyFieldOpaqueExact}},
		PayloadShape: PrivacyPayloadShapeOneOf(
			PrivacyPayloadShapeOf[ambiguousA](), PrivacyPayloadShapeOf[ambiguousB](),
		),
	}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("ambiguous one-of registration error = %v", err)
	}
}

func TestCoreProductionPrivacyCatalogExercisesEverySubjectBearingPath(t *testing.T) {
	covered := 0
	for _, schema := range CoreProductionPrivacyEventSchemas() {
		count, err := ValidatePrivacyEventPolicySubjectFixtures(schema.EventType, schema.SchemaVersion)
		if err != nil {
			t.Errorf("core event %s v%d subject fixture: %v", schema.EventType, schema.SchemaVersion, err)
		}
		covered += count
	}
	if covered == 0 {
		t.Fatal("core production privacy catalog exercised no subject-bearing paths")
	}
}

func TestCTSubmissionQueuedPrivacyPolicyRewritesNestedProducerIdentityFields(t *testing.T) {
	const subject = "operator@example.test"
	raw := []byte(`{
		"capability":"CAP-REV-06",
		"requested_by":"operator@example.test",
		"queued_at":"2026-08-11T12:00:00Z",
		"submission_ids":["submission-a"],
		"outbox_keys":["ct.submit:key:certificate:submission-a"],
		"logs":["https://ct.example.test"],
		"fingerprints":["sha256:leaf"],
		"payloads":[{
			"capability":"CAP-REV-06",
			"submission_id":"submission-a",
			"log_url":"https://ct.example.test",
			"entry_type":"certificate",
			"leaf_der":"YmluYXJ5LWxlYWY=",
			"chain_der":["YmluYXJ5LWNoYWlu"],
			"leaf_sha256_fingerprint":"sha256:leaf",
			"subject":"CN=operator@example.test,O=Example",
			"serial_number":"01",
			"requested_by":"operator@example.test",
			"idempotency_key":"stable-authority-key",
			"allow_private_endpoint":true,
			"private_egress_cidrs":["10.0.0.0/24"],
			"submission_profile":"public-tls",
			"operator_correlation_ref":"ticket/operator@example.test",
			"queued_at":"2026-08-11T12:00:00Z"
		}]
	}`)
	rewritten, changed, err := PseudonymizeEventDataForSubject(
		raw, "tenant-a", subject, "ct.submission.queued", 1,
	)
	if err != nil || !changed {
		t.Fatalf("CT queued rewrite changed=%t err=%v data=%s", changed, err, rewritten)
	}
	if bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("CT queued rewrite retained raw identity: %s", rewritten)
	}
	var decoded struct {
		RequestedBy string `json:"requested_by"`
		Payloads    []struct {
			LeafDER                []byte   `json:"leaf_der"`
			ChainDER               [][]byte `json:"chain_der"`
			Subject                string   `json:"subject"`
			RequestedBy            string   `json:"requested_by"`
			OperatorCorrelationRef string   `json:"operator_correlation_ref"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal(rewritten, &decoded); err != nil || len(decoded.Payloads) != 1 {
		t.Fatalf("decode rewritten CT queued payload: payload=%+v err=%v", decoded, err)
	}
	want := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", subject))
	payload := decoded.Payloads[0]
	if decoded.RequestedBy != want || payload.RequestedBy != want ||
		payload.Subject != "CN="+want+",O=Example" ||
		payload.OperatorCorrelationRef != "ticket/"+want {
		t.Fatalf("CT queued nested rewrite = top requester %q payload %+v, want %q", decoded.RequestedBy, payload, want)
	}
	if string(payload.LeafDER) != "binary-leaf" || len(payload.ChainDER) != 1 ||
		string(payload.ChainDER[0]) != "binary-chain" {
		t.Fatalf("CT queued rewrite changed binary leaves: %+v", payload)
	}
}

func TestCTSubmissionQueuedPrivacyPolicyRejectsUnknownNestedProducerField(t *testing.T) {
	data := []byte(`{
		"capability":"CAP-REV-06",
		"queued_at":"2026-08-11T12:00:00Z",
		"submission_ids":["submission-a"],
		"outbox_keys":["outbox-a"],
		"logs":["https://ct.example.test"],
		"fingerprints":["sha256:leaf"],
		"payloads":[{
			"capability":"CAP-REV-06",
			"submission_id":"submission-a",
			"log_url":"https://ct.example.test",
			"entry_type":"certificate",
			"leaf_der":"YmluYXJ5LWxlYWY=",
			"leaf_sha256_fingerprint":"sha256:leaf",
			"subject":"CN=operator@example.test",
			"serial_number":"01",
			"idempotency_key":"stable-authority-key",
			"queued_at":"2026-08-11T12:00:00Z",
			"new_identity_field":"operator@example.test"
		}]
	}`)
	if _, _, err := PseudonymizeEventDataForSubject(
		data, "tenant-a", "operator@example.test", "ct.submission.queued", 1,
	); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
		t.Fatalf("CT queued policy accepted unknown nested producer field: %v", err)
	}
}

func TestCoreHistoricalCollisionPoliciesAcceptOnlyExactProducerVariants(t *testing.T) {
	tests := []struct {
		name, eventType string
		valid           []string
		invalid         []string
	}{
		{
			name: "secret version written", eventType: "secret.version.written",
			valid: []string{
				`{"path":"kv/team/alice@example.test","version":1,"sealed":"YQ==","envelope":{"wrapped_dek":null,"dek_nonce":null,"nonce":null,"ciphertext":null}}`,
				`{"path":"kv/team/alice@example.test","version":1,"envelope":{"wrapped_dek":"YQ==","dek_nonce":"Yg==","nonce":"Yw==","ciphertext":"ZA=="}}`,
				`{"name":"team/alice@example.test","version":2,"sealed":"YQ==","written_at":"2026-08-11T00:00:00Z"}`,
				`{"name":"team/alice@example.test","version":3,"sealed":null,"written_at":"2026-08-11T00:00:00Z","recovered_from_version":1}`,
			},
			invalid: []string{
				`{"path":"a","version":1}`,
				`{"path":"a","version":1,"sealed":"YQ=="}`,
				`{"path":"a","version":1,"envelope":{"wrapped_dek":null,"dek_nonce":null,"nonce":null,"ciphertext":null}}`,
				`{"path":"a","name":"b","version":1,"sealed":"YQ==","written_at":"2026-08-11T00:00:00Z"}`,
				`{"name":"a","version":1,"sealed":"YQ=="}`,
			},
		},
		{
			name: "secret sync delivered", eventType: "secret.sync.delivered",
			valid: []string{
				`{"key":"kv/alice@example.test","target":"cluster/alice@example.test"}`,
				`{"id":"job-a","attempts":2}`,
				`{"id":"job-a","attempts":2,"remote_version":"version-a"}`,
			},
			invalid: []string{
				`{"key":"kv/a","target":"cluster-a","id":"job-a","attempts":2}`,
				`{"id":"job-a"}`,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, data := range test.valid {
				if err := validateRegisteredPrivacyEventPayload([]byte(data), test.eventType, 1); err != nil {
					t.Errorf("exact producer variant rejected: %v\npayload=%s", err, data)
				}
			}
			for _, data := range test.invalid {
				if err := validateRegisteredPrivacyEventPayload([]byte(data), test.eventType, 1); err == nil {
					t.Errorf("mixed/incomplete producer variant accepted: %s", data)
				}
			}
		})
	}
}

func TestPrivacyRewriteRejectsMalformedHistoricalOneOfPayloadsBeforeRewrite(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{
			name: "mixed historical variants",
			data: []byte(`{"key":"a","target":"safe","id":"job","attempts":2}`),
		},
		{
			name: "missing required field",
			data: []byte(`{"key":"a"}`),
		},
		{
			name: "bad nullability",
			data: []byte(`{"key":"a","target":null}`),
		},
		{
			name: "unknown field",
			data: []byte(`{"key":"a","target":"safe","extra":"safe"}`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := PseudonymizeEventDataForSubject(
				test.data, "tenant-a", "a", "secret.sync.delivered", 1,
			); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
				t.Fatalf("malformed historical payload rewrite error = %v", err)
			}
		})
	}

	rewritten, changed, err := PseudonymizeEventDataForSubject(
		[]byte(`{"key":"team/a","target":"safe"}`),
		"tenant-a", "a", "secret.sync.delivered", 1,
	)
	if err != nil || !changed {
		t.Fatalf("valid historical payload rewrite changed=%t err=%v", changed, err)
	}
	if err := validateRegisteredPrivacyEventPayload(
		rewritten, "secret.sync.delivered", 1,
	); err != nil {
		t.Fatalf("post-rewrite payload left its exact historical shape: %v", err)
	}
}

func TestRequiredPrivacyEventPolicyRejectsUnknownAppendSchemaBeforePublish(t *testing.T) {
	log := &Log{requirePrivacyEventPolicies: true}
	for _, event := range []Event{
		{Type: "privacy.policy.not-registered", TenantID: "tenant-a"},
		{Type: "owner.created", TenantID: "tenant-a", SchemaVersion: 999},
	} {
		if _, err := log.Append(context.Background(), event); err == nil ||
			!strings.Contains(err.Error(), "no registered privacy policy") {
			t.Fatalf("unknown production append schema error = %v", err)
		}
	}
}

func TestRequiredPrivacyPolicyRejectsSameVersionAppendAndImportSchemaDrift(t *testing.T) {
	const eventType = "privacy.policy.required-schema-drift.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
		{Path: "/count", Mode: PrivacyFieldOpaqueExact},
		{Path: "/items/*", Mode: PrivacyFieldSubjectToken},
	}}); err != nil {
		t.Fatal(err)
	}
	log := &Log{requirePrivacyEventPolicies: true}
	invalid := []struct {
		name string
		data []byte
	}{
		{name: "unknown scalar", data: []byte(`{"requester":"safe","extra":"value"}`)},
		{name: "unknown object", data: []byte(`{"requester":"safe","extra":{}}`)},
		{name: "unknown array", data: []byte(`{"requester":"safe","extra":[]}`)},
		{name: "identity shape", data: []byte(`{"requester":{}}`)},
		{name: "array shape", data: []byte(`{"items":{}}`)},
		{name: "duplicate key", data: []byte(`{"requester":"first","requester":"second"}`)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			appendEvent := Event{Type: eventType, TenantID: "tenant-a", Data: test.data}
			if _, err := log.Append(context.Background(), appendEvent); err == nil {
				t.Fatal("same-version append schema drift reached publish")
			}
			importEvent := appendEvent
			importEvent.ID = "privacy-import-" + strings.ReplaceAll(test.name, " ", "-")
			importEvent.Time = time.Unix(1_700_000_000, 0).UTC()
			if _, err := log.Import(context.Background(), importEvent); err == nil {
				t.Fatal("same-version import schema drift reached publish")
			}
		})
	}
	if err := validateRegisteredPrivacyEventPayload(
		[]byte(`{"requester":"safe","count":3,"items":["worker-a","worker-b"]}`),
		eventType, 1,
	); err != nil {
		t.Fatalf("declared same-version payload rejected: %v", err)
	}
}

func TestTypedPrivacyPayloadShapeRejectsScalarTypeDrift(t *testing.T) {
	type payload struct {
		Requester string `json:"requester"`
		Count     int    `json:"count"`
		Enabled   bool   `json:"enabled"`
	}
	const eventType = "privacy.policy.typed-shape.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{
			{Path: "/requester", Mode: PrivacyFieldIdentityExact},
		},
		PayloadShape: PrivacyPayloadShapeOf[payload](),
	}); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"requester":"safe","count":"1","enabled":true}`),
		[]byte(`{"requester":"safe","count":1,"enabled":"true"}`),
	} {
		if err := validateRegisteredPrivacyEventPayload(data, eventType, 1); err == nil ||
			!strings.Contains(err.Error(), "changed scalar") {
			t.Fatalf("typed scalar drift error = %v", err)
		}
	}
}

func TestPrivacyPayloadShapeOfMatchesEncodingJSONOmitEmptyPresence(t *testing.T) {
	type nested struct {
		Value string `json:"value,omitempty"`
	}
	type payload struct {
		RequiredStruct nested    `json:"required_struct,omitempty"`
		RequiredTime   time.Time `json:"required_time,omitempty"`
		OptionalPtr    *nested   `json:"optional_ptr,omitempty"`
		OptionalSlice  []string  `json:"optional_slice,omitempty"`
	}

	const eventType = "privacy.policy.omitempty-wire-presence.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{
		PayloadShape:      PrivacyPayloadShapeOf[payload](),
		RejectSubjectData: true,
	}); err != nil {
		t.Fatal(err)
	}

	wire, err := json.Marshal(payload{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["required_struct"]; !ok {
		t.Fatalf("encoding/json omitted a non-pointer struct: %s", wire)
	}
	if _, ok := fields["required_time"]; !ok {
		t.Fatalf("encoding/json omitted a non-pointer time: %s", wire)
	}
	for _, name := range []string{"optional_ptr", "optional_slice"} {
		if _, ok := fields[name]; ok {
			t.Fatalf("encoding/json retained empty %s: %s", name, wire)
		}
	}
	if err := validateRegisteredPrivacyEventPayload(wire, eventType, 1); err != nil {
		t.Fatalf("producer wire form rejected: %v", err)
	}
	if err := validateRegisteredPrivacyEventPayload([]byte(`{}`), eventType, 1); err == nil ||
		!strings.Contains(err.Error(), "required") {
		t.Fatalf("missing non-pointer omitempty fields error = %v", err)
	}
}

func TestPrivacyClosingRulesPreserveTypedNodeKindAndNullability(t *testing.T) {
	type nested struct {
		Name     string `json:"name"`
		Optional string `json:"optional,omitempty"`
	}
	type payload struct {
		Ciphertext []byte            `json:"ciphertext"`
		Reason     string            `json:"reason"`
		Metadata   map[string]string `json:"metadata"`
		Required   string            `json:"required"`
		Optional   *string           `json:"optional"`
		Nested     nested            `json:"nested"`
	}
	const eventType = "privacy.policy.typed-closing-node.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{
			{Path: "/ciphertext", Mode: PrivacyFieldOpaqueExact},
			{Path: "/reason", Mode: PrivacyFieldFreeTextClear},
			{Path: "/metadata", Mode: PrivacyFieldJSONIdentityValues},
			{Path: "/required", Mode: PrivacyFieldOpaqueExact},
			{Path: "/optional", Mode: PrivacyFieldOpaqueExact},
			{Path: "/nested/name", Mode: PrivacyFieldOpaqueExact},
			{Path: "/nested/optional", Mode: PrivacyFieldOpaqueExact},
		},
		PayloadShape: PrivacyPayloadShapeOf[payload](),
	}); err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"ciphertext":"Y2lwaGVydGV4dA==","reason":"safe","metadata":{"principal":"safe"},"required":"safe","optional":null,"nested":{"name":"safe"}}`)
	if err := validateRegisteredPrivacyEventPayload(valid, eventType, 1); err != nil {
		t.Fatalf("typed closing rules rejected a nullable payload: %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "opaque byte slice became object", data: []byte(`{"ciphertext":{},"reason":"safe","metadata":{},"required":"safe","optional":null,"nested":{"name":"safe"}}`)},
		{name: "free text string became array", data: []byte(`{"ciphertext":"YQ==","reason":[],"metadata":{},"required":"safe","optional":null,"nested":{"name":"safe"}}`)},
		{name: "JSON map became scalar", data: []byte(`{"ciphertext":"YQ==","reason":"safe","metadata":"safe","required":"safe","optional":null,"nested":{"name":"safe"}}`)},
		{name: "required value became null", data: []byte(`{"ciphertext":"YQ==","reason":"safe","metadata":{},"required":null,"optional":null,"nested":{"name":"safe"}}`)},
		{name: "required field missing", data: []byte(`{"ciphertext":"YQ==","reason":"safe","metadata":{},"optional":null,"nested":{"name":"safe"}}`)},
		{name: "required nested object empty", data: []byte(`{"ciphertext":"YQ==","reason":"safe","metadata":{},"required":"safe","optional":null,"nested":{}}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRegisteredPrivacyEventPayload(test.data, eventType, 1); err == nil {
				t.Fatal("typed closing rule accepted node-kind or nullability drift")
			}
		})
	}
}

func TestCoreProductionPrivacyCatalogRejectsLeafKindAndRequiredFieldDrift(t *testing.T) {
	valid := []byte(`{"agent_id":"agent-a","credential_id":"credential-a","subject":"spiffe://tenant/workload-a"}`)
	if err := validateRegisteredPrivacyEventPayload(valid, "agent.identity.issued", 1); err != nil {
		t.Fatalf("producer-aligned core payload rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "identity leaf became object", data: []byte(`{"agent_id":{},"credential_id":"credential-a","subject":"spiffe://tenant/workload-a"}`)},
		{name: "opaque leaf became array", data: []byte(`{"agent_id":"agent-a","credential_id":[],"subject":"spiffe://tenant/workload-a"}`)},
		{name: "required field missing", data: []byte(`{"agent_id":"agent-a","subject":"spiffe://tenant/workload-a"}`)},
		{name: "empty payload", data: []byte(`{}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRegisteredPrivacyEventPayload(test.data, "agent.identity.issued", 1); err == nil {
				t.Fatal("core production catalog accepted same-version leaf or presence drift")
			}
		})
	}
}

func TestPrivacyScalarFieldModesRejectNestedShapeDrift(t *testing.T) {
	for i, mode := range []PrivacyFieldMode{PrivacyFieldIdentityExact, PrivacyFieldSubjectToken} {
		eventType := fmt.Sprintf("privacy.policy.scalar-shape.test.%d", i)
		if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
			{Path: "/requester", Mode: mode},
		}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := PseudonymizeEventDataForSubject(
			[]byte(`{"requester":{"nested":"alice"}}`), "tenant-a", "alice", eventType, 1,
		); err == nil || !strings.Contains(err.Error(), "not a string") {
			t.Errorf("mode %q nested-shape error = %v", mode, err)
		}
	}
}

func TestPrivacyIdentityExactRejectsSubjectBearingShapeDrift(t *testing.T) {
	const eventType = "privacy.policy.identity-exact-shape.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PseudonymizeEventDataForSubject(
		[]byte(`{"requester":"spiffe://tenant/alice"}`), "tenant-a", "alice", eventType, 1,
	); err == nil || !strings.Contains(err.Error(), "non-exact") {
		t.Fatalf("subject-bearing exact-identity shape error = %v", err)
	}
}

func TestPrivacyJSONIdentityValuesRejectSubjectBearingShapeDrift(t *testing.T) {
	const eventType = "privacy.policy.json-identity-shape.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/metadata", Mode: PrivacyFieldJSONIdentityValues},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PseudonymizeEventDataForSubject(
		[]byte(`{"metadata":{"principal":"spiffe://tenant/alice"}}`),
		"tenant-a", "alice", eventType, 1,
	); err == nil || !strings.Contains(err.Error(), "non-exact") {
		t.Fatalf("subject-bearing JSON identity shape error = %v", err)
	}
}

func TestPseudonymizeEventPolicyRejectsDuplicateJSONKeysBeforeCollapse(t *testing.T) {
	const eventType = "privacy.policy.duplicate-key.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"requester":"alice","requester":"safe"}`),
		[]byte(`{"nested":{"requester":"alice","requester":"safe"}}`),
	} {
		if _, _, err := PseudonymizeEventDataForSubject(
			data, "tenant-a", "alice", eventType, 1,
		); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate-key payload error = %v", err)
		}
	}
}

func TestPseudonymizeEventPolicyRejectsObjectKeyCollisionInEitherOrder(t *testing.T) {
	const eventType = "privacy.policy.key-collision.test"
	if privacyPathMatches([]string{"*"}, []string{"@key"}) ||
		privacyRulePathsOverlap([]string{"*"}, []string{"@key"}) {
		t.Fatal("dynamic-object value wildcard shadows the synthetic key coordinate")
	}
	if privacyPathMatches([]string{"0"}, []string{"*"}) {
		t.Fatal("an explicit value segment matched a runtime wildcard path")
	}
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{
			{Path: "/@key", Mode: PrivacyFieldIdentityExact},
			{Path: "/*", Mode: PrivacyFieldOpaqueExact},
		},
		PayloadShape: PrivacyPayloadShapeOf[map[string]string](),
	}); err != nil {
		t.Fatal(err)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef("tenant-a", "alice"))
	if err := validateRegisteredPrivacyEventPayload(
		[]byte(`{"safe":1}`), eventType, 1,
	); err == nil || !strings.Contains(err.Error(), "scalar") {
		t.Fatalf("typed dynamic-object value drift error = %v", err)
	}
	rewritten, changed, err := PseudonymizeEventDataForSubject(
		[]byte(`{"alice":"opaque-value"}`), "tenant-a", "alice", eventType, 1,
	)
	if err != nil || !changed {
		t.Fatalf("dynamic-object key rewrite changed=%t err=%v", changed, err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(rewritten, &decoded); err != nil ||
		decoded[placeholder] != "opaque-value" || len(decoded) != 1 {
		t.Fatalf("dynamic-object key rewrite = %v err=%v", decoded, err)
	}
	for _, data := range [][]byte{
		[]byte(`{"alice":"first","` + placeholder + `":"second"}`),
		[]byte(`{"` + placeholder + `":"second","alice":"first"}`),
	} {
		if _, _, err := PseudonymizeEventDataForSubject(
			data, "tenant-a", "alice", eventType, 1,
		); err == nil || !strings.Contains(err.Error(), "collides") {
			t.Fatalf("object-key collision error = %v", err)
		}
	}
}

func TestSubjectErasurePolicyFailureDoesNotCreateTargetGeneration(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID  = "11111111-1111-1111-1111-111111111111"
		eventType = "privacy.policy.preflight.test"
	)
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{Rules: []PrivacyFieldRule{
		{Path: "/requester", Mode: PrivacyFieldIdentityExact},
	}}); err != nil {
		t.Fatal(err)
	}
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "closed-policy-source", Type: eventType, TenantID: tenantID,
		Data: []byte(`{"requester":"a","unknown":"a"}`),
	}); err != nil {
		t.Fatal(err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created := false
	log.createRewriteTargetTestHook = func() error {
		created = true
		return errors.New("target creation must not run")
	}
	if err := log.PseudonymizeSubject(ctx, tenantID, "a", rewriteProofOptions(t)...); err == nil {
		t.Fatal("subject rewrite accepted an undeclared personal field")
	}
	if created {
		t.Fatal("closed-policy failure reached target creation")
	}
	afterName, _, err := log.resolveActiveStream(ctx)
	if err != nil || afterName != beforeName {
		t.Fatalf("policy preflight changed active generation from %q to %q: %v", beforeName, afterName, err)
	}
	if state, err := log.findRewriteStreams(ctx); err != nil || state != nil {
		t.Fatalf("policy preflight left rewrite state=%+v err=%v", state, err)
	}
}

func TestSubjectErasureMalformedHistoricalOneOfDoesNotCreateTargetGeneration(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "historical-one-of-source", Type: "secret.sync.delivered", TenantID: tenantID,
		Data: []byte(`{"key":"a","target":"safe","id":"job","attempts":2}`),
	}); err != nil {
		t.Fatal(err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created := false
	log.createRewriteTargetTestHook = func() error {
		created = true
		return errors.New("target creation must not run")
	}
	if err := log.PseudonymizeSubject(ctx, tenantID, "a", rewriteProofOptions(t)...); err == nil ||
		!strings.Contains(err.Error(), "pre-rewrite payload") {
		t.Fatalf("malformed OneOf subject rewrite error = %v", err)
	}
	if created {
		t.Fatal("malformed OneOf preflight reached target generation creation")
	}
	afterName, _, err := log.resolveActiveStream(ctx)
	if err != nil || afterName != beforeName {
		t.Fatalf("OneOf preflight changed active generation from %q to %q: %v", beforeName, afterName, err)
	}
	if state, err := log.findRewriteStreams(ctx); err != nil || state != nil {
		t.Fatalf("OneOf preflight left rewrite state=%+v err=%v", state, err)
	}
}

func TestPseudonymizeDataBytesRewritesEscapedJSONStringsWithoutReformatting(t *testing.T) {
	subject := "alice\"\\\n☃😀"
	const placeholder = "subject-ref:erased"
	input := []byte("{\n" +
		"  \"untouched\\u004bey\" : \"raw\\u003ctag\", \n" +
		"  \"target\" : \"before alice\\u0022\\u005c\\u000a\\u2603\\ud83d\\ude00 after\\u004b\\/\\u003c\",\n" +
		"  \"array\": [ \"alice\\\"\\\\\\n☃😀\", \"keep\\u00e9\" ],\n" +
		"  \"alice\\u0022\\u005c\\u000a\\u2603\\ud83d\\ude00\" : \"key-remains\"\n" +
		"}")
	want := []byte("{\n" +
		"  \"untouched\\u004bey\" : \"raw\\u003ctag\", \n" +
		"  \"target\" : \"before subject-ref:erased after\\u004b\\/\\u003c\",\n" +
		"  \"array\": [ \"subject-ref:erased\", \"keep\\u00e9\" ],\n" +
		"  \"subject-ref:erased\" : \"key-remains\"\n" +
		"}")

	got, changed := pseudonymizeDataBytes(input, subject, placeholder)
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for escaped semantic values")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("escaped JSON rewrite changed an unrelated raw span:\n got=%q\nwant=%q", got, want)
	}
}

func TestPseudonymizeDataBytesRewritesEscapedJSONObjectKey(t *testing.T) {
	input := []byte(`{ "owner\u0040example.com" : "keep\u003craw" }`)
	want := []byte(`{ "subject-ref:erased" : "keep\u003craw" }`)

	got, changed := pseudonymizeDataBytes(input, "owner@example.com", "subject-ref:erased")
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for escaped object key")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("escaped object-key rewrite = %q, want exact span-preserving result %q", got, want)
	}
}

func TestPseudonymizeDataBytesInvalidJSONUsesRawFallback(t *testing.T) {
	input := []byte(`prefix alice@example.com {"escaped":"alice\u0040example.com"`)
	want := []byte(`prefix subject-ref:erased {"escaped":"alice\u0040example.com"`)

	got, changed := pseudonymizeDataBytes(input, "alice@example.com", "subject-ref:erased")
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for raw non-JSON subject")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("invalid JSON fallback = %q, want exact raw replacement %q", got, want)
	}
}

func TestPseudonymizeDataBytesRewritesBase64EncodedNestedJSON(t *testing.T) {
	const subject = "alice@example.com"
	const placeholder = "subject-ref:erased"
	type sideEffect struct {
		Destination string `json:"destination"`
		Payload     []byte `json:"payload"`
	}
	type envelope struct {
		Requester  string     `json:"requester"`
		SideEffect sideEffect `json:"side_effect"`
		Opaque     string     `json:"opaque"`
	}
	inner := []byte(`{"requester":"alice@example.com","profile":"prod/alice@example.com","keep":"unchanged"}`)
	// DecodeString accepts line breaks, but this is deliberately not the canonical
	// encoding/json []byte representation. It must remain an unrelated opaque value.
	nonCanonicalOpaque := base64.StdEncoding.EncodeToString(inner)
	nonCanonicalOpaque = nonCanonicalOpaque[:4] + "\n" + nonCanonicalOpaque[4:]
	input, err := json.Marshal(envelope{
		Requester:  subject,
		SideEffect: sideEffect{Destination: "ca.issue", Payload: inner},
		Opaque:     nonCanonicalOpaque,
	})
	if err != nil {
		t.Fatal(err)
	}

	rewritten, changed := pseudonymizeDataBytes(input, subject, placeholder)
	if !changed {
		t.Fatal("base64 nested JSON was treated as opaque")
	}
	if bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("outer rewritten JSON retained raw subject: %s", rewritten)
	}
	var got envelope
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatalf("decode rewritten envelope: %v", err)
	}
	if got.Requester != placeholder || got.SideEffect.Destination != "ca.issue" ||
		got.Opaque != nonCanonicalOpaque ||
		bytes.Contains(got.SideEffect.Payload, []byte(subject)) ||
		!bytes.Contains(got.SideEffect.Payload, []byte("prod/"+placeholder)) ||
		!bytes.Contains(got.SideEffect.Payload, []byte(`"keep":"unchanged"`)) {
		t.Fatalf("rewritten nested lifecycle body = outer requester %q side effect %+v payload %s",
			got.Requester, got.SideEffect, got.SideEffect.Payload)
	}
}

func TestNestedJSONBytesPolicyRewritesCanonicalCommandAndRejectsMalformedHistory(t *testing.T) {
	const (
		eventType = "privacy.policy.nested-json-bytes.test"
		tenantID  = "11111111-1111-1111-1111-111111111111"
		subject   = "alice@example.com"
	)
	type envelope struct {
		Payload []byte `json:"payload"`
	}
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{
		Rules:        []PrivacyFieldRule{{Path: "/payload", Mode: PrivacyFieldNestedJSONBytes}},
		PayloadShape: PrivacyPayloadShapeOf[envelope](),
	}); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(envelope{Payload: []byte(
		`{"requester":"alice@example.com","profile":"prod/alice@example.com","keep":"unchanged"}`,
	)})
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := applyRegisteredPrivacyEventPolicy(input, tenantID, subject, eventType, 1)
	if err != nil || !changed {
		t.Fatalf("nested command rewrite = changed %t err %v", changed, err)
	}
	var got envelope
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	if bytes.Contains(got.Payload, []byte(subject)) ||
		!bytes.Contains(got.Payload, []byte(`"profile":"prod/`+placeholder+`"`)) ||
		!bytes.Contains(got.Payload, []byte(`"keep":"unchanged"`)) {
		t.Fatalf("rewritten nested command = %s", got.Payload)
	}

	malformed := []byte(`{"payload":"e30=\n"}`)
	if _, _, err := applyRegisteredPrivacyEventPolicy(malformed, tenantID, subject, eventType, 1); err == nil ||
		!strings.Contains(err.Error(), "canonical base64") {
		t.Fatalf("malformed nested command error = %v, want canonical base64 refusal", err)
	}

	shortInput, err := json.Marshal(envelope{Payload: []byte(`{"destination":"ca.issue","requester":"a"}`)})
	if err != nil {
		t.Fatal(err)
	}
	shortRewritten, changed, err := applyRegisteredPrivacyEventPolicy(shortInput, tenantID, "a", eventType, 1)
	if err != nil || !changed {
		t.Fatalf("short-subject nested rewrite = changed %t err %v", changed, err)
	}
	if err := json.Unmarshal(shortRewritten, &got); err != nil {
		t.Fatal(err)
	}
	shortPlaceholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, "a"))
	if !bytes.Contains(got.Payload, []byte(`"destination":"ca.issue"`)) ||
		!bytes.Contains(got.Payload, []byte(`"requester":"`+shortPlaceholder+`"`)) {
		t.Fatalf("short-subject nested rewrite corrupted opaque token: %s", got.Payload)
	}
}

func TestSubjectErasurePseudonymizeSubjectSecureRewritesHotLogStorage(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	originalData := []byte("{\n  \"z\": \"keep\\\\u003cbytes\", \"name\" : \"alice@example.com\"\n}")
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	actorCtx := ContextWithActor(ctx, Actor{
		Subject: subject,
		Roles: []string{
			"admin", "delegate:" + subject, subject + ":release", "admin",
		},
	})
	if _, err := log.Append(actorCtx, Event{
		Type:     "owner.created",
		TenantID: tenantID,
		Data:     originalData,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if raw := rawStreamBytes(t, log); !bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("expected raw hot-log storage to contain the subject before erasure, got %s", raw)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, subject, rewriteProofOptions(t)...); err != nil {
		t.Fatalf("PseudonymizeSubject: %v", err)
	}
	raw := rawStreamBytes(t, log)
	if bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("hot-log storage still contains erased subject bytes: %s", raw)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	if !bytes.Contains(raw, []byte(placeholder)) {
		t.Fatalf("hot-log storage = %s, want erasure placeholder %q", raw, placeholder)
	}

	var got []Event
	if err := log.Replay(ctx, 0, func(e Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("replayed %d events, want sanitized event plus continuity receipt", len(got))
	}
	if got[0].Actor == nil || got[0].Actor.Subject != placeholder {
		t.Fatalf("replayed actor = %+v, want placeholder %q", got[0].Actor, placeholder)
	}
	wantRoles := []string{
		"admin", "delegate:" + placeholder, placeholder + ":release", "admin",
	}
	if !reflect.DeepEqual(got[0].Actor.Roles, wantRoles) {
		t.Fatalf("replayed actor roles = %v, want exact ordered rewrite %v", got[0].Actor.Roles, wantRoles)
	}
	if bytes.Contains(got[0].Data, []byte(subject)) || !bytes.Contains(got[0].Data, []byte(placeholder)) {
		t.Fatalf("replayed data = %s, want placeholder and no raw subject", got[0].Data)
	}
	var payload struct {
		Name string `json:"name"`
		Z    string `json:"z"`
	}
	if err := json.Unmarshal(got[0].Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Name != placeholder || payload.Z != `keep\u003cbytes` {
		t.Fatalf("pseudonymized payload changed an undeclared/opaque value: %+v", payload)
	}
	if got[1].Type != "tenant.data.rewrite.receipt" {
		t.Fatalf("replayed second event type = %q, want continuity receipt", got[1].Type)
	}
}

func TestSubjectErasureNoOpKeepsGenerationSequenceAndMetadata(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(ctx, Event{
		Type: "owner.created", TenantID: tenantID, Data: []byte(`{"subject":"bob@example.com"}`),
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve before no-op: %v", err)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, "alice@example.com", rewriteProofOptions(t)...); err != nil {
		t.Fatalf("PseudonymizeSubject no-op: %v", err)
	}
	afterName, stream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve after no-op: %v", err)
	}
	if afterName != beforeName {
		t.Fatalf("no-op switched generation from %q to %q", beforeName, afterName)
	}
	info, err := log.infoForStream(ctx, stream)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.State.LastSeq != event.Sequence {
		t.Fatalf("no-op consumed sequence: head=%d want=%d", info.State.LastSeq, event.Sequence)
	}
	for key := range info.Config.Metadata {
		if strings.HasPrefix(key, "trstctl.rewrite.") {
			t.Fatalf("no-op left rewrite metadata %q", key)
		}
	}
}

func TestSubjectErasurePseudonymizeSubjectFailsClosedWithoutProofCallbacks(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{
		Type: "owner.created", TenantID: tenantID,
		Data: []byte(`{"subject":"alice@example.com"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := rawStreamBytes(t, log)

	if err := log.PseudonymizeSubject(ctx, tenantID, subject); err == nil {
		t.Fatal("PseudonymizeSubject accepted missing continuity proof callbacks")
	}
	if after := rawStreamBytes(t, log); !bytes.Equal(after, before) {
		t.Fatalf("hot log changed despite fail-closed proof wall:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestPseudonymizeSubjectCompletionStaysInsideRewriteOperationLock(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "completion-source", Type: "owner.created", TenantID: tenantID,
		Data: []byte(`{"subject":"alice@example.com"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	competingEntered := make(chan struct{})
	competingDone := make(chan error, 1)
	var completionCalls int
	err = log.PseudonymizeSubjectWithCompletion(
		ctx,
		tenantID,
		subject,
		func(completionCtx context.Context) error {
			completionCalls++
			go func() { // #nosec G118 -- test goroutine lifecycle is managed by the test (CWE-664)
				competingDone <- log.WithHistoryOperation(
					context.Background(),
					func(context.Context) error {
						close(competingEntered)
						return nil
					},
				)
			}()
			select {
			case <-competingEntered:
				return errors.New("competing history operation entered before completion returned")
			case <-time.After(50 * time.Millisecond):
			}
			_, err := log.Append(completionCtx, Event{
				ID: "privacy-completion", Type: "privacy.subject.erased",
				TenantID: tenantID, Data: []byte(`{"completed":true}`),
			})
			return err
		},
		rewriteProofOptions(t)...,
	)
	if err != nil {
		t.Fatalf("PseudonymizeSubjectWithCompletion: %v", err)
	}
	if completionCalls != 1 {
		t.Fatalf("completion calls = %d, want 1", completionCalls)
	}
	select {
	case err := <-competingDone:
		if err != nil {
			t.Fatalf("competing history operation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("competing history operation did not enter after completion released lock")
	}
}

func TestPseudonymizeSubjectPreparationFollowsSignedStagingAndNoOpRetryStillCompletes(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	coordinator := newPrivacyPreparationTestCoordinator()
	log, err := Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	},
		WithHistoryRewriteCoordinator(coordinator),
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "preparation-source", Type: "approval.requested", TenantID: tenantID,
		Data: []byte(`{"requester":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, completed int
	run := func() error {
		return log.PseudonymizeSubjectWithPreparationAndCompletion(
			ctx, tenantID, subject,
			func(_ context.Context, report TenantDataRewriteReport) error {
				prepared++
				if report.OperationID == "" || report.TargetGeneration == "" {
					t.Fatal("preparation did not receive a durable generation identity")
				}
				if prepared == 1 {
					source, err := log.js.Stream(ctx, report.SourceStream)
					if err != nil {
						t.Fatalf("open frozen source during preparation: %v", err)
					}
					raw, err := source.GetMsg(ctx, 1)
					if err != nil {
						t.Fatalf("read frozen source during preparation: %v", err)
					}
					stored, err := decodeStored(raw.Data, raw.Sequence)
					if err != nil || !bytes.Contains(stored.Data, []byte(subject)) {
						t.Fatalf("preparation ran after source scrub: event=%+v err=%v", stored, err)
					}
				}
				return nil
			},
			func(context.Context) error {
				completed++
				canonical, found, err := log.EventByID(ctx, "preparation-source")
				if err != nil || !found || bytes.Contains(canonical.Data, []byte(subject)) {
					t.Fatalf("completion ran before pseudonymized cutover: event=%+v found=%v err=%v", canonical, found, err)
				}
				return nil
			},
			rewriteProofOptions(t)...,
		)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	afterFirst, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterFirst == beforeName {
		t.Fatal("first subject rewrite did not activate a replacement generation")
	}
	if err := run(); err != nil {
		t.Fatalf("no-op retry: %v", err)
	}
	afterRetry, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRetry != afterFirst {
		t.Fatalf("no-op retry switched generation from %q to %q", afterFirst, afterRetry)
	}
	if prepared != 2 || completed != 2 {
		t.Fatalf("preparation/completion calls = %d/%d, want 2/2", prepared, completed)
	}
}

func TestPseudonymizeSubjectEmptyStreamStillPreparesAgainstActiveGeneration(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	coordinator := newPrivacyPreparationTestCoordinator()
	log, err := Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	},
		WithHistoryRewriteCoordinator(coordinator),
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	wantGeneration, err := log.ActiveGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, completed int
	err = log.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx, tenantID, subject,
		func(_ context.Context, report TenantDataRewriteReport) error {
			prepared++
			if report.OperationID == "" || report.SourceStream == "" ||
				report.TargetStream != report.SourceStream ||
				report.SourceGeneration != wantGeneration ||
				report.TargetGeneration != wantGeneration || report.ChangedEvents != 0 {
				t.Fatalf("empty-stream preparation report = %+v, want active source generation %q", report, wantGeneration)
			}
			return nil
		},
		func(context.Context) error {
			completed++
			if prepared != 1 {
				t.Fatalf("completion ran before preparation: prepared=%d", prepared)
			}
			return nil
		},
		rewriteProofOptions(t)...,
	)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != 1 || completed != 1 {
		t.Fatalf("empty-stream preparation/completion calls = %d/%d, want 1/1", prepared, completed)
	}
	gotGeneration, err := log.ActiveGeneration(ctx)
	if err != nil || gotGeneration != wantGeneration {
		t.Fatalf("empty-stream rewrite changed active generation to %q from %q: %v", gotGeneration, wantGeneration, err)
	}
	if state, err := log.findRewriteStreams(ctx); err != nil || state != nil {
		t.Fatalf("empty-stream rewrite left state=%+v err=%v", state, err)
	}
}

func TestPseudonymizeSubjectExternalPreparationReadsFrozenCanonicalGeneration(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
		eventID  = "external-preparation-replay-source"
	)
	coordinator := newPrivacyPreparationTestCoordinator()
	log, err := Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	},
		WithHistoryRewriteCoordinator(coordinator),
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: eventID, Type: "approval.requested", TenantID: tenantID,
		Data: []byte(`{"requester":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}

	err = log.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx, tenantID, subject,
		func(preparationCtx context.Context, report TenantDataRewriteReport) error {
			generation, err := log.ActiveGeneration(preparationCtx)
			if err != nil {
				return fmt.Errorf("read frozen active generation: %w", err)
			}
			if generation != report.SourceGeneration {
				return fmt.Errorf(
					"external preparation generation = %q, want frozen source %q",
					generation, report.SourceGeneration,
				)
			}
			var canonical Event
			if err := log.Replay(preparationCtx, 0, func(event Event) error {
				if event.ID == eventID {
					canonical = event
				}
				return nil
			}); err != nil {
				return fmt.Errorf("replay frozen canonical generation: %w", err)
			}
			if canonical.ID != eventID || !bytes.Contains(canonical.Data, []byte(subject)) {
				return fmt.Errorf("external preparation replay = %+v, want original frozen event", canonical)
			}
			return nil
		},
		nil,
		rewriteProofOptions(t)...,
	)
	if err != nil {
		t.Fatalf("PseudonymizeSubjectWithPreparationAndCompletion: %v", err)
	}
	canonical, found, err := log.EventByID(ctx, eventID)
	if err != nil || !found {
		t.Fatalf("canonical event after cutover = found %v, err %v", found, err)
	}
	if bytes.Contains(canonical.Data, []byte(subject)) {
		t.Fatalf("activated target retained erased subject: %s", canonical.Data)
	}
}

func TestPseudonymizeSubjectExternalPreparationWaitsForReadAndRevokesEscapedContext(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
		eventID  = "external-preparation-pinned-read-source"
	)
	coordinator := newPrivacyPreparationTestCoordinator()
	log, err := Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	},
		WithHistoryRewriteCoordinator(coordinator),
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: eventID, Type: "approval.requested", TenantID: tenantID,
		Data: []byte(`{"requester":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}

	readStarted := make(chan struct{})
	preparationReturned := make(chan struct{})
	continueRead := make(chan struct{})
	escapedPreparation := make(chan context.Context, 1)
	escapedRead := make(chan context.Context, 1)
	rewriteDone := make(chan error, 1)
	go func() {
		rewriteDone <- log.PseudonymizeSubjectWithPreparationAndCompletion(
			ctx, tenantID, subject,
			func(preparationCtx context.Context, _ TenantDataRewriteReport) error {
				escapedPreparation <- preparationCtx
				readDone := make(chan error, 1)
				go func() {
					readDone <- log.WithHistoryRead(preparationCtx, func(readCtx context.Context) error {
						escapedRead <- readCtx
						close(readStarted)
						<-continueRead
						var canonical Event
						if err := log.Replay(readCtx, 0, func(event Event) error {
							if event.ID == eventID {
								canonical = event
							}
							return nil
						}); err != nil {
							return fmt.Errorf("nested replay after preparation returned: %w", err)
						}
						if canonical.ID != eventID || !bytes.Contains(canonical.Data, []byte(subject)) {
							return fmt.Errorf("pinned replay = %+v, want frozen source event", canonical)
						}
						return nil
					})
				}()
				select {
				case <-readStarted:
					close(preparationReturned)
					return nil
				case err := <-readDone:
					return fmt.Errorf("generation read exited before entering callback: %w", err)
				case <-time.After(2 * time.Second):
					return errors.New("generation read did not enter external preparation callback")
				}
			},
			nil,
			rewriteProofOptions(t)...,
		)
	}()

	var escaped context.Context
	var escapedCallback context.Context
	select {
	case escapedCallback = <-escapedPreparation:
	case err := <-rewriteDone:
		t.Fatalf("rewrite exited before preparation context was captured: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("external preparation did not expose its callback context")
	}
	select {
	case escaped = <-escapedRead:
	case err := <-rewriteDone:
		t.Fatalf("rewrite exited before pinned read entered: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("external preparation did not establish pinned read")
	}
	<-preparationReturned
	select {
	case err := <-rewriteDone:
		t.Fatalf("rewrite proceeded before pinned read returned: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	close(continueRead)
	select {
	case err := <-rewriteDone:
		if err != nil {
			t.Fatalf("rewrite after pinned read release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rewrite did not proceed after pinned read returned")
	}

	for name, escapedCtx := range map[string]context.Context{
		"preparation": escapedCallback,
		"read":        escaped,
	} {
		var canonical Event
		if err := log.Replay(escapedCtx, 0, func(event Event) error {
			if event.ID == eventID {
				canonical = event
			}
			return nil
		}); err != nil {
			t.Fatalf("replay through escaped %s context: %v", name, err)
		}
		if canonical.ID != eventID || bytes.Contains(canonical.Data, []byte(subject)) {
			t.Fatalf("escaped %s context selected stale source instead of activated target: %+v", name, canonical)
		}
	}
}

func TestPseudonymizeSubjectPreparationFailureLeavesGenerationUnchanged(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	coordinator := newPrivacyPreparationTestCoordinator()
	log, err := Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	},
		WithHistoryRewriteCoordinator(coordinator),
		WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "failed-preparation-source", Type: "approval.requested", TenantID: tenantID,
		Data: []byte(`{"requester":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := rawStreamBytes(t, log)
	completionCalled := false
	wantErr := errors.New("simulated preparation commit failure")
	err = log.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx, tenantID, subject,
		func(context.Context, TenantDataRewriteReport) error { return wantErr },
		func(context.Context) error {
			completionCalled = true
			return nil
		},
		rewriteProofOptions(t)...,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("preparation error = %v, want %v", err, wantErr)
	}
	if completionCalled {
		t.Fatal("completion ran after preparation failed")
	}
	afterName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterName != beforeName || !bytes.Equal(rawStreamBytes(t, log), before) {
		t.Fatal("preparation failure changed the active generation")
	}
}

func TestPseudonymizeSubjectPreparationRequiresDurableResolverBeforeStaging(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, Event{
		ID: "missing-preparation-resolver-source", Type: "approval.requested", TenantID: tenantID,
		Data: []byte(`{"requester":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := rawStreamBytes(t, log)
	preparationCalled := false
	err = log.PseudonymizeSubjectWithPreparationAndCompletion(
		ctx, tenantID, subject,
		func(context.Context, TenantDataRewriteReport) error {
			preparationCalled = true
			return nil
		},
		nil,
		rewriteProofOptions(t)...,
	)
	if err == nil || !strings.Contains(err.Error(), "durable history rewrite preparation resolver") {
		t.Fatalf("missing resolver error = %v", err)
	}
	if preparationCalled {
		t.Fatal("preparation ran without its durable resolver")
	}
	if state, err := log.findRewriteStreams(ctx); err != nil || state != nil {
		t.Fatalf("missing-resolver preflight left rewrite state=%+v err=%v", state, err)
	}
	afterName, _, err := log.resolveActiveStream(ctx)
	if err != nil || afterName != beforeName || !bytes.Equal(rawStreamBytes(t, log), before) {
		t.Fatalf("missing-resolver preflight changed source: name=%q err=%v", afterName, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatalf("reopen after missing-resolver refusal: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if got := rawStreamBytes(t, reopened); !bytes.Equal(got, before) {
		t.Fatalf("reopen changed source after missing-resolver refusal:\nbefore=%s\nafter=%s", before, got)
	}
}

type privacyPreparationTestCoordinator struct {
	*localHistoryRewriteCoordinator
	mu         sync.Mutex
	active     map[string]bool
	resolveErr error
}

func newPrivacyPreparationTestCoordinator() *privacyPreparationTestCoordinator {
	return &privacyPreparationTestCoordinator{
		localHistoryRewriteCoordinator: newLocalHistoryRewriteCoordinator(),
		active:                         map[string]bool{},
	}
}

func (c *privacyPreparationTestCoordinator) mark(tenantID, generation string) {
	c.mu.Lock()
	c.active[tenantID+"\x00"+generation] = true
	c.mu.Unlock()
}

func (c *privacyPreparationTestCoordinator) setResolveError(err error) {
	c.mu.Lock()
	c.resolveErr = err
	c.mu.Unlock()
}

func (c *privacyPreparationTestCoordinator) HistoryRewritePreparationActive(
	_ context.Context,
	tenantID, targetGeneration string,
) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resolveErr != nil {
		return false, c.resolveErr
	}
	return c.active[tenantID+"\x00"+targetGeneration], nil
}

func TestPseudonymizeSubjectPostCommitErrorsPreserveTargetForRestartRecovery(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	for _, test := range []struct {
		name              string
		ambiguousResponse bool
		resolverFailure   bool
	}{
		{name: "ordinary error after successful preparation"},
		{name: "commit success with response error", ambiguousResponse: true},
		{name: "commit response and resolver both fail", ambiguousResponse: true, resolverFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			coordinator := newPrivacyPreparationTestCoordinator()
			cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
			open := func() (*Log, error) {
				return Open(ctx, cfg,
					WithHistoryRewriteCoordinator(coordinator),
					WithHistoryRewriteContinuityVerifier(rewriteTestContinuityVerifier),
				)
			}
			log, err := open()
			if err != nil {
				t.Fatal(err)
			}
			const eventID = "privacy-prepared-restart-source"
			if _, err := log.Append(ctx, Event{
				ID: eventID, Type: "approval.requested", TenantID: tenantID,
				Data: []byte(`{"requester":"alice@example.com"}`),
			}); err != nil {
				t.Fatal(err)
			}
			wantErr := errors.New("ordinary post-commit failure")
			if !test.ambiguousResponse {
				log.rewriteTestHook = func(phase rewritePhase) error {
					if phase == rewritePhasePrepared {
						return wantErr
					}
					return nil
				}
			}
			completionCalled := false
			err = log.PseudonymizeSubjectWithPreparationAndCompletion(
				ctx, tenantID, subject,
				func(_ context.Context, report TenantDataRewriteReport) error {
					coordinator.mark(tenantID, report.TargetGeneration)
					if test.ambiguousResponse {
						if test.resolverFailure {
							coordinator.setResolveError(errors.New("preparation authority temporarily unavailable"))
						}
						return wantErr
					}
					return nil
				},
				func(context.Context) error {
					completionCalled = true
					return nil
				},
				rewriteProofOptions(t)...,
			)
			if !errors.Is(err, wantErr) {
				t.Fatalf("rewrite error = %v, want %v", err, wantErr)
			}
			if completionCalled {
				t.Fatal("completion ran after post-preparation failure")
			}
			coordinator.setResolveError(nil)
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := open()
			if err != nil {
				t.Fatalf("Open recovered prepared rewrite: %v", err)
			}
			defer func() { _ = reopened.Close() }()
			canonical, found, err := reopened.EventByID(ctx, eventID)
			if err != nil || !found {
				t.Fatalf("EventByID after recovery = found %v, err %v", found, err)
			}
			if bytes.Contains(canonical.Data, []byte(subject)) {
				t.Fatalf("recovered target retained raw subject: %s", canonical.Data)
			}
			if _, err := reopened.js.Stream(ctx, streamName); !errors.Is(err, jetstream.ErrStreamNotFound) {
				t.Fatalf("recovered prepared rewrite retained frozen source: %v", err)
			}
		})
	}
}

func rawStreamBytes(t *testing.T, log *Log) []byte {
	t.Helper()
	info, err := log.streamInfo(context.Background())
	if err != nil {
		t.Fatalf("streamInfo: %v", err)
	}
	var out []byte
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		msg, err := log.stream.GetMsg(context.Background(), seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			t.Fatalf("GetMsg(%d): %v", seq, err)
		}
		out = append(out, msg.Data...)
	}
	return out
}
