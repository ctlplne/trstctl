// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/rotationcommand"
)

func TestSecretRotationSchedulePrivacyFieldPoliciesPreserveShortSubjectCollisions(t *testing.T) {
	const subject = "a"
	const placeholder = "subject-ref"

	for _, value := range []string{"vault", "sha256:abc123", "provider-ref:a", "550e8400-e29b-41d4-a716-446655440000"} {
		got, changed := rewriteSecretRotationSchedulePrivacyOpaqueExact(value, subject, placeholder)
		if changed || got != value {
			t.Fatalf("opaque value %q was spliced into %q", value, got)
		}
	}
	if got, changed := rewriteSecretRotationSchedulePrivacyOpaqueExact(subject, subject, placeholder); !changed || got != placeholder {
		t.Fatalf("whole opaque subject rewrite = (%q, %t), want (%q, true)", got, changed, placeholder)
	}

	for _, value := range []string{"vault", "database", "sha256:abc123"} {
		got, changed := rewriteSecretRotationSchedulePrivacySubjectToken(value, subject, placeholder)
		if changed || got != value {
			t.Fatalf("token value %q was rewritten into %q", value, got)
		}
	}
	for value, want := range map[string]string{
		"connector:a": "connector:" + placeholder,
		"/a/secret":   "/" + placeholder + "/secret",
		"a":           placeholder,
	} {
		got, changed := rewriteSecretRotationSchedulePrivacySubjectToken(value, subject, placeholder)
		if !changed || got != want {
			t.Fatalf("token rewrite %q = (%q, %t), want (%q, true)", value, got, changed, want)
		}
	}

	got, changed := rewriteSecretRotationSchedulePrivacyFreeText("provider failed for a owner", subject)
	if !changed || got != secretRotationSchedulePrivacyClearedFreeText {
		t.Fatalf("free-text rewrite = (%q, %t), want fixed cleared marker", got, changed)
	}
}

func TestSecretRotationSchedulePrivacyEvidenceIsClosedBoundedAndCounted(t *testing.T) {
	dispositions := []SecretRotationSchedulePrivacyDisposition{
		{
			Kind:         SecretRotationSchedulePrivacyDispositionCommand,
			AuthorityRef: "30630630-6306-4306-8306-306306306306",
			Disposition:  SecretRotationSchedulePrivacyDispositionErased,
		},
		{
			Kind:         SecretRotationSchedulePrivacyDispositionTick,
			AuthorityRef: strings.Repeat("a", 64),
			Disposition:  SecretRotationSchedulePrivacyDispositionErased,
		},
	}
	counts := map[string]int{
		"secret_rotation_schedule_ticks":             1,
		"secret_rotation_schedule_tick_rows":         1,
		"secret_rotation_schedule_commands":          1,
		"secret_rotation_schedule_outer_resolutions": 1,
	}
	if err := ValidateSecretRotationSchedulePrivacyEvidenceV3(counts, dispositions); err != nil {
		t.Fatalf("valid scheduler privacy evidence: %v", err)
	}
	for name, mutate := range map[string]func(map[string]int, []SecretRotationSchedulePrivacyDisposition){
		"missing count": func(counts map[string]int, _ []SecretRotationSchedulePrivacyDisposition) {
			delete(counts, "secret_rotation_schedule_outer_resolutions")
		},
		"count mismatch": func(counts map[string]int, _ []SecretRotationSchedulePrivacyDisposition) {
			counts["secret_rotation_schedule_commands"] = 0
		},
		"unsorted": func(_ map[string]int, evidence []SecretRotationSchedulePrivacyDisposition) {
			evidence[0], evidence[1] = evidence[1], evidence[0]
		},
		"open disposition": func(_ map[string]int, evidence []SecretRotationSchedulePrivacyDisposition) {
			evidence[0].Disposition = "retained"
		},
		"raw tick authority": func(_ map[string]int, evidence []SecretRotationSchedulePrivacyDisposition) {
			evidence[1].AuthorityRef = "scheduler:alice:outer"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateCounts := make(map[string]int, len(counts))
			for key, value := range counts {
				candidateCounts[key] = value
			}
			candidateEvidence := append([]SecretRotationSchedulePrivacyDisposition(nil), dispositions...)
			mutate(candidateCounts, candidateEvidence)
			if err := ValidateSecretRotationSchedulePrivacyEvidenceV3(
				candidateCounts, candidateEvidence,
			); err == nil {
				t.Fatal("invalid scheduler privacy evidence was accepted")
			}
		})
	}
}

func TestRewriteSecretRotationSchedulePrivacyReceiptUsesDeclaredFieldPolicies(t *testing.T) {
	raw := []byte(`{
		"ran":1,
		"scanned":1,
		"runs":[{
			"schedule_id":"550e8400-e29b-41d4-a716-446655440000",
			"run_id":"550e8400-e29b-41d4-a716-446655440001",
			"due_at":"2026-08-11T11:59:00Z",
			"status":"failed",
			"rotation":{
				"key":"connector:a",
				"old_ref":"vault",
				"new_ref":"sha256:abc123",
				"completed":false,
				"queued":false,
				"rolled_back":false,
				"rollback_attempted":false,
				"rollback_failed":false,
				"error":"failed for a owner"
			},
			"error":"failed for a owner",
			"ran_at":"2026-08-11T12:00:00Z",
			"reconciled":false
		}],
		"deferred":[],
		"run_limit_reached":false,
		"scan_limit_reached":false,
		"complete":false,
		"partial":false
	}`)

	rewritten, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(
		raw, "a", "subject-ref", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("receipt containing a declared subject token was not rewritten")
	}
	var receipt struct {
		Runs []struct {
			ScheduleID string `json:"schedule_id"`
			RunID      string `json:"run_id"`
			Rotation   struct {
				Key    string `json:"key"`
				OldRef string `json:"old_ref"`
				NewRef string `json:"new_ref"`
				Error  string `json:"error"`
			} `json:"rotation"`
			Error string `json:"error"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rewritten, &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(receipt.Runs))
	}
	run := receipt.Runs[0]
	if run.ScheduleID != "550e8400-e29b-41d4-a716-446655440000" ||
		run.RunID != "550e8400-e29b-41d4-a716-446655440001" {
		t.Fatalf("opaque UUID identity changed: %#v", run)
	}
	if run.Rotation.Key != "connector:subject-ref" || run.Rotation.OldRef != "vault" ||
		run.Rotation.NewRef != "sha256:abc123" {
		t.Fatalf("rotation field policy mismatch: %#v", run.Rotation)
	}
	if run.Error != secretRotationSchedulePrivacyClearedFreeText ||
		run.Rotation.Error != secretRotationSchedulePrivacyClearedFreeText {
		t.Fatalf("free text was not wholly cleared: %#v", run)
	}
}

func TestRewriteSecretRotationSchedulePrivacyReceiptRejectsUnknownFieldUnconditionally(t *testing.T) {
	raw := []byte(`{
		"ran":0,"scanned":0,"runs":[],"deferred":[],
		"run_limit_reached":false,"scan_limit_reached":false,
		"complete":true,"partial":false,
		"future_field":"safe"
	}`)
	_, _, err := rewriteSecretRotationSchedulePrivacyReceipt(raw, "alice", "subject-ref", false, "")
	if !errors.Is(err, ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("unknown field error = %v, want tick conflict", err)
	}
}

func TestRewriteSecretRotationSchedulePrivacyReceiptRejectsDuplicateKeysRecursively(t *testing.T) {
	rootDuplicate := []byte(`{
		"ran":0,"ran":1,"scanned":0,"runs":[],"deferred":[],
		"run_limit_reached":false,"scan_limit_reached":false,
		"complete":true,"partial":false
	}`)
	nestedDuplicate := []byte(`{
		"ran":1,"scanned":1,
		"runs":[{
			"schedule_id":"550e8400-e29b-41d4-a716-446655440000",
			"run_id":"550e8400-e29b-41d4-a716-446655440001",
			"due_at":"2026-08-11T11:59:00Z",
			"status":"failed",
			"rotation":{
				"key":"connector:alice","key":"connector:bob",
				"old_ref":"version:1","new_ref":"version:2",
				"completed":false,"queued":false,"rolled_back":false,
				"rollback_attempted":false,"rollback_failed":false
			},
			"ran_at":"2026-08-11T12:00:00Z","reconciled":false
		}],
		"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,
		"complete":false,"partial":false
	}`)
	for name, raw := range map[string][]byte{"root": rootDuplicate, "nested": nestedDuplicate} {
		t.Run(name, func(t *testing.T) {
			_, _, err := rewriteSecretRotationSchedulePrivacyReceipt(
				raw, "alice", "subject-ref", false, "")
			if !errors.Is(err, ErrSecretRotationScheduleTickConflict) {
				t.Fatalf("duplicate-key error = %v, want tick conflict", err)
			}
		})
	}
}

func TestSecretRotationScheduleTickProgressRequiresStrictExactTerminalDueEdge(t *testing.T) {
	const (
		tenantID        = "11111111-1111-1111-1111-111111111111"
		registrationID  = "15500000-0000-4000-8000-000000000001"
		registrationSeq = uint64(41)
		scheduleID      = "10600000-0000-4000-8000-000000000001"
	)
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 123000000, time.UTC)
	runID := rotationcommand.RunID(tenantID, registrationSeq, scheduleID, dueAt)
	initial := json.RawMessage(`{"ran":0,"scanned":0,"runs":[],"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,"complete":false,"partial":false}`)
	retained := SecretRotationScheduleTick{
		TenantID: tenantID, IdentityVersion: SecretRotationScheduleIdentityVersion,
		TenantRegistrationEventID:       registrationID,
		TenantRegistrationEventSequence: registrationSeq,
		Phase:                           "row_started", Receipt: initial,
		CurrentSchedule: &SecretRotationSchedule{
			ID: scheduleID, TenantID: tenantID,
			IdentityVersion:                 SecretRotationScheduleIdentityVersion,
			TenantRegistrationEventID:       registrationID,
			TenantRegistrationEventSequence: registrationSeq,
			Provider:                        "connector:ci", Key: "rotation/exact-edge", OldRef: "version:1",
			IntervalSeconds: 60, ConfigEventSequence: registrationSeq + 1,
			Enabled: true, NextRunAt: dueAt,
		},
	}
	receipt := func(id, edge, status string) []byte {
		return []byte(fmt.Sprintf(`{
			"ran":1,"scanned":1,
			"runs":[{
				"schedule_id":%q,"run_id":%q,"due_at":%q,"status":%q,
				"rotation":{"key":"rotation/exact-edge","old_ref":"version:1","new_ref":"version:2","completed":false,"queued":true,"rolled_back":false,"rollback_attempted":false,"rollback_failed":false},
				"ran_at":"2026-08-11T12:00:01.123Z","reconciled":false
			}],
			"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,
			"complete":false,"partial":false
		}`, id, runID, edge, status))
	}
	exact := receipt(scheduleID, dueAt.Format(time.RFC3339Nano), "queued")
	if err := validateSecretRotationScheduleTickProgress(retained, exact, 1, 1); err != nil {
		t.Fatalf("exact lifecycle-bound due edge rejected: %v", err)
	}

	wrongRun := strings.Replace(string(exact), runID,
		rotationcommand.RunID(tenantID, registrationSeq+1, scheduleID, dueAt), 1)
	wrongDue := strings.Replace(string(exact), dueAt.Format(time.RFC3339Nano),
		dueAt.Add(time.Second).Format(time.RFC3339Nano), 1)
	missingDue := strings.Replace(string(exact), `"due_at":"`+dueAt.Format(time.RFC3339Nano)+`",`, "", 1)
	wrongSchedule := strings.Replace(string(exact), scheduleID,
		"10600000-0000-4000-8000-000000000002", 1)
	nonTerminal := strings.Replace(string(exact), `"status":"queued"`, `"status":"claimed"`, 1)
	unknownRoot := strings.Replace(string(exact), `"partial":false`, `"partial":false,"future":true`, 1)
	unknownNested := strings.Replace(string(exact), `"reconciled":false`, `"reconciled":false,"future":true`, 1)
	duplicateRoot := strings.Replace(string(exact), `"ran":1`, `"ran":1,"ran":1`, 1)
	duplicateNested := strings.Replace(string(exact), `"run_id":"`+runID+`"`,
		`"run_id":"`+runID+`","run_id":"`+runID+`"`, 1)
	for name, raw := range map[string][]byte{
		"wrong run id":           []byte(wrongRun),
		"wrong due at":           []byte(wrongDue),
		"missing due at":         []byte(missingDue),
		"wrong schedule id":      []byte(wrongSchedule),
		"non-terminal status":    []byte(nonTerminal),
		"unknown root field":     []byte(unknownRoot),
		"unknown nested field":   []byte(unknownNested),
		"duplicate root field":   []byte(duplicateRoot),
		"duplicate nested field": []byte(duplicateNested),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSecretRotationScheduleTickProgress(retained, raw, 1, 1); !errors.Is(err, ErrSecretRotationScheduleTickConflict) {
				t.Fatalf("corrupt receipt error=%v, want scheduler conflict", err)
			}
		})
	}
}

func TestSecretRotationSchedulePrivacyPlaceholderIsOpaqueAndReceiptConverges(t *testing.T) {
	const subject = "erased"
	placeholder := privacy.Placeholder(privacy.SubjectRef("tenant-a", subject))
	first, changed := rewriteSecretRotationSchedulePrivacySubjectToken(
		"connector:"+subject, subject, placeholder)
	if !changed || first != "connector:"+placeholder {
		t.Fatalf("first token rewrite = (%q, %t), want connector placeholder", first, changed)
	}
	second, changed := rewriteSecretRotationSchedulePrivacySubjectToken(first, subject, placeholder)
	if changed || second != first {
		t.Fatalf("placeholder expanded on retry: first=%q second=%q changed=%t", first, second, changed)
	}

	raw := []byte(`{
		"ran":1,"scanned":1,
		"runs":[{
			"schedule_id":"550e8400-e29b-41d4-a716-446655440000",
			"run_id":"550e8400-e29b-41d4-a716-446655440001",
			"due_at":"2026-08-11T11:59:00Z",
			"status":"failed",
			"rotation":{
				"key":"connector:erased","old_ref":"vault","new_ref":"sha256:abc123",
				"completed":false,"queued":false,"rolled_back":false,
				"rollback_attempted":false,"rollback_failed":false
			},
			"ran_at":"2026-08-11T12:00:00Z","reconciled":false
		}],
		"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,
		"complete":false,"partial":false
	}`)
	firstReceipt, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(
		raw, subject, placeholder, false, "")
	if err != nil || !changed {
		t.Fatalf("first receipt rewrite = (%s, %t, %v)", firstReceipt, changed, err)
	}
	secondReceipt, changed, err := rewriteSecretRotationSchedulePrivacyReceipt(
		firstReceipt, subject, placeholder, false, "")
	if err != nil || changed || !bytes.Equal(secondReceipt, firstReceipt) {
		t.Fatalf("receipt did not converge: changed=%t err=%v\nfirst=%s\nsecond=%s",
			changed, err, firstReceipt, secondReceipt)
	}
}

func TestSecretRotationSchedulePrivacyOuterRequirementBindsOneExactProtectedResult(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice"
		rawKey   = "scheduler:alice:outer"
	)
	status := 200
	terminalBody := []byte(`{
		"ran":1,"scanned":1,
		"runs":[{
			"schedule_id":"550e8400-e29b-41d4-a716-446655440000",
			"run_id":"550e8400-e29b-41d4-a716-446655440001",
			"due_at":"2026-08-11T11:59:00Z","status":"queued",
			"rotation":{
				"key":"connector:alice","old_ref":"version:1","new_ref":"version:2",
				"completed":false,"queued":true,"rolled_back":false,
				"rollback_attempted":false,"rollback_failed":false
			},
			"ran_at":"2026-08-11T12:00:00Z","reconciled":false
		}],
		"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,
		"complete":true,"partial":false
	}`)
	outer := secretRotationSchedulePrivacyOuter{
		key: rawKey, status: "completed", requestBinding: "sha256:binding",
		resultCodec: "aes-gcm:v1", result: []byte("protected-before-erasure"),
	}
	tick := SecretRotationScheduleTick{
		Phase: "terminal", TerminalHTTPStatus: &status, TerminalBody: terminalBody,
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, subject))
	requirement, required, err := secretRotationSchedulePrivacyOuterRequirementForTick(
		tenantID, subject, placeholder, outer, tick)
	if err != nil || !required {
		t.Fatalf("outer requirement required=%t err=%v", required, err)
	}
	if !requirement.RawKeyTokenMatch || !requirement.TerminalBodyMatch ||
		requirement.TerminalHTTPStatus != status || requirement.RequestBinding != outer.requestBinding ||
		requirement.ResultCodec != outer.resultCodec {
		t.Fatalf("outer requirement omitted exact authority: %+v", requirement)
	}
	wantAuthority := secretRotationSchedulePrivacyOuterAuthorityRef(tenantID, rawKey)
	if requirement.AuthorityRef != wantAuthority ||
		requirement.ReplacementIdempotencyKey != secretRotationSchedulePrivacyOuterReplacementKey(wantAuthority) ||
		requirement.ReplacementIdempotencyKey == rawKey || strings.Contains(requirement.AuthorityRef, rawKey) {
		t.Fatalf("outer rekey authority is not one-way/deterministic: %+v", requirement)
	}
	if len(requirement.RewrittenTerminalBody) == 0 ||
		!bytes.Equal(requirement.OriginalTerminalBody, terminalBody) ||
		bytes.Equal(requirement.RewrittenTerminalBody, terminalBody) ||
		bytes.Contains(requirement.RewrittenTerminalBody, []byte("connector:"+subject)) ||
		!bytes.Contains(requirement.RewrittenTerminalBody, []byte("connector:"+placeholder)) {
		t.Fatalf("outer protected-result requirement did not carry the exact rewritten body: %s",
			requirement.RewrittenTerminalBody)
	}
}

func TestSecretRotationSchedulePrivacyOuterRequirementFailsClosedOnContradictoryEvidence(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	outer := secretRotationSchedulePrivacyOuter{
		key: "scheduler:alice:outer", status: "completed", requestBinding: "sha256:binding",
		resultCodec: "aes-gcm:v1", result: []byte("protected-before-erasure"),
	}
	_, required, err := secretRotationSchedulePrivacyOuterRequirementForTick(
		tenantID, "alice", "erased:0123456789ab", outer, SecretRotationScheduleTick{Phase: "snapshot"})
	if required || !errors.Is(err, ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("completed outer without terminal tick required=%t err=%v, want conflict", required, err)
	}

	status := 200
	_, required, err = secretRotationSchedulePrivacyOuterRequirementForTick(
		tenantID, "alice", "erased:0123456789ab",
		secretRotationSchedulePrivacyOuter{
			key: "scheduler:outer", status: "bound", requestBinding: "sha256:binding",
		},
		SecretRotationScheduleTick{Phase: "terminal", TerminalHTTPStatus: &status, TerminalBody: []byte(`{}`)})
	if required || !errors.Is(err, ErrSecretRotationScheduleTickConflict) {
		t.Fatalf("nonterminal outer with terminal tick required=%t err=%v, want conflict", required, err)
	}
}

func TestSecretRotationSchedulePrivacyStampedCommandSelectsOnlyRemainingSubject(t *testing.T) {
	firstPlaceholder := privacy.Placeholder(privacy.SubjectRef("tenant-a", "alice"))
	command := secretRotationSchedulePrivacyCommand{
		provider:              "connector:" + firstPlaceholder + "/bob",
		key:                   "vault",
		oldRef:                "version:1",
		privacyRewriteVersion: SecretRotationSchedulePrivacyRewriteVersion,
		privacySubjectRef:     privacy.SubjectRef("tenant-a", "alice"),
		privacyOperationID:    "sha256:" + string(bytes.Repeat([]byte{'1'}, 64)),
		privacyEventID:        "sha256:" + string(bytes.Repeat([]byte{'2'}, 64)),
	}
	selected, err := secretRotationSchedulePrivacyCommandMatches(command, "alice")
	if err != nil || selected {
		t.Fatalf("previously erased subject selected stamped command: selected=%t err=%v", selected, err)
	}
	selected, err = secretRotationSchedulePrivacyCommandMatches(command, "bob")
	if err != nil || !selected {
		t.Fatalf("remaining subject did not select stamped command: selected=%t err=%v", selected, err)
	}
	selected, err = secretRotationSchedulePrivacyCommandMatches(command, "carol")
	if err != nil || selected {
		t.Fatalf("absent subject selected stamped command: selected=%t err=%v", selected, err)
	}
}

func TestValidateSecretRotationSchedulePrivacyStampRejectsPartialShape(t *testing.T) {
	err := validateSecretRotationSchedulePrivacyStamp(
		0, "subject-ref", "", "")
	if !errors.Is(err, ErrSecretRotationScheduleCommandConflict) {
		t.Fatalf("partial privacy stamp error = %v, want command conflict", err)
	}
}
