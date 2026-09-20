// SPDX-License-Identifier: BUSL-1.1

package schedulerhistory

import (
	"bytes"
	"strings"
	"testing"
)

func TestRewriteLegacyRunChangesOnlyErrorToken(t *testing.T) {
	secret := "postgres://scheduler:credential@provider.internal/db" // #nosec G101 -- deliberately toxic non-routable fixture proves redaction (CWE-798).
	before := []byte("{ \"run_id\" : \"run-1\", \"error\" : \"" + secret + "\", \"schedule_id\" : \"schedule-1\", \"new_ref\" : \"version:2\", \"status\" : \"failed\" }")
	want := bytes.Replace(before, []byte("\""+secret+"\""), []byte(`"scheduled rotation failed"`), 1)

	after, changed, err := RewriteLegacyRun(before)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("provider error was not classified")
	}
	if !bytes.Equal(after, want) {
		t.Fatalf("rewrite changed bytes outside error token:\n got %s\nwant %s", after, want)
	}
	if strings.Contains(string(after), secret) {
		t.Fatal("rewritten history retains provider credential")
	}
	if err := ValidateLegacyRunPair(before, after); err != nil {
		t.Fatalf("pair validation failed: %v", err)
	}
}

func TestRewriteLegacyRunPreservesCanonicalBytes(t *testing.T) {
	before := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"delivery_failed","error":"connector delivery failed"}`)
	after, changed, err := RewriteLegacyRun(before)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("canonical payload was rewritten")
	}
	if !bytes.Equal(after, before) {
		t.Fatal("canonical payload bytes changed")
	}
	if err := ValidateSanitizedLegacyRun(after); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalErrorRequiresStatusSpecificAgreement(t *testing.T) {
	tests := []struct {
		status string
		detail string
		want   string
		valid  bool
	}{
		{status: "completed", detail: "scheduled rotation failed", want: "", valid: false},
		{status: "queued", detail: "no such secret", want: "", valid: false},
		{status: "privacy_erased", detail: "scheduled rotation is unavailable", want: "", valid: false},
		{status: "delivery_failed", detail: "no such secret", want: "connector delivery failed", valid: false},
		{status: "rollback_failed", detail: "scheduled rotation failed", want: RollbackError, valid: false},
		{status: "delivery_failed", detail: "connector delivery failed", want: "connector delivery failed", valid: true},
		{status: "rollback_failed", detail: RollbackError, want: RollbackError, valid: true},
		{status: "unsupported", detail: "scheduled rotation is unavailable", want: "scheduled rotation is unavailable", valid: true},
		{status: "failed", detail: "no such secret", want: "no such secret", valid: true},
		{status: "rolled_back", detail: "approval request expired", want: "approval request expired", valid: true},
		{status: "retire_pending", detail: "scheduled rotation failed", want: "scheduled rotation failed", valid: true},
	}
	for _, test := range tests {
		if got := CanonicalError(test.status, test.detail); got != test.want {
			t.Errorf("CanonicalError(%q, %q) = %q, want %q", test.status, test.detail, got, test.want)
		}
		if got := IsCanonicalError(test.status, test.detail); got != test.valid {
			t.Errorf("IsCanonicalError(%q, %q) = %v, want %v", test.status, test.detail, got, test.valid)
		}
	}
}

func TestLegacyRunValidationIsClosedAndNeverEchoesValues(t *testing.T) {
	secret := "token-super-sensitive" // #nosec G101 -- deliberately toxic fixture proves closed parsing without echo (CWE-798).
	tests := [][]byte{
		[]byte(`{"schedule_id":"s","run_id":"r","status":"failed","error":"` + secret + `","error":"again"}`),
		[]byte(`{"schedule_id":"s","run_id":"r","status":"failed","unknown":"` + secret + `"}`),
		[]byte(`{"schedule_id":"s","run_id":"r","status":7,"error":"` + secret + `"}`),
		[]byte(`{"run_id":"r","status":"failed","error":"` + secret + `"}`),
	}
	for _, data := range tests {
		_, _, err := RewriteLegacyRun(data)
		if err == nil {
			t.Fatalf("invalid payload accepted: %s", data)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed payload value: %v", err)
		}
	}
}

func TestValidateLegacyRunPairRejectsAnyOtherChange(t *testing.T) {
	before := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","new_ref":"version:1","error":"provider secret"}`)
	after := []byte(`{"schedule_id":"schedule-1","run_id":"run-2","status":"failed","new_ref":"version:1","error":"scheduled rotation failed"}`)
	if err := ValidateLegacyRunPair(before, after); err == nil {
		t.Fatal("pair validator accepted a changed run_id")
	}
}

func TestRequiresSanitationTargetsOnlyLegacySchedulerRun(t *testing.T) {
	unsafe := []byte(`{"schedule_id":"s","run_id":"r","status":"failed","error":"provider secret"}`)
	for _, test := range []struct {
		eventType string
		version   int
		want      bool
	}{
		{EventType, LegacySchemaVersion, true},
		{EventType, LegacySchemaVersion + 1, false},
		{"other.event", LegacySchemaVersion, false},
	} {
		got, err := RequiresSanitation(test.eventType, test.version, unsafe)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("RequiresSanitation(%q, %d) = %v, want %v", test.eventType, test.version, got, test.want)
		}
	}
}
