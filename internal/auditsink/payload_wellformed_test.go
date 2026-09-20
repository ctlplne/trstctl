// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// TestSprintfQuotedPayloadsAreNotAlwaysJSON pins the reason the seam check
// exists. Audit payloads across this codebase are built as
// fmt.Sprintf(`{"k":%q}`, v), which reads as safe and is not: %q emits Go string
// syntax, so a control byte becomes \x1b and invalid UTF-8 becomes \xff —
// escapes JSON does not have.
func TestSprintfQuotedPayloadsAreNotAlwaysJSON(t *testing.T) {
	for _, v := range []string{"esc\x1bhere", "bad\xffutf8", "nul\x00byte"} {
		payload := fmt.Sprintf(`{"key_id":%q}`, v)
		if json.Valid([]byte(payload)) {
			t.Errorf("fixture is wrong: %q was supposed to produce invalid JSON, got %s", v, payload)
		}
	}
	// The ordinary case must stay valid, or the check below would be trivial.
	if !json.Valid([]byte(fmt.Sprintf(`{"key_id":%q}`, "normal-id"))) {
		t.Fatal("an ordinary key id produced invalid JSON; the fixture is broken")
	}
}

// TestEmitNeverWritesMalformedJSON is the regression guard: whatever a call site
// hands Emit, what reaches the auditor parses. The event must survive — it is the
// AN-2 record that something happened — but its payload must not be unreadable.
func TestEmitNeverWritesMalformedJSON(t *testing.T) {
	hostile := fmt.Sprintf(`{"key_id":%q,"serial":1}`, "pwn\x1b\xff")
	rec := &Recorder{}
	before := MalformedAuditPayloads()

	if err := Emit(context.Background(), rec, nil, "ssh.cert.issued", "t1", []byte(hostile)); err != nil {
		t.Fatalf("emit: %v", err)
	}

	records := rec.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1; the event was dropped rather than repaired", len(records))
	}
	got := records[0]
	if got.Type != "ssh.cert.issued" || got.TenantID != "t1" {
		t.Errorf("event identity was altered: type=%q tenant=%q", got.Type, got.TenantID)
	}
	if !json.Valid(got.Data) {
		t.Fatalf("a malformed payload reached the auditor unrepaired: %q", got.Data)
	}
	var back struct {
		Malformed bool   `json:"trstctl_payload_malformed"`
		Bytes     int    `json:"original_bytes"`
		SHA256    string `json:"original_sha256"`
	}
	if err := json.Unmarshal(got.Data, &back); err != nil {
		t.Fatalf("substitute payload does not decode: %v", err)
	}
	if !back.Malformed || back.Bytes != len(hostile) || len(back.SHA256) != 64 {
		t.Errorf("substitute lost the forensic trail: %+v", back)
	}
	if MalformedAuditPayloads() != before+1 {
		t.Error("the malformed-payload counter did not increment; operators get no signal")
	}
}

// TestEmitPassesValidPayloadsThrough guards the other direction: the seam must
// not rewrite, re-encode, or reorder a payload that was already fine.
func TestEmitPassesValidPayloadsThrough(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"key_id":"normal","serial":7}`),
		[]byte(`{"nested":{"a":[1,2,3]},"unicode":"héllo → 世界"}`),
		[]byte(`[]`),
		nil,
	} {
		rec := &Recorder{}
		if err := Emit(context.Background(), rec, nil, "e", "t1", payload); err != nil {
			t.Fatalf("emit: %v", err)
		}
		got := rec.Records()[0].Data
		if string(got) != string(payload) {
			t.Errorf("payload was rewritten: got %q, want %q", got, payload)
		}
	}
}
