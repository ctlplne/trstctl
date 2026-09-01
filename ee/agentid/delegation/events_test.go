// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation_test

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/internal/events"
)

// TestEvents_RoundTrip verifies every delegation-lifecycle event type has a
// versioned schema with round-trip encode/decode (acceptance criterion 1).
func TestEvents_RoundTrip(t *testing.T) {
	cases := []delegation.Payload{
		delegation.DelegationRecordedV1{
			TenantID:       "t1",
			RecordDigest:   []byte{1, 2, 3},
			DelegatorID:    "root",
			DelegateID:     "manager",
			ParentDigest:   nil, // root-anchored
			RootAnchor:     true,
			DepthRemaining: 5,
		},
		delegation.IssuanceRecordedV1{
			TenantID:         "t1",
			CredentialDigest: []byte{4, 5},
			SubjectID:        "worker",
			ChainDigest:      []byte{6, 7},
		},
		delegation.RefusalRecordedV1{
			TenantID:      "t1",
			SubjectID:     "worker",
			FailedCheck:   "authority.widened",
			RequestDigest: []byte{8},
			Signature:     []byte{9},
		},
		delegation.RevocationDirectiveV1{
			TenantID:  "t1",
			SubjectID: "manager",
			Reason:    "compromise",
			Watermark: 42,
		},
	}
	for _, want := range cases {
		e, err := delegation.Encode(want)
		if err != nil {
			t.Fatalf("Encode(%T): %v", want, err)
		}
		if e.TenantID == "" {
			t.Fatalf("Encode(%T) dropped tenant id (AN-1)", want)
		}
		if e.SchemaVersion == 0 {
			t.Fatalf("Encode(%T) did not stamp a schema version", want)
		}
		got, err := delegation.Decode(e)
		if err != nil {
			t.Fatalf("Decode(%T): %v", want, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round-trip mismatch\n got=%#v\nwant=%#v", got, want)
		}
	}
}

// TestEvents_UnknownTypeSkipped asserts an unrecognized event type decodes to
// Unknown (skip arm of the skip-or-carry rule) rather than erroring (criterion 1).
func TestEvents_UnknownTypeSkipped(t *testing.T) {
	e := events.Event{Type: "some.other.event", SchemaVersion: 1, Data: []byte(`{"x":1}`)}
	p, err := delegation.Decode(e)
	if err != nil {
		t.Fatalf("Decode(unknown type) error: %v", err)
	}
	u, ok := p.(delegation.Unknown)
	if !ok {
		t.Fatalf("Decode(unknown type) = %T, want Unknown", p)
	}
	if u.Type != "some.other.event" {
		t.Fatalf("Unknown.Type = %q", u.Type)
	}
}

// TestEvents_NewerVersionCarried asserts a known type at a newer-than-known schema
// version decodes to Unknown (carry the raw bytes forward, no panic) — the
// forward-compatible arm of the skip-or-carry rule (criterion 1).
func TestEvents_NewerVersionCarried(t *testing.T) {
	e := events.Event{
		Type:          delegation.TypeDelegationRecorded,
		SchemaVersion: delegation.DelegationRecordedSchemaV1 + 9,
		Data:          []byte(`{"tenant_id":"t1","depth_remaining":3}`),
	}
	p, err := delegation.Decode(e)
	if err != nil {
		t.Fatalf("Decode(newer version) error: %v", err)
	}
	u, ok := p.(delegation.Unknown)
	if !ok {
		t.Fatalf("Decode(newer version) = %T, want Unknown", p)
	}
	if u.Version != delegation.DelegationRecordedSchemaV1+9 {
		t.Fatalf("Unknown.Version = %d", u.Version)
	}
	if !reflect.DeepEqual(u.Raw, e.Data) {
		t.Fatalf("Unknown did not carry the raw payload forward")
	}
}

// TestEvents_MalformedKnownVersionErrors asserts a malformed payload of a known
// type+version is a decode error (not a silent skip and not a panic).
func TestEvents_MalformedKnownVersionErrors(t *testing.T) {
	e := events.Event{
		Type:          delegation.TypeIssuanceRecorded,
		SchemaVersion: delegation.IssuanceRecordedSchemaV1,
		Data:          []byte("{not json"),
	}
	if _, err := delegation.Decode(e); err == nil {
		t.Fatalf("Decode(malformed known version) = nil error; want error")
	}
}

// TestEvents_MemSinkReplayAssertion demonstrates asserting the lifecycle over an
// in-memory ordered event sink (the MemSink precedent), decoding each event back to
// its typed payload in append order.
func TestEvents_MemSinkReplayAssertion(t *testing.T) {
	var sink delegation.MemSink
	payloads := []delegation.Payload{
		delegation.DelegationRecordedV1{TenantID: "t1", DelegatorID: "root", DelegateID: "mgr", RootAnchor: true, DepthRemaining: 3, RecordDigest: []byte{1}},
		delegation.IssuanceRecordedV1{TenantID: "t1", SubjectID: "mgr", CredentialDigest: []byte{2}, ChainDigest: []byte{3}},
		delegation.RevocationDirectiveV1{TenantID: "t1", SubjectID: "mgr", Reason: "compromise", Watermark: 7},
	}
	for _, p := range payloads {
		e, err := delegation.Encode(p)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		sink.Append(e)
	}
	evs := sink.Events()
	if len(evs) != len(payloads) {
		t.Fatalf("sink recorded %d events, want %d", len(evs), len(payloads))
	}
	for i, e := range evs {
		got, err := delegation.Decode(e)
		if err != nil {
			t.Fatalf("Decode event %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, payloads[i]) {
			t.Fatalf("event %d replay mismatch\n got=%#v\nwant=%#v", i, got, payloads[i])
		}
	}
}

// FuzzEventEnvelopeDecode fuzzes the event-envelope parser on untrusted input: it
// must never panic and must never return both a nil payload and a nil error.
