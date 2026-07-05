// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// TestPayload_RoundTrip verifies that every event type has a versioned schema
// with round-trip encode/decode (PCAS-01 acceptance criterion 1).
func TestPayload_RoundTrip(t *testing.T) {
	cases := []Payload{
		FindingV1{IdentityID: "id", TenantID: "t", Epoch: 0, Algorithm: "RSA2048", PublicKeyDER: []byte{1, 2, 3}, Reason: "quantum-vulnerable"},
		SuccessionV1{IdentityID: "id", TenantID: "t", PredecessorEpoch: 0, Epoch: 1, PredecessorAlgorithm: "RSA2048", SuccessorAlgorithm: "ML-DSA-65", SuccessorPublicKeyDER: []byte{4, 5}, PolicyRef: "sha256:abc", AlgorithmClass: ClassPurePQ, RecordDigest: []byte{9}},
		RetirementV1{IdentityID: "id", TenantID: "t", Epoch: 1, RetiredAlg: "RSA2048", SuccessionRef: []byte{7}},
		RPAckV1{IdentityID: "id", TenantID: "t", Epoch: 1, RelyingParty: "rp1", AckSignature: []byte{8}},
	}
	for _, want := range cases {
		e, err := Encode(want)
		if err != nil {
			t.Fatalf("Encode(%T): %v", want, err)
		}
		if e.TenantID == "" {
			t.Fatalf("Encode(%T) did not propagate tenant (AN-1)", want)
		}
		if e.SchemaVersion == 0 {
			t.Fatalf("Encode(%T) did not stamp a schema version", want)
		}
		got, err := Decode(e)
		if err != nil {
			t.Fatalf("Decode(%T): %v", want, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round-trip mismatch for %T:\n got %#v\nwant %#v", want, got, want)
		}
	}
}

// TestDecode_UnknownTypeSkipped confirms an unrelated event type decodes to
// Unknown without error (forward-compatible skip; criterion 4).
func TestDecode_UnknownTypeSkipped(t *testing.T) {
	e := events.Event{Type: "some.other.event", SchemaVersion: 1, Data: []byte(`{"x":1}`)}
	got, err := Decode(e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, ok := got.(Unknown)
	if !ok {
		t.Fatalf("want Unknown, got %T", got)
	}
	if u.Type != "some.other.event" {
		t.Fatalf("Unknown.Type = %q", u.Type)
	}
}

// TestDecode_FutureVersionSkipped confirms a newer-than-known schema version of
// a known type decodes to Unknown (skip), never a mis-projection (criterion 4).
func TestDecode_FutureVersionSkipped(t *testing.T) {
	e := events.Event{Type: TypeSuccession, SchemaVersion: SuccessionSchemaV1 + 7, Data: []byte(`{"identity_id":"id","epoch":5}`)}
	got, err := Decode(e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got.(Unknown); !ok {
		t.Fatalf("future version must skip to Unknown, got %T", got)
	}
}

// TestDecode_MalformedKnownVersionErrors confirms corruption of a known
// type+version is surfaced as an error (fail-closed), not silently skipped.
func TestDecode_MalformedKnownVersionErrors(t *testing.T) {
	e := events.Event{Type: TypeSuccession, SchemaVersion: SuccessionSchemaV1, Data: []byte("{not json")}
	if _, err := Decode(e); err == nil {
		t.Fatal("want error on malformed known payload, got nil")
	}
}

// FuzzDecode asserts the envelope parser never panics on untrusted input
// (PCAS-01 test-first plan: fuzz the envelope parser).
func FuzzDecode(f *testing.F) {
	f.Add(TypeSuccession, 1, []byte(`{"identity_id":"id","epoch":1}`))
	f.Add(TypeFinding, 1, []byte(`{"identity_id":"id","algorithm":"RSA2048"}`))
	f.Add("random.type", 3, []byte("garbage"))
	f.Add(TypeRetirement, 99, []byte(""))
	f.Fuzz(func(t *testing.T, typ string, ver int, data []byte) {
		// Must never panic; may return a payload, Unknown, or an error.
		_, _ = Decode(events.Event{Type: typ, SchemaVersion: ver, Data: data})
	})
}
