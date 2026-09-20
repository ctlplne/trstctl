// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/eventspec"
)

func TestDepState_EventPayloadRoundTrip(t *testing.T) {
	cases := []Payload{
		DependencyRegisteredV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentCiphertext, ID: "ct-1"}, Origin: RegistrationOriginIssued},
		DependencyReleasedV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentWrappedKey, ID: "wrapped-1"}, Reason: "expired"},
		DependencyErasureDesignatedV1{TenantID: "tenant-a", KeyID: "key-a", Dependent: Dependent{Class: DependentDataSet, ID: "dataset-1"}, DesignationRef: "erase-1"},
		ReprotectionCompletedV1{
			TenantID: "tenant-a", KeyID: "key-a", JobID: "job-1",
			Dependent:      Dependent{Class: DependentCredential, ID: "cred-1"},
			SuccessorKeyID: "key-b",
			CredentialSupersession: &CredentialSupersessionV1{
				OldCredentialID: "cred-1",
				NewCredentialID: "cred-2",
			},
		},
		RevocationCompletedV1{TenantID: "tenant-a", KeyID: "key-a", JobID: "job-lease-1", Dependent: Dependent{Class: DependentLeasedSecret, ID: "lease-1"}, Destination: "vault/db"},
	}

	for _, want := range cases {
		e, err := Encode(want)
		if err != nil {
			t.Fatalf("Encode(%T): %v", want, err)
		}
		if e.TenantID != "tenant-a" {
			t.Fatalf("Encode(%T) TenantID = %q, want tenant-a", want, e.TenantID)
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

func TestDepState_FutureVersionSkipped(t *testing.T) {
	e := eventspec.Event{
		Type:          TypeDependencyRegistered,
		TenantID:      "tenant-a",
		SchemaVersion: SchemaV1 + 1,
		Data:          []byte(`{"tenant_id":"tenant-a","key_id":"key-a","dependent":{"class":"ciphertext","id":"ct-1"}}`),
	}
	got, err := Decode(e)
	if err != nil {
		t.Fatalf("Decode future version: %v", err)
	}
	if _, ok := got.(Unknown); !ok {
		t.Fatalf("future version should decode to Unknown, got %T", got)
	}
	if state, err := Fold([]eventspec.Event{e}); err != nil {
		t.Fatalf("Fold future version: %v", err)
	} else if len(state) != 0 {
		t.Fatalf("future version should be skipped by projection, got %#v", state)
	}
}

func TestDepState_UnknownTypeSkipped(t *testing.T) {
	e := eventspec.Event{Type: "unrelated.lifecycle.event", TenantID: "tenant-a", SchemaVersion: 1, Data: []byte("not json")}
	got, err := Decode(e)
	if err != nil {
		t.Fatalf("Decode unknown type: %v", err)
	}
	u, ok := got.(Unknown)
	if !ok {
		t.Fatalf("unknown type should decode to Unknown, got %T", got)
	}
	if u.Type != e.Type || string(u.Raw) != string(e.Data) {
		t.Fatalf("Unknown did not carry raw event: %#v", u)
	}
	if state, err := Fold([]eventspec.Event{e}); err != nil {
		t.Fatalf("Fold unknown type: %v", err)
	} else if len(state) != 0 {
		t.Fatalf("unknown type should be skipped by projection, got %#v", state)
	}
}

func TestDepState_MalformedKnownVersionErrors(t *testing.T) {
	e := eventspec.Event{Type: TypeDependencyRegistered, TenantID: "tenant-a", SchemaVersion: SchemaV1, Data: []byte("{broken")}
	if _, err := Decode(e); err == nil {
		t.Fatal("Decode malformed known-version event returned nil error")
	}
	if _, err := Fold([]eventspec.Event{e}); err == nil {
		t.Fatal("Fold malformed known-version event returned nil error")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(TypeDependencyRegistered, SchemaV1, []byte(`{"tenant_id":"tenant-a","key_id":"key-a","dependent":{"class":"ciphertext","id":"ct-1"}}`))
	f.Add(TypeDependencyReleased, SchemaV1, []byte(`{"tenant_id":"tenant-a","key_id":"key-a","dependent":{"class":"credential","id":"cred-1"}}`))
	f.Add(TypeDependencyErasureDesignated, SchemaV1, []byte(`{"tenant_id":"tenant-a","key_id":"key-a","dependent":{"class":"data_set","id":"dataset-1"}}`))
	f.Add("other.event", 7, []byte("not json"))
	f.Fuzz(func(t *testing.T, typ string, ver int, data []byte) {
		_, _ = Decode(eventspec.Event{Type: typ, SchemaVersion: ver, Data: data})
	})
}
