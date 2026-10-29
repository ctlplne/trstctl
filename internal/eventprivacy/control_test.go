// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

const controlTestTenant = "d59b4292-1adc-4d43-a405-781f95b1779c"

func TestRequestedControlIsCanonicalAndBoundToLifetime(t *testing.T) {
	request, err := NewRequested(controlTestTenant, "registration-one", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseRequested(controlTestTenant, wire); err != nil || got != request {
		t.Fatalf("canonical request failed: %v", err)
	}
	for _, malformed := range [][]byte{
		append(bytes.Clone(wire), []byte(` {}`)...),
		bytes.Replace(wire, []byte(`"retention_ns":1000000000`), []byte(`"retention_ns":1,"retention_ns":1000000000`), 1),
		bytes.Replace(wire, []byte(`"retention_ns":1000000000`), []byte(`"retention_ns":1000000000,"diagnostic":"private text"`), 1),
		bytes.Replace(wire, []byte(request.KeyID), []byte("262844c2-dc6b-446c-a1c4-042b2dca5285"), 1),
	} {
		if _, err := ParseRequested(controlTestTenant, malformed); err == nil {
			t.Fatal("ambiguous or changed command was accepted")
		}
	}
	if _, err := ParseRequested("2c14fe81-1956-4e9d-a174-e27a38e8e979", wire); err == nil {
		t.Fatal("request gained authority for a different tenant")
	}
	changed, err := NewRequested(controlTestTenant, request.RegistrationIdentity, 2*time.Second)
	if err != nil || changed.OperationID != request.OperationID {
		t.Fatal("changing the policy minted another operation for the same lifetime")
	}
	for _, registration := range []string{"", " leading", "trailing ", "a\x00b", "a\nb"} {
		if _, err := NewRequested(controlTestTenant, registration, time.Second); err == nil {
			t.Fatal("invalid lifetime identity was accepted")
		}
	}
}

func FuzzRequestedControl(f *testing.F) {
	request, err := NewRequested(controlTestTenant, "fuzz-registration", time.Second)
	if err != nil {
		f.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{"registration_identity":"x","retention_ns":0}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := ParseRequested(controlTestTenant, input)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(got)
		if err != nil || !bytes.Equal(canonical, input) || got.KeyID == "" || got.RetentionNanos <= 0 {
			t.Fatal("accepted non-canonical or unbound request")
		}
		if _, err := ParseRequested("2c14fe81-1956-4e9d-a174-e27a38e8e979", input); err == nil {
			t.Fatal("accepted request crossed tenant scope")
		}
	})
}
