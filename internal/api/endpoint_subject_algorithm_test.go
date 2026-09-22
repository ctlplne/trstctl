// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"encoding/json"
	"testing"
)

func TestEndpointSubjectChoiceKeepsExistingAndReplacementAlgorithm(t *testing.T) {
	original := &identityResponse{Attributes: json.RawMessage(`{"subject_key_algorithm":"ML-DSA-65"}`)}
	for _, test := range []struct {
		name, requested    string
		existing, replaced *identityResponse
		want               string
	}{
		{"new default", "", nil, nil, ""},
		{"existing omitted", "", original, nil, "ML-DSA-65"},
		{"replacement omitted", "", nil, original, "ML-DSA-65"},
		{"explicit replacement", "ML-DSA-87", nil, original, "ML-DSA-87"},
		{"explicit classical replacement", "ECDSA-P256", nil, original, "ECDSA-P256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := endpointSubjectChoice(test.requested, test.existing, test.replaced)
			if err != nil || got != test.want {
				t.Fatalf("got %q %v, want %q", got, err, test.want)
			}
		})
	}
	for _, raw := range []string{`{"subject_key_algorithm":3}`, `{"subject_key_algorithm":"ML-DSA-unknown"}`, `{"subject_key_algorithm":null}`, `{"subject_key_algorithm":""}`, `{"subject_key_algorithm":" "}`} {
		identity := &identityResponse{Attributes: json.RawMessage(raw)}
		for _, replacement := range []bool{false, true} {
			existing, replaced := identity, (*identityResponse)(nil)
			if replacement {
				existing, replaced = nil, identity
			}
			if _, err := endpointSubjectChoice("", existing, replaced); err == nil {
				t.Fatalf("accepted unreviewable saved intent (replacement=%v): %s", replacement, raw)
			}
		}
	}
	for _, raw := range []string{`{}`, `{"unrelated":"field"}`} {
		if got, err := endpointSubjectChoice("", &identityResponse{Attributes: json.RawMessage(raw)}, nil); err != nil || got != "" {
			t.Fatalf("missing legacy choice rejected: %q %v", got, err)
		}
	}
}
func TestEndpointSubjectChoiceRequiresAHostConnector(t *testing.T) {
	for _, target := range []endpointBindingTargetSummary{
		{Connector: "nginx", Config: json.RawMessage(`{"executor":"control_plane"}`)},
		{Connector: "f5", Config: json.RawMessage(`{"executor":"agent"}`)},
	} {
		if err := validateEndpointSubjectChoice("ML-DSA-65", target); err == nil {
			t.Fatalf("non-host target accepted: %s", target.Connector)
		}
	}
	if err := validateEndpointSubjectChoice("ML-DSA-65", endpointBindingTargetSummary{Connector: "nginx", Config: json.RawMessage(`{"executor":"agent"}`)}); err != nil {
		t.Fatal(err)
	}
}
