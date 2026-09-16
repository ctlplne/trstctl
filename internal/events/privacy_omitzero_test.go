// SPDX-License-Identifier: MPL-2.0

package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPrivacyPayloadShapeMatchesOmitZeroWithoutWeakeningOmitEmpty(t *testing.T) {
	type nested struct {
		Value string `json:"value"`
	}
	type payload struct {
		ZeroTime       time.Time `json:"zero_time,omitzero"`
		ZeroStruct     nested    `json:"zero_struct,omitzero"`
		ZeroArray      [1]string `json:"zero_array,omitzero"`
		RequiredTime   time.Time `json:"required_time,omitempty"`
		RequiredStruct nested    `json:"required_struct,omitempty"`
	}
	const eventType = "privacy.policy.omitzero-wire-presence.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{PayloadShape: PrivacyPayloadShapeOf[payload](), RejectSubjectData: true}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []payload{{}, {ZeroTime: time.Unix(1_900_000_000, 0).UTC(), ZeroStruct: nested{Value: "present"}, ZeroArray: [1]string{"present"}}} {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRegisteredPrivacyEventPayload(wire, eventType, 1); err != nil {
			t.Errorf("actual producer wire form rejected: %s: %v", wire, err)
		}
	}
	for _, wire := range []string{
		`{}`,
		`{"required_time":"0001-01-01T00:00:00Z"}`,
		`{"required_struct":{"value":""}}`,
		`{"required_time":"0001-01-01T00:00:00Z","required_struct":{"value":""},"zero_time":42}`,
		`{"required_time":"0001-01-01T00:00:00Z","required_struct":{"value":""},"unknown_identity":"unregistered"}`,
	} {
		if err := validateRegisteredPrivacyEventPayload([]byte(wire), eventType, 1); err == nil {
			t.Errorf("accepted deleted required field or closed-shape drift: %s", wire)
		}
	}
}

func TestPrivacyOmitZeroDoesNotRemovePromotedRequiredFields(t *testing.T) {
	type Embedded struct {
		Value string `json:"value"`
	}
	type payload struct {
		Embedded `json:",omitzero"`
	}
	const eventType = "privacy.policy.omitzero-promoted-fields.test"
	if err := RegisterPrivacyEventPolicy(eventType, 1, PrivacyEventPolicy{PayloadShape: PrivacyPayloadShapeOf[payload](), RejectSubjectData: true}); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(payload{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRegisteredPrivacyEventPayload(wire, eventType, 1); err != nil {
		t.Fatalf("promoted producer fields refused: %s: %v", wire, err)
	}
	if err := validateRegisteredPrivacyEventPayload([]byte(`{}`), eventType, 1); err == nil {
		t.Fatal("omitzero parent removed a producer-required promoted field")
	}
}
