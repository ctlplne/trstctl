// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
)

func TestCloudFingerprintSurvivesJSONObjectOrderA264(t *testing.T) {
	value := Assessment{Version: 1, Provider: "aws-iam", Identity: awsiam.Identity{TrustDocument: json.RawMessage(`{"Version":"2012-10-17","Statement":{"Principal":"*","Effect":"Allow"}}`)}}
	before, err := Fingerprint(value)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var sorted map[string]any
	if err = json.Unmarshal(raw, &sorted); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(sorted)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAssessment(raw)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("JSON object reordering invalidated identical typed evidence")
	}
	decoded.RiskScore++
	changed, err := Fingerprint(decoded)
	if err != nil || changed == before {
		t.Fatal("typed evidence tampering did not change fingerprint")
	}
}

func TestCloudFingerprintPreservesJSONBNumberMeaningA264(t *testing.T) {
	value := Assessment{Version: 1, Provider: "aws-iam", Identity: awsiam.Identity{TrustDocument: json.RawMessage(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"NumericLessThan":{"sts:DurationSeconds":1e2}}}}`)}}
	before, err := Fingerprint(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Identity.TrustDocument = json.RawMessage(`{"Statement":{"Condition":{"NumericLessThan":{"sts:DurationSeconds":100.00}},"Action":"sts:AssumeRole","Principal":"*","Effect":"Allow"},"Version":"2012-10-17"}`)
	after, err := Fingerprint(value)
	if err != nil || before != after {
		t.Fatal("equivalent JSONB numeric spelling changed typed fingerprint")
	}
	value.Identity.TrustDocument = json.RawMessage(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"NumericLessThan":{"sts:DurationSeconds":101}}}}`)
	changed, err := Fingerprint(value)
	if err != nil || changed == before {
		t.Fatal("different numeric fact retained fingerprint")
	}
}
