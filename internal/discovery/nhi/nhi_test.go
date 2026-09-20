// SPDX-License-Identifier: BUSL-1.1

package nhi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateConfigReportsEveryMissingSurfaceTogether(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(Config{Observations: []Observation{{
		Surface:    "idp",
		System:     "okta",
		ExternalID: "app/payments",
	}}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	err = ValidateConfig(raw)
	if err == nil {
		t.Fatal("ValidateConfig accepted a source missing five required surfaces")
	}
	for _, want := range []string{"cloud", "saas", "on_prem", "code", "ci"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("ValidateConfig error %q does not name missing surface %q", err, want)
		}
	}
}
