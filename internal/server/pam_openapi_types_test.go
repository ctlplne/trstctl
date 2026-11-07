// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestOpenAPISessionSchemasAdmitEverySessionTargetTypeA273: every target type
// a session is opened on (every provider-backed or vaulted gateway type, and
// SSH) is a value the published session request, approval, activation and
// emergency session schemas admit, so a typed client can ask for it.
func TestOpenAPISessionSchemasAdmitEverySessionTargetTypeA273(t *testing.T) {
	raw, err := os.ReadFile("../api/testdata/openapi.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	want := []string{pamTargetSSH}
	for targetType := range pamDatabaseProviderTypes {
		want = append(want, targetType)
	}
	for _, schema := range []string{"PAMSessionRequest", "PAMApprovalRequest", "PAMSessionActivationRequest", "PAMEmergencySessionRequest"} {
		admitted := spec.Components.Schemas[schema].Properties["target_type"].Enum
		for _, targetType := range want {
			if !slices.Contains(admitted, targetType) {
				t.Errorf("%s.target_type does not admit %q", schema, targetType)
			}
		}
	}
}
