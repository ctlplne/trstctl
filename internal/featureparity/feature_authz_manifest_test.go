// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"strings"
	"testing"
)

func TestFeatureRBACEvidenceReferencesAuthzManifests(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature catalog: %v", err)
	}
	protocolFeatureIDs := map[string]bool{
		"F5": true, "F46": true, "F69": true, "F70": true, "F71": true, "F72": true, "F73": true, "F74": true,
		"F22": true, "F23": true, "F55": true, "F56": true,
		"F24": true, "F25": true, "F30": true,
		"F43": true, "F45": true,
		"F51": true,
	}
	for _, item := range catalog.Items {
		rbacText := strings.ToLower(strings.Join(append(append([]string{}, item.FacetEvidence.RBAC.Evidence...), item.FacetEvidence.RBAC.Refs...), "\n"))
		if len(item.APISurface) > 0 {
			if !strings.Contains(rbacText, "feature authz manifest") || !strings.Contains(rbacText, "internal/api/feature_authz_test.go") {
				t.Errorf("%s API RBAC evidence must reference the API feature authz manifest/test; got %+v", item.FeatureID, item.FacetEvidence.RBAC)
			}
		}
		if protocolFeatureIDs[item.FeatureID] {
			if !strings.Contains(rbacText, "protocol authz manifest") || !strings.Contains(rbacText, "internal/server/protocol_authz.go") || !strings.Contains(rbacText, "internal/server/protocol_authz_test.go") {
				t.Errorf("%s protocol RBAC evidence must reference the protocol authz manifest/test; got %+v", item.FeatureID, item.FacetEvidence.RBAC)
			}
		}
	}
}
