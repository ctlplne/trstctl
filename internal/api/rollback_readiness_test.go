// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// A target says whether a rollback would find anything to restore (A46), with
// the same refusals the rollback route gives, before an operator relies on it.
func TestRollbackReadinessMirrorsTheRollbackRouteRefusals(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		in     rollbackReadinessInputs
		model  string
		ready  bool
		reason string
	}{
		"family without rollback":                       {rollbackReadinessInputs{Family: "cisco"}, "none", false, "no executable rollback"},
		"host target never deployed":                    {rollbackReadinessInputs{Family: "nginx", HostRollback: true}, "host", false, "no successful enrolled host-agent deploy"},
		"host target deployed once":                     {rollbackReadinessInputs{Family: "nginx", HostRollback: true, HostEvidenceFound: true, HostIdentityID: "id-1", HostFingerprint: "ff"}, "host", false, "second successful deploy"},
		"host target with retained predecessor":         {rollbackReadinessInputs{Family: "nginx", HostRollback: true, HostEvidenceFound: true, HostIdentityID: "id-1", HostFingerprint: "ff", HostPredecessorFingerprint: "ee", PredecessorKnown: true}, "host", true, ""},
		"host predecessor revoked":                      {rollbackReadinessInputs{Family: "nginx", HostRollback: true, HostEvidenceFound: true, HostIdentityID: "id-1", HostFingerprint: "ff", HostPredecessorFingerprint: "ee", PredecessorKnown: true, PredecessorRevoked: true}, "host", false, "revoked"},
		"fortigate without bind_to":                     {rollbackReadinessInputs{Family: "fortigate", Rebind: true, Config: []byte(`{"endpoint":"https://fgt"}`)}, "re-bind", false, "bind_to"},
		"paloalto without commit_admin":                 {rollbackReadinessInputs{Family: "paloalto", Rebind: true, Config: []byte(`{"ssl_tls_profile":"web"}`)}, "re-bind", false, "commit_admin"},
		"f5 with no bound identity":                     {rollbackReadinessInputs{Family: "f5", Rebind: true, Config: []byte(`{}`)}, "re-bind", false, "no identity is bound"},
		"f5 bound identity without predecessor":         {rollbackReadinessInputs{Family: "f5", Rebind: true, Config: []byte(`{}`), BoundIdentityID: "id-1"}, "re-bind", false, "no predecessor certificate"},
		"f5 predecessor never deployed through trstctl": {rollbackReadinessInputs{Family: "f5", Rebind: true, Config: []byte(`{}`), BoundIdentityID: "id-1", PredecessorKnown: true, PredecessorFingerprint: "ee", PredecessorSerial: "7"}, "re-bind", false, "never delivered"},
		"f5 ready": {rollbackReadinessInputs{Family: "f5", Rebind: true, Config: []byte(`{}`), BoundIdentityID: "id-1", PredecessorKnown: true, PredecessorFingerprint: "ee", PredecessorSerial: "7", PredecessorDeliveredHere: true}, "re-bind", true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := rollbackReadinessFrom(tc.in)
			if got.Model != tc.model || got.Ready != tc.ready || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("readiness = %+v; want model %q ready %v reason containing %q", got, tc.model, tc.ready, tc.reason)
			}
			if got.Ready && (got.PredecessorFingerprint == "" || got.IdentityID == "") {
				t.Fatalf("a ready verdict names no predecessor or identity: %+v", got)
			}
		})
	}
}
