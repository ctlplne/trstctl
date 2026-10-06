// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

func TestAgentResponseAdvertisesOnlyCertificateRoleJobCapabilities(t *testing.T) {
	tests := []struct {
		name           string
		roles          []string
		wantKinds      []string
		absentKinds    []string
		wantConnectors []string
		absentTargets  []string
		wantFlags      []string
		absentFlags    []string
	}{
		{
			name: "host", roles: []string{mtls.AgentRoleHost},
			wantKinds:      []string{"endpoint.contain", "endpoint.renew", "connector.deploy"},
			absentKinds:    []string{"discovery.run", "endpoint.verify"},
			wantConnectors: []string{"apache"}, absentTargets: []string{"f5"},
			wantFlags: []string{"--host-exec-profile", "--host-rollback-dir"},
		},
		{
			name: "network", roles: []string{mtls.AgentRoleNetwork},
			wantKinds:      []string{"discovery.run", "endpoint.verify", "connector.deploy"},
			absentKinds:    []string{"endpoint.contain", "endpoint.renew"},
			wantConnectors: []string{"f5"}, absentTargets: []string{"apache"},
			absentFlags: []string{"--host-exec-profile", "--host-rollback-dir"},
		},
		{
			name: "unreported", absentKinds: []string{"endpoint.contain", "discovery.run", "connector.deploy"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toAgentResponse(store.Agent{ID: "11111111-1111-1111-1111-111111111111", Roles: tc.roles})
			kinds := map[string]agentRelayCapabilityResponse{}
			for _, capability := range got.RelayCapabilities {
				if _, duplicate := kinds[capability.Kind]; duplicate {
					t.Errorf("duplicate advertised job kind %s", capability.Kind)
				}
				kinds[capability.Kind] = capability
				for _, connector := range tc.absentTargets {
					if slices.Contains(capability.Connectors, connector) {
						t.Errorf("%s advertises connector %s outside its role", capability.Kind, connector)
					}
				}
				for _, flag := range tc.absentFlags {
					if slices.Contains(capability.EnableFlags, flag) {
						t.Errorf("%s advertises flag %s outside its role", capability.Kind, flag)
					}
				}
			}
			for _, kind := range tc.wantKinds {
				if _, ok := kinds[kind]; !ok {
					t.Errorf("role %v does not advertise executable job %s", tc.roles, kind)
				}
			}
			for _, kind := range tc.absentKinds {
				if _, ok := kinds[kind]; ok {
					t.Errorf("role %v advertises unclaimable job %s", tc.roles, kind)
				}
			}
			deploy := kinds["connector.deploy"]
			for _, connector := range tc.wantConnectors {
				if !slices.Contains(deploy.Connectors, connector) {
					t.Errorf("role %v omits executable connector %s", tc.roles, connector)
				}
			}
			for _, flag := range tc.wantFlags {
				found := false
				for _, capability := range got.RelayCapabilities {
					found = found || slices.Contains(capability.EnableFlags, flag)
				}
				if !found {
					t.Errorf("role %v omits required flag %s", tc.roles, flag)
				}
			}
			if len(tc.roles) == 0 && len(got.RelayCapabilities) != 0 {
				t.Errorf("agent with no reported certificate role advertises %d jobs", len(got.RelayCapabilities))
			}
		})
	}
}
