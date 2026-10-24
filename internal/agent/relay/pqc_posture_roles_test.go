// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"path/filepath"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A104: posture work is claimable by the network role too, and a network
// relay that keeps a rollback store for it still asks for its whole claim set.
// A host agent with a store and no exec profile keeps asking only for its
// co-resident Envoy posture and its self-check.
func TestNetworkRelayWithARollbackStoreKeepsItsClaimSet(t *testing.T) {
	for _, kind := range []string{relay.KindPQCPosture, relay.KindPQCPostureRollback} {
		if roles := relay.ShippedJobVantages()[kind]; !slices.Contains(roles, mtls.AgentRoleHost) || !slices.Contains(roles, mtls.AgentRoleNetwork) {
			t.Fatalf("%s roles = %v; want host and network", kind, roles)
		}
	}
	store, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "rollbacks"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	network := &kindRecordingChannel{}
	if _, err := relay.RunOnceWithRoles(t.Context(), network, nil, connector.LocalOpsConfig{}, nil, nil, store,
		[]string{mtls.AgentRoleNetwork}, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(network.asked) != 1 || !slices.Equal(network.asked[0], relay.ClaimableKinds()) {
		t.Fatalf("network relay asked for %v; want its whole claim set %v", network.asked, relay.ClaimableKinds())
	}
	host := &kindRecordingChannel{}
	if _, err := relay.RunOnceWithRoles(t.Context(), host, nil, connector.LocalOpsConfig{}, nil, nil, store,
		[]string{mtls.AgentRoleHost}, 4, 30); err != nil {
		t.Fatal(err)
	}
	want := []string{relay.KindPQCPosture, relay.KindPQCPostureRollback, relay.KindAgentSelfCheck}
	if len(host.asked) != 1 || !slices.Equal(host.asked[0], want) {
		t.Fatalf("host agent without an exec profile asked for %v; want %v", host.asked, want)
	}
}
