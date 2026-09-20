// SPDX-License-Identifier: BUSL-1.1

package f5

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// HA-peer sync for F5 BIG-IP pairs (epic E1).
//
// An active/standby BIG-IP pair keeps its certificate objects in SEPARATE
// configuration stores: config-sync propagates virtual-server and profile
// definitions, but the crypto objects a profile binds to do not replicate.
// So a deploy that reaches one peer reports success while the other keeps
// presenting the previous certificate — and that gap does not surface until a
// failover, at which point the standby serves a certificate that expired
// months ago while every receipt read green.
//
// That is why migrating F5 to the relay without this would make the migrated
// path WRONG rather than merely incomplete: it would retire the control
// plane's deploy for one that silently updates half an HA pair. HAPair closes
// the gap by treating the pair as one target — a deploy must reach BOTH peers
// or fail, a rollback re-binds BOTH, and a readback reports the pair as serving
// only when BOTH peers are bound to the deployed certificate.

// HAPair deploys to and reads back both peers of an F5 HA pair. It is a
// Connector in its own right so the relay runtime, the conformance suite, and
// the rollback/readback machinery drive it exactly like a single appliance.
type HAPair struct {
	peers []*Connector
}

var (
	_ connector.Connector  = (*HAPair)(nil)
	_ connector.Rollbacker = (*HAPair)(nil)
	_ connector.Readbacker = (*HAPair)(nil)
)

// NewHAPair returns an HA connector over the given peers (each a full F5
// connector against one appliance in the pair). At least one peer is required;
// with a single peer it behaves exactly like that connector, so a caller need
// not special-case "no peer configured".
func NewHAPair(peers ...*Connector) *HAPair {
	kept := make([]*Connector, 0, len(peers))
	for _, p := range peers {
		if p != nil {
			kept = append(kept, p)
		}
	}
	return &HAPair{peers: kept}
}

// Name identifies the connector as f5 — the pair is one F5 target, not a new
// family.
func (h *HAPair) Name() string { return "f5" }

// Capabilities grants net.dial to EVERY peer's host. Each peer computed its own
// one-host grant; the union is what a pair deploy needs, and nothing wider —
// pluginhost.Allows admits a resource matching any one constraint.
func (h *HAPair) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapNetDial)
	for _, p := range h.peers {
		g = g.WithPathPrefix(pluginhost.CapNetDial, p.host)
	}
	return g
}

// Deploy installs the certificate on BOTH peers. It fails if any peer fails,
// and the failure names the peer — a pair deploy that reached only the active
// node is the exact defect this type exists to prevent, so a partial success
// must read as a failure, not a success with a warning.
func (h *HAPair) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if len(h.peers) == 0 {
		return fmt.Errorf("f5 ha: no peers configured")
	}
	for i, p := range h.peers {
		if err := p.Deploy(ctx, sb, dep); err != nil {
			return fmt.Errorf("f5 ha: peer %d (%s): %w", i, p.host, err)
		}
	}
	return nil
}

// Rollback re-binds BOTH peers to the predecessor. Same reasoning as Deploy: a
// rollback that restored only the active node would leave the standby serving
// the bad certificate after a failover.
func (h *HAPair) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if len(h.peers) == 0 {
		return fmt.Errorf("f5 ha: no peers configured")
	}
	for i, p := range h.peers {
		if err := p.Rollback(ctx, sb, rb); err != nil {
			return fmt.Errorf("f5 ha: peer %d (%s): %w", i, p.host, err)
		}
	}
	return nil
}

// Readback reports the pair as serving ONLY when every peer is bound to the
// same certificate. A pair where the peers disagree — one updated, one behind —
// is reported not-bound, because from a client's perspective across a failover
// the pair is not reliably serving the new certificate. That is the whole point
// of asking both: a single-peer readback would confirm the active node and miss
// exactly the standby that hurts.
func (h *HAPair) Readback(ctx context.Context, sb connector.Sandbox, target string) (connector.Installed, error) {
	if len(h.peers) == 0 {
		return connector.Installed{}, fmt.Errorf("f5 ha: no peers configured")
	}
	first, err := h.peers[0].Readback(ctx, sb, target)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("f5 ha: peer 0 (%s): %w", h.peers[0].host, err)
	}
	for i := 1; i < len(h.peers); i++ {
		got, err := h.peers[i].Readback(ctx, sb, target)
		if err != nil {
			return connector.Installed{}, fmt.Errorf("f5 ha: peer %d (%s): %w", i, h.peers[i].host, err)
		}
		if got.Fingerprint != first.Fingerprint || got.Bound != first.Bound {
			// The peers do not agree. Report the deployed-side fingerprint (so
			// the classifier does not read it as diverged-to-something-else)
			// with Bound=false, which classifies as installed_not_bound — the
			// verdict that says "the object may be present but the pair is not
			// uniformly serving it", which is precisely true here.
			return connector.Installed{
				Fingerprint: first.Fingerprint,
				ObjectName:  first.ObjectName + " (HA peer divergence)",
				Bound:       false,
			}, nil
		}
	}
	return first, nil
}

// Close zeroizes every peer's held credential.
func (h *HAPair) Close() {
	for _, p := range h.peers {
		p.Close()
	}
}
