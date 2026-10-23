// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// EndpointChainFindingKind is the discovery finding kind recorded when a
// listener serves the deployed leaf with other issuers than were written
// (B10-L1). Verification passes on the leaf, so the chain mismatch stays
// visible as a posture finding until it is triaged.
const EndpointChainFindingKind = "endpoint-chain-mismatch"

var endpointChainSourceNamespace = uuid.MustParse("6672dd1c-34b6-478b-b488-e8bb1c29e000")

// EndpointChainMismatch is one accepted chain-only mismatch.
type EndpointChainMismatch struct {
	EndpointID      string
	Address         string
	ServerName      string
	Connector       string
	Target          string
	LeafFingerprint string
	Rollback        bool
	ObservedAt      time.Time
}

// RecordEndpointChainMismatch records an accepted chain-only mismatch as one
// finding under the product's own endpoint-verification source, in a run of
// its own. key is the durable job key of the signed verification report, so
// a retried report converges on the same events.
func (o *Orchestrator) RecordEndpointChainMismatch(ctx context.Context, tenantID, key string, m EndpointChainMismatch) error {
	sourceID := uuid.NewSHA1(endpointChainSourceNamespace, []byte(tenantID+"\x00endpoint-chain")).String()
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "endpoint_chain_verification", Name: sourcecatalog.EndpointChainSourcePrefix + "deploy-verification",
		Config: json.RawMessage(`{"check":"issuer_chain"}`),
	}); err != nil {
		return err
	}
	runID := uuid.NewSHA1(endpointChainSourceNamespace, []byte(tenantID+"\x00"+key)).String()
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: "system:endpoint-verification"})
	if err != nil {
		return err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, key, "endpoint-chain-run-queued"),
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued}); err != nil {
		return err
	}
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, runID, DiscoveryRelayEventID(tenantID, key, "endpoint-chain-run-started")); err != nil {
		return err
	}
	verification := "deploy"
	if m.Rollback {
		verification = "rollback"
	}
	meta, err := json.Marshal(map[string]any{
		"endpoint_id": m.EndpointID, "server_name": m.ServerName, "connector": m.Connector, "target": m.Target,
		"verification": verification, "mismatch": "chain",
		"reason": "the listener serves the deployed leaf with other issuers than were written; set strict_chain on the target to fail on this",
	})
	if err != nil {
		return err
	}
	if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "endpoint-chain-finding"), store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: EndpointChainFindingKind, Ref: strings.TrimSpace(m.Address),
		Provenance: "endpoint-verification:" + m.EndpointID, Fingerprint: strings.ToLower(strings.TrimSpace(m.LeafFingerprint)),
		RiskScore: 40, Metadata: meta, DiscoveredAt: m.ObservedAt,
	}); err != nil {
		return err
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "endpoint-chain-run-completed"),
		store.DiscoveryRun{ID: runID, Status: "succeeded", Targets: 1, Discovered: 1})
}
