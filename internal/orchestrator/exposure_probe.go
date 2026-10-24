// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Live reachability probing of exposed NHIs (A102).
//
// The exposure posture reads public endpoints and callback URLs out of
// discovery metadata. A probe asks a network relay to connect to exactly
// those endpoints, public addresses only, through the relay's ordinary
// endpoint.verify sweep, and records what answered: one discovery run under
// the product's exposure-probe source, one finding per endpoint. The control
// plane itself never dials them; network contact stays on a relay.

// ExposureProbeFindingKind is the discovery finding kind of one probed
// endpoint.
const ExposureProbeFindingKind = "nhi-exposure-probe"

// MaxExposureProbeEndpoints bounds one probe to one relay sweep.
const MaxExposureProbeEndpoints = 50

var exposureProbeSourceNamespace = uuid.MustParse("69dc889c-b7b4-4efa-833b-3f23c961ff36")

// ExposureProbeEndpoint is one public endpoint of one NHI inventory row.
type ExposureProbeEndpoint struct {
	InventoryID string
	Endpoint    string // as the exposure posture shows it
	Address     string // host:port the relay connects to
	ServerName  string
}

// exposureProbeEndpointID binds a sweep endpoint to its inventory row; the
// relay echoes it, and the control plane never trusts the address to match.
func exposureProbeEndpointID(inventoryID, address string) string {
	return "exposure|" + inventoryID + "|" + address
}

func exposureProbeInventoryID(endpointID string) (string, bool) {
	rest, ok := strings.CutPrefix(endpointID, "exposure|")
	if !ok {
		return "", false
	}
	i := strings.LastIndex(rest, "|")
	if i <= 0 {
		return "", false
	}
	return rest[:i], true
}

// Exposure probe outcomes, one per probed endpoint.
const (
	ExposureProbeTLSCertificate     = "tls_certificate"         // a TLS listener served a certificate
	ExposureProbeUnparseableLeaf    = "unparseable_certificate" // a TLS listener served something unparseable
	ExposureProbeListenerWithoutTLS = "listener_without_tls"    // the connection was accepted, TLS was not (plaintext, say)
	ExposureProbeNotPublic          = "not_public"              // the name resolved to a non-public address; the relay refused it
	ExposureProbeUnreachable        = "unreachable"             // nothing accepted the connection
)

// exposureProbeOutcome classifies one probed endpoint from its signed
// transcript. Reachable means something accepted the relay's connection at
// that address: a TLS identity, an unparseable one, or a listener that took
// the connection and then failed or refused TLS. A transcript's Reached is
// narrower (a completed handshake), and the probe stage named in its error
// tells a failed dial from a failed handshake.
func exposureProbeOutcome(tr transport.ProbeTranscript) (string, bool) {
	switch {
	case tr.Reached && tr.ObservedFingerprint != "":
		return ExposureProbeTLSCertificate, true
	case tr.Reached:
		return ExposureProbeUnparseableLeaf, true
	case strings.Contains(tr.Error, netsec.ErrSSRFBlocked.Error()):
		return ExposureProbeNotPublic, false
	case strings.HasPrefix(tr.Error, "tlsprobe: handshake ") || strings.HasPrefix(tr.Error, "tlsprobe: negotiate "):
		return ExposureProbeListenerWithoutTLS, true
	default:
		return ExposureProbeUnreachable, false
	}
}

func exposureProbeSourceID(tenantID string) string {
	return uuid.NewSHA1(exposureProbeSourceNamespace, []byte(tenantID+"\x00exposure-probe")).String()
}

// QueueExposureProbe records a queued discovery run for the probe and queues
// one public-only relay sweep of the endpoints. requestKey is the durable
// request identity, so a retried request converges on the same run and job.
func (o *Orchestrator) QueueExposureProbe(ctx context.Context, tenantID, requestKey, requestedBy string, endpoints []ExposureProbeEndpoint) (string, error) {
	if len(endpoints) == 0 || len(endpoints) > MaxExposureProbeEndpoints {
		return "", errors.New("orchestrator: an exposure probe needs 1-50 endpoints")
	}
	if o.outbox == nil {
		return "", errors.New("orchestrator: exposure probe outbox is unavailable")
	}
	sourceID := exposureProbeSourceID(tenantID)
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "nhi_exposure_probe", Name: sourcecatalog.ExposureProbeSourcePrefix + "relay",
		Config: json.RawMessage(`{"vantage":"relay","addresses":"public_only"}`),
	}); err != nil {
		return "", err
	}
	runID := uuid.NewSHA1(exposureProbeSourceNamespace, []byte(tenantID+"\x00"+requestKey)).String()
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: requestedBy})
	if err != nil {
		return "", err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, requestKey, "exposure-probe-run-queued"),
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued}); err != nil {
		return "", err
	}
	intent := relay.EndpointVerifyIntent{
		Endpoints: make([]relay.EndpointExpectation, 0, len(endpoints)),
		Exposure:  &relay.EndpointVerifyExposure{RequestID: requestKey, RunID: runID},
	}
	for _, e := range endpoints {
		intent.Endpoints = append(intent.Endpoints, relay.EndpointExpectation{
			EndpointID: exposureProbeEndpointID(e.InventoryID, e.Address), Address: e.Address, ServerName: e.ServerName,
		})
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: relay.KindEndpointVerify,
			IdempotencyKey: "exposure-probe:" + requestKey, Payload: payload,
		})
		return err
	})
	return runID, err
}

// RecordExposureProbe projects one relay's signed exposure sweep, already
// admitted, as the probe run's findings and completes the run. key is the
// sweep's durable job key, so a retried report converges.
func (o *Orchestrator) RecordExposureProbe(ctx context.Context, tenantID, agentName, key string, intent relay.EndpointVerifyIntent, report relay.EndpointVerifyReport) error {
	if intent.Exposure == nil || strings.TrimSpace(intent.Exposure.RunID) == "" {
		return errors.New("orchestrator: an exposure probe report needs its run")
	}
	runID, sourceID := intent.Exposure.RunID, exposureProbeSourceID(tenantID)
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, runID, DiscoveryRelayEventID(tenantID, key, "exposure-probe-run-started")); err != nil {
		return err
	}
	reachable := 0
	for _, result := range report.Results {
		inventoryID, ok := exposureProbeInventoryID(result.EndpointID)
		if !ok {
			return errors.New("orchestrator: an exposure probe result names no inventory row")
		}
		tr := result.Transcript
		outcome, answered := exposureProbeOutcome(tr)
		risk := 10
		if answered {
			reachable++
			risk = 80
		}
		observedAt := time.Unix(tr.ObservedAtUnix, 0).UTC()
		meta := map[string]any{
			"inventory_id": inventoryID, "address": tr.Address, "server_name": tr.ServerName, "outcome": outcome,
			"reachable": answered, "vantage": string(tr.Vantage), "agent": agentName,
		}
		if tr.ObservedFingerprint != "" {
			meta["observed_fingerprint"] = strings.ToLower(tr.ObservedFingerprint)
			meta["not_after"] = time.Unix(tr.NotAfterUnix, 0).UTC().Format(time.RFC3339)
		}
		if tr.Error != "" {
			meta["error"] = tr.Error
		}
		raw, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "exposure-probe-finding:"+result.EndpointID), store.DiscoveryFinding{
			// The ref names the NHI and its endpoint, so two NHIs behind one
			// host stay two observations; each outcome (a served leaf, or
			// nothing) is its own finding, and the posture reads the latest.
			RunID: runID, SourceID: sourceID, Kind: ExposureProbeFindingKind, Ref: inventoryID + "@" + tr.Address,
			Provenance: "exposure-probe:" + inventoryID, Fingerprint: strings.ToLower(tr.ObservedFingerprint),
			RiskScore: risk, Metadata: raw, DiscoveredAt: observedAt,
		}); err != nil {
			return err
		}
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "exposure-probe-run-completed"),
		store.DiscoveryRun{ID: runID, Status: "succeeded", Targets: len(report.Results), Discovered: reachable})
}
