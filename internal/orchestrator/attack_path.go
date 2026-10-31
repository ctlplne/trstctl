// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Provider-native attack-path validation (A167).
//
// A live probe (A102) shows what answered from a relay. Attack-path
// validation asks the cloud that hosts an exposed endpoint whether its own
// network configuration admits the internet to it — route table, network ACL
// and security groups — and names the resource that decides. It runs against
// an operator's cloud_network_path discovery source, whose read-only
// credentials the control plane resolves when the row executes, and records
// one discovery finding per endpoint under that source.

// AttackPathFindingKind is the discovery finding kind of one validated
// endpoint.
const AttackPathFindingKind = "nhi-attack-path"

// AttackPathSourceKind is the discovery source kind that carries a cloud
// account's read-only network credentials.
const AttackPathSourceKind = "cloud_network_path"

// AttackPathJobKind marks a validation's discovery.run.queued event. Its
// validation row is enqueued in the same transaction, so outbox reconciliation
// must not restore a discovery.run job for it.
const AttackPathJobKind = "nhi_attack_path"

// DestinationAttackPathValidate is the control-plane row that reads the cloud
// configuration and records the findings.
const DestinationAttackPathValidate = "nhi.attack_path.validate"

// MaxAttackPathEndpoints bounds one validation.
const MaxAttackPathEndpoints = 50

var attackPathNamespace = uuid.MustParse("2f2b6b8e-1d7c-4c47-9a0e-a1670a1670a1")

// AttackPathEndpoint is one public address and port of one NHI inventory row.
type AttackPathEndpoint struct {
	InventoryID string `json:"inventory_id"`
	Endpoint    string `json:"endpoint"`
	Address     string `json:"address"` // ip:port
}

// AttackPathIntent is the validation row's payload: public identity and
// addresses only; credentials stay behind the source's references.
type AttackPathIntent struct {
	RunID     string               `json:"run_id"`
	SourceID  string               `json:"source_id"`
	Endpoints []AttackPathEndpoint `json:"endpoints"`
}

// ErrAttackPathSource refuses a validation whose source is missing or of
// another kind.
var ErrAttackPathSource = errors.New("orchestrator: attack-path validation needs a cloud_network_path discovery source")

// QueueAttackPathValidation records a queued discovery run under the named
// source and queues its validation row in the same transaction. requestKey is
// the durable request identity, so a retried request converges on one run.
func (o *Orchestrator) QueueAttackPathValidation(ctx context.Context, tenantID, requestKey, requestedBy, sourceID string, endpoints []AttackPathEndpoint) (string, error) {
	if len(endpoints) == 0 || len(endpoints) > MaxAttackPathEndpoints {
		return "", errors.New("orchestrator: an attack-path validation needs 1-50 endpoints")
	}
	if o.outbox == nil {
		return "", errors.New("orchestrator: attack-path outbox is unavailable")
	}
	source, err := o.store.GetDiscoverySource(ctx, tenantID, strings.TrimSpace(sourceID))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && source.Kind != AttackPathSourceKind) {
		return "", ErrAttackPathSource
	}
	if err != nil {
		return "", err
	}
	runID := uuid.NewSHA1(attackPathNamespace, []byte(tenantID+"\x00"+requestKey)).String()
	if existing, err := o.store.GetDiscoveryRun(ctx, tenantID, runID); err == nil && existing.Status != "queued" {
		return runID, nil
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: source.ID, RequestedBy: requestedBy,
		JobKind: AttackPathJobKind, Execution: "control_plane"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(AttackPathIntent{RunID: runID, SourceID: source.ID, Endpoints: endpoints})
	if err != nil {
		return "", err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, requestKey, "attack-path-run-queued"),
			Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued})
		if err != nil {
			return err
		}
		if ev.Type != projections.EventDiscoveryRunQueued || ev.TenantID != tenantID || !bytes.Equal(ev.Data, queued) {
			return fmt.Errorf("%w: attack-path run event differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationAttackPathValidate,
			IdempotencyKey: "attack-path:" + requestKey, Payload: payload, RequiredAgentRole: "control_plane",
		})
		return err
	})
	return runID, err
}

// AttackPathObservation is one endpoint's verdict as the validation row read it.
type AttackPathObservation struct {
	Endpoint AttackPathEndpoint
	Metadata map[string]any // status, blocked_by, resource, rule, path, reason
	Open     bool
}

// RecordAttackPathValidation projects one validation's verdicts as the run's
// findings and completes the run. key is the row's idempotency key, so a
// redelivered row converges.
func (o *Orchestrator) RecordAttackPathValidation(ctx context.Context, tenantID, key string, intent AttackPathIntent, observed []AttackPathObservation, at time.Time) error {
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, intent.RunID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-started")); err != nil {
		return err
	}
	open := 0
	for _, obs := range observed {
		risk := 10
		if obs.Open {
			open++
			risk = 85
		}
		meta := map[string]any{"inventory_id": obs.Endpoint.InventoryID, "endpoint": obs.Endpoint.Endpoint, "address": obs.Endpoint.Address}
		for k, v := range obs.Metadata {
			meta[k] = v
		}
		raw, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		ref := obs.Endpoint.InventoryID + "@" + obs.Endpoint.Address
		if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "attack-path-finding:"+ref), store.DiscoveryFinding{
			RunID: intent.RunID, SourceID: intent.SourceID, Kind: AttackPathFindingKind, Ref: ref,
			Provenance: "attack-path:" + obs.Endpoint.InventoryID, RiskScore: risk, Metadata: raw, DiscoveredAt: at,
		}); err != nil {
			return err
		}
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-completed"),
		store.DiscoveryRun{ID: intent.RunID, Status: "succeeded", Targets: len(observed), Discovered: open})
}

// FailAttackPathValidation completes a validation's run as failed with the
// reason, when its source cannot be read at all (an unset credential
// reference, a rejected endpoint): no endpoint is judged on a broken source.
func (o *Orchestrator) FailAttackPathValidation(ctx context.Context, tenantID, key string, intent AttackPathIntent, reason string) error {
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, intent.RunID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-started")); err != nil {
		return err
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-completed"),
		store.DiscoveryRun{ID: intent.RunID, Status: "failed", Targets: len(intent.Endpoints), Failed: len(intent.Endpoints), Error: reason})
}
