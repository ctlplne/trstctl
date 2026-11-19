// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
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

const AttackPathRefusedOriginField = "credential_refused_origin"
const attackPathProviderReadPrefix = "the provider could not be read: "

var attackPathReaderStatus = regexp.MustCompile(`^(?:awsnetpath: [A-Za-z]+|(?:azurenetpath|gcpnetpath): GET /[^\r\n]*): status ([45][0-9]{2}) \(response body redacted\)$`)

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
	Endpoint      AttackPathEndpoint
	Metadata      map[string]any // status, blocked_by, resource, rule, path, reason
	RefusedOrigin string         // exact destination refused by the credential pin
	Open          bool
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
		if obs.Open {
			open++
		}
		finding, err := AttackPathFinding(intent.RunID, intent.SourceID, obs, at)
		if err != nil {
			return err
		}
		if _, err := o.RecordAttackPathFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "attack-path-finding:"+finding.Ref), finding); err != nil {
			return err
		}
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-completed"),
		store.DiscoveryRun{ID: intent.RunID, Status: "succeeded", Targets: len(observed), Discovered: open})
}

// AttackPathFinding is the finding one address's verdict becomes under a
// run: its ref names the record and the address, its metadata carries the
// verdict, and an open path carries a high risk score.
func AttackPathFinding(runID, sourceID string, obs AttackPathObservation, at time.Time) (store.DiscoveryFinding, error) {
	risk := 10
	if obs.Open {
		risk = 85
	}
	meta := map[string]any{"inventory_id": obs.Endpoint.InventoryID, "endpoint": obs.Endpoint.Endpoint, "address": obs.Endpoint.Address}
	for k, v := range obs.Metadata {
		meta[k] = v
	}
	delete(meta, AttackPathRefusedOriginField)
	var refusedOrigin string
	if reason, ok := meta["reason"].(string); ok {
		safe := AttackPathFindingDiagnostic(reason)
		meta["reason"] = safe
		if safe == attackPathProviderReadPrefix+DiscoveryDestinationPinRefusal {
			refusedOrigin = discoveryRefusedOrigin(obs.RefusedOrigin)
		}
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	return store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: AttackPathFindingKind, Ref: obs.Endpoint.InventoryID + "@" + obs.Endpoint.Address,
		Provenance: "attack-path:" + obs.Endpoint.InventoryID, RiskScore: risk, Metadata: raw, DiscoveredAt: at,
		AttackPathRefusedOrigin: refusedOrigin,
	}, nil
}

// AttackPathFindingDiagnostic keeps provider read failures out of finding
// history and removes raw provider detail from historical API views.
func AttackPathFindingDiagnostic(reason string) string {
	detail, found := strings.CutPrefix(reason, attackPathProviderReadPrefix)
	if !found {
		return reason
	}
	var class string
	if match := attackPathReaderStatus.FindStringSubmatch(detail); match != nil {
		class = discoveryStatusDiagnostic(match[1])
	} else {
		class = SanitizeDiscoveryRunError(detail)
	}
	if class == "" || class == discoveryRunErrorWithheld {
		return "the provider could not be read. Check connectivity and provider access."
	}
	return attackPathProviderReadPrefix + class
}

// AttackPathFindingDisplayReason can show a pinned destination carried as a
// separate finding fact. An old free-text reason supplies only its class.
func AttackPathFindingDisplayReason(reason, refusedOrigin string) string {
	safe := AttackPathFindingDiagnostic(reason)
	if origin := discoveryRefusedOrigin(refusedOrigin); origin != "" && safe == attackPathProviderReadPrefix+DiscoveryDestinationPinRefusal {
		return attackPathProviderReadPrefix + discoveryOriginPinDiagnostic(origin)
	}
	return safe
}

// A retained finding owns its projection. New commands may reproduce its
// facts after a diagnostic migration or rewrite cleared a display value.
func sameAttackPathFinding(retained, next events.Event) bool {
	if retained.SchemaVersion == next.SchemaVersion {
		if bytes.Equal(retained.Data, next.Data) {
			return true
		}
		var cleared struct {
			Origin *string `json:"refused_origin"`
		}
		var prior, candidate projections.DiscoveryAttackPathFindingRecorded
		if json.Unmarshal(retained.Data, &cleared) != nil || json.Unmarshal(retained.Data, &prior) != nil ||
			json.Unmarshal(next.Data, &candidate) != nil {
			return false
		}
		// An empty origin is omitted by a producer and present when a
		// privacy rewrite cleared it. The other event facts must still match.
		if cleared.Origin == nil || *cleared.Origin != "" {
			return false
		}
		candidate.RefusedOrigin = ""
		return reflect.DeepEqual(prior, candidate)
	}
	if retained.SensitiveErased || retained.SchemaVersion != events.DefaultSchemaVersion {
		return false
	}
	var prior projections.DiscoveryFindingRecorded
	var candidate projections.DiscoveryAttackPathFindingRecorded
	if json.Unmarshal(retained.Data, &prior) != nil || prior.Kind != AttackPathFindingKind ||
		json.Unmarshal(next.Data, &candidate) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(prior.Metadata, &fields) != nil || len(fields[AttackPathRefusedOriginField]) != 0 {
		return false
	}
	var reason string
	_ = json.Unmarshal(fields["reason"], &reason)
	safe := AttackPathFindingDiagnostic(reason)
	if origin := candidate.RefusedOrigin; origin != "" &&
		(safe != attackPathProviderReadPrefix+DiscoveryDestinationPinRefusal ||
			!strings.Contains(reason, "a request to "+origin+discoveryOriginPinSuffix)) {
		return false
	}
	if safe != reason {
		fields["reason"], _ = json.Marshal(safe)
		metadata, err := json.Marshal(fields)
		if err != nil {
			return false
		}
		prior.Metadata = metadata
	}
	oldPayload, oldErr := json.Marshal(prior)
	newPayload, newErr := json.Marshal(candidate.DiscoveryFindingRecorded)
	return oldErr == nil && newErr == nil && bytes.Equal(oldPayload, newPayload)
}

// FailAttackPathValidation completes a validation's run as failed with the
// reason, when its source cannot be read at all (an unset credential
// reference, a rejected endpoint): no endpoint is judged on a broken source.
func (o *Orchestrator) FailAttackPathValidation(ctx context.Context, tenantID, key string, intent AttackPathIntent, reason string, authority DiscoveryDiagnosticAuthority) error {
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, intent.RunID, DiscoveryRelayEventID(tenantID, key, "attack-path-run-started")); err != nil {
		return err
	}
	return o.completeDiscoveryRun(ctx, tenantID,
		store.DiscoveryRun{ID: intent.RunID, Status: "failed", Targets: len(intent.Endpoints), Failed: len(intent.Endpoints), Error: reason},
		DiscoveryRelayEventID(tenantID, key, "attack-path-run-completed"), authority)
}
