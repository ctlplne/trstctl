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

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Replacing a stale cloud access key with a dynamic credential (M3-L4).
//
// An operator who decides a discovered AWS IAM user key should give way to
// short-lived credentials names the tenant's dynamic-secret provider and
// role that replaces it. The request is durable, as an OAuth provider action
// is: the finding records it as queued and one control-plane outbox row
// carries it in the same transaction. The row's executor sets the key
// Inactive through the finding's source (IAM UpdateAccessKey; never a
// deletion, so it can be activated again), and the finding then records what
// IAM confirmed and is marked remediated with the replacement as evidence.

// DestinationCloudKeyAction is the control-plane row that acts at the cloud.
const DestinationCloudKeyAction = "cloud_key.action"

// CloudKeyActionDeactivate sets the key Inactive.
const CloudKeyActionDeactivate = "deactivate_key"

var cloudKeyActionNamespace = uuid.MustParse("8f0a3c5e-2b41-4d6a-9c7e-3a4d5e6f7a81")

// CloudKeyActionIntent is the row's payload: public identifiers only; the
// source's credentials stay behind its references.
type CloudKeyActionIntent struct {
	RequestID string `json:"request_id"`
	FindingID string `json:"finding_id"`
	SourceID  string `json:"source_id"`
	Action    string `json:"action"`
	Provider  string `json:"provider"`
	// Host is the IAM host the finding's provenance names; the executor acts
	// through the source's aws-iam connections at that host.
	Host        string `json:"host"`
	User        string `json:"user"`
	AccessKeyID string `json:"access_key_id"`
	// ReplacementProvider and ReplacementRole name the tenant dynamic-secret
	// provider and role whose short-lived credentials replace the key.
	ReplacementProvider string `json:"replacement_provider"`
	ReplacementRole     string `json:"replacement_role"`
	Reason              string `json:"reason,omitempty"`
}

// Replacement is the evidence reference of the dynamic credential.
func (in CloudKeyActionIntent) Replacement() string {
	return "dynamic-secret:" + in.ReplacementProvider + "/" + in.ReplacementRole
}

// QueueCloudKeyAction records the request on the finding and queues its row
// in one tenant transaction; a retried request converges on one row.
func (o *Orchestrator) QueueCloudKeyAction(ctx context.Context, tenantID, requestKey, actor string, in CloudKeyActionIntent) (CloudKeyActionIntent, error) {
	if o.outbox == nil {
		return CloudKeyActionIntent{}, errors.New("orchestrator: cloud key action outbox is unavailable")
	}
	if in.Action != CloudKeyActionDeactivate || strings.TrimSpace(in.FindingID) == "" || strings.TrimSpace(in.SourceID) == "" ||
		strings.TrimSpace(in.Provider) == "" || strings.TrimSpace(in.Host) == "" || strings.TrimSpace(in.User) == "" || strings.TrimSpace(in.AccessKeyID) == "" ||
		strings.TrimSpace(in.ReplacementProvider) == "" || strings.TrimSpace(in.ReplacementRole) == "" {
		return CloudKeyActionIntent{}, errors.New("orchestrator: cloud key action is incomplete")
	}
	in.RequestID = uuid.NewSHA1(cloudKeyActionNamespace, []byte(tenantID+"\x00"+requestKey)).String()
	queued, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.Action, Status: OAuthActionQueued, Provider: in.Provider,
		Detail: "replace with short-lived credentials from " + in.Replacement(), RequestID: in.RequestID, Reason: in.Reason, Actor: actor,
	})
	if err != nil {
		return CloudKeyActionIntent{}, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return CloudKeyActionIntent{}, err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, requestKey, "cloud-key-action-queued"),
			Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: queued})
		if err != nil {
			return err
		}
		if ev.Type != projections.EventDiscoveryFindingProviderAction || ev.TenantID != tenantID || !bytes.Equal(ev.Data, queued) {
			return fmt.Errorf("%w: cloud key action request differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationCloudKeyAction,
			IdempotencyKey: "cloud-key-action:" + in.RequestID, Payload: payload,
			EffectLane: "cloud-key:" + in.Provider + ":" + in.AccessKeyID, RequiredAgentRole: "control_plane",
		})
		return err
	})
	return in, err
}

// RecordCloudKeyAction records what the cloud confirmed. A confirmed or
// already-absent key marks the finding remediated, with the replacement and
// the time as its evidence.
func (o *Orchestrator) RecordCloudKeyAction(ctx context.Context, tenantID string, in CloudKeyActionIntent, status, detail string, at time.Time) error {
	payload, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.Action, Status: status, Provider: in.Provider,
		Detail: detail, RequestID: in.RequestID, ProviderRef: in.AccessKeyID,
	})
	if err != nil {
		return err
	}
	if _, err := o.emitPrepared(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, in.RequestID, "cloud-key-action-result"),
		Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: payload}); err != nil {
		return err
	}
	if status != OAuthActionConfirmed && status != OAuthActionAlreadyAbsent {
		return nil
	}
	patch, err := json.Marshal(map[string]any{"status": "Inactive", "replaced_by": in.Replacement(), "deactivated_at": at.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	reason := "deactivated at " + in.Provider + "; replaced by short-lived credentials from " + in.Replacement()
	_, err = o.TriageDiscoveryFinding(ctx, tenantID, in.FindingID, discovery.TriageRemediated, nil, reason, patch)
	if err != nil && !errors.Is(err, discovery.ErrInvalidTriageTransition) {
		return err
	}
	return nil
}
