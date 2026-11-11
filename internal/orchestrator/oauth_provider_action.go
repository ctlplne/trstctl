// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Acting at the provider on an abusive OAuth grant (A170, A171).
//
// Discovery reads metadata exports; it never changes provider state. An
// operator who decides a grant is abusive asks for one of two actions, and
// each is a durable request: the finding records it as queued and one
// control-plane outbox row carries it in the same transaction. The row's
// executor calls the provider through the source's admin connection and the
// finding then records what the provider confirmed.

// DestinationOAuthProviderAction is the control-plane row that acts at the
// provider.
const DestinationOAuthProviderAction = "oauth.provider_action"

// OAuth provider actions.
const (
	OAuthActionRevokeGrant = "revoke_grant"
	OAuthActionBlockApp    = "block_app"
)

// OAuth provider action statuses, as the finding records them.
const (
	OAuthActionQueued        = "queued"
	OAuthActionConfirmed     = "confirmed"
	OAuthActionAlreadyAbsent = "already_absent"
	OAuthActionFailed        = "failed"
)

var oauthProviderActionNamespace = uuid.MustParse("6c2d8f3a-1a70-4a17-8a71-a170a171a170")

// OAuthProviderActionIntent is the row's payload: public identifiers only; the
// admin token stays behind the source's reference.
type OAuthProviderActionIntent struct {
	RequestID string `json:"request_id"`
	FindingID string `json:"finding_id"`
	SourceID  string `json:"source_id"`
	Action    string `json:"action"`
	Provider  string `json:"provider"`
	AppID     string `json:"app_id"`
	Principal string `json:"principal,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// TenantWide revokes Microsoft Graph's admin consent for every user
	// (consentType AllPrincipals), which names no principal (A170-L1).
	TenantWide bool `json:"tenant_wide,omitempty"`
}

// QueueOAuthProviderAction records the request on the finding and queues its
// row in one tenant transaction. requestKey is the durable request identity:
// a retried request converges on the same request and row.
func (o *Orchestrator) QueueOAuthProviderAction(ctx context.Context, tenantID, requestKey, actor string, in OAuthProviderActionIntent) (OAuthProviderActionIntent, error) {
	if o.outbox == nil {
		return OAuthProviderActionIntent{}, errors.New("orchestrator: OAuth provider action outbox is unavailable")
	}
	if (in.Action != OAuthActionRevokeGrant && in.Action != OAuthActionBlockApp) || strings.TrimSpace(in.FindingID) == "" ||
		strings.TrimSpace(in.SourceID) == "" || strings.TrimSpace(in.Provider) == "" || strings.TrimSpace(in.AppID) == "" ||
		(in.Action == OAuthActionRevokeGrant && strings.TrimSpace(in.Principal) == "" && !in.TenantWide) {
		return OAuthProviderActionIntent{}, errors.New("orchestrator: OAuth provider action is incomplete")
	}
	in.RequestID = uuid.NewSHA1(oauthProviderActionNamespace, []byte(tenantID+"\x00"+requestKey)).String()
	queued, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.Action, Status: OAuthActionQueued, Provider: in.Provider,
		RequestID: in.RequestID, Reason: in.Reason, Actor: actor,
	})
	if err != nil {
		return OAuthProviderActionIntent{}, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return OAuthProviderActionIntent{}, err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ev, err := o.log.Append(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, requestKey, "oauth-provider-action-queued"),
			Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: queued})
		if err != nil {
			return err
		}
		if ev.Type != projections.EventDiscoveryFindingProviderAction || ev.TenantID != tenantID || !bytes.Equal(ev.Data, queued) {
			return fmt.Errorf("%w: OAuth provider action request differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationOAuthProviderAction,
			IdempotencyKey: "oauth-provider-action:" + in.RequestID, Payload: payload,
			EffectLane: "oauth-provider:" + in.Provider + ":" + in.AppID, RequiredAgentRole: "control_plane",
		})
		return err
	})
	return in, err
}

// RecordOAuthProviderAction records what the provider confirmed, under an id
// derived from the request so a redelivered row converges.
func (o *Orchestrator) RecordOAuthProviderAction(ctx context.Context, tenantID string, in OAuthProviderActionIntent, status, detail string) error {
	payload, err := json.Marshal(projections.DiscoveryFindingProviderAction{
		FindingID: in.FindingID, Action: in.Action, Status: status, Provider: in.Provider,
		Detail: detail, RequestID: in.RequestID,
	})
	if err != nil {
		return err
	}
	_, err = o.emitPrepared(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, in.RequestID, "oauth-provider-action-result"),
		Type: projections.EventDiscoveryFindingProviderAction, TenantID: tenantID, Data: payload})
	return err
}
