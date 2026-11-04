// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// trstctl's Slack app (N8): the workspace a tenant installed it in (with the
// bot token sealed under the tenant's key), the approval channel, the Slack
// users members linked to themselves, and the approval messages posted and
// decided from Slack.
const (
	EventSlackInstalled          = "slack.app.installed"
	EventSlackApprovalChannelSet = "slack.app.approval_channel_set"
	EventSlackUninstalled        = "slack.app.uninstalled"
	EventSlackUserLinked         = "slack.user.linked"
	EventSlackApprovalPosted     = "slack.approval.posted"
	EventSlackApprovalDecided    = "slack.approval.decided"
)

// SlackInstalled is the payload of slack.app.installed. SealedBotToken is
// ciphertext under the tenant's key; the token itself is never in an event.
type SlackInstalled struct {
	TeamID         string `json:"team_id"`
	TeamName       string `json:"team_name"`
	BotUserID      string `json:"bot_user_id"`
	AppID          string `json:"app_id"`
	SealedBotToken []byte `json:"sealed_bot_token"`
	InstalledBy    string `json:"installed_by"`
}

// SlackApprovalChannelSet is the payload of slack.app.approval_channel_set.
type SlackApprovalChannelSet struct {
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	SetBy       string `json:"set_by"`
}

// SlackUninstalled is the payload of slack.app.uninstalled.
type SlackUninstalled struct {
	TeamID string `json:"team_id"`
	By     string `json:"by"`
}

// SlackUserLinked is the payload of slack.user.linked.
type SlackUserLinked struct {
	SlackUserID string `json:"slack_user_id"`
	Subject     string `json:"subject"`
}

// SlackApprovalPosted is the payload of slack.approval.posted.
type SlackApprovalPosted struct {
	ApprovalRequestID string `json:"approval_request_id"`
	ChannelID         string `json:"channel_id"`
	MessageTS         string `json:"message_ts"`
}

// SlackApprovalDecided is the payload of slack.approval.decided.
type SlackApprovalDecided struct {
	ApprovalRequestID string `json:"approval_request_id"`
	Decision          string `json:"decision"`
	Subject           string `json:"subject"`
	SlackUserID       string `json:"slack_user_id"`
}

func init() {
	for _, typ := range []string{EventSlackInstalled, EventSlackApprovalChannelSet, EventSlackUninstalled,
		EventSlackUserLinked, EventSlackApprovalPosted, EventSlackApprovalDecided} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applySlackAppTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	decode := func(into any) error {
		if err := json.Unmarshal(e.Data, into); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return nil
	}
	switch e.Type {
	case EventSlackInstalled:
		var d SlackInstalled
		if err := decode(&d); err != nil {
			return true, err
		}
		return true, p.store.ApplySlackInstalledTx(ctx, tx, store.SlackInstall{TenantID: e.TenantID, TeamID: d.TeamID, TeamName: d.TeamName,
			BotUserID: d.BotUserID, AppID: d.AppID, SealedBotToken: d.SealedBotToken, InstalledBy: d.InstalledBy}, e.Time, e.Sequence)
	case EventSlackApprovalChannelSet:
		var d SlackApprovalChannelSet
		if err := decode(&d); err != nil {
			return true, err
		}
		if d.ChannelID == "" {
			return true, errors.New("projections: an approval channel needs its ID")
		}
		return true, p.store.ApplySlackApprovalChannelSetTx(ctx, tx, e.TenantID, d.ChannelID, d.ChannelName, e.Time, e.Sequence)
	case EventSlackUninstalled:
		return true, p.store.ApplySlackUninstalledTx(ctx, tx, e.TenantID)
	case EventSlackUserLinked:
		var d SlackUserLinked
		if err := decode(&d); err != nil {
			return true, err
		}
		if d.SlackUserID == "" || d.Subject == "" {
			return true, errors.New("projections: a Slack link needs the Slack user and the member")
		}
		return true, p.store.ApplySlackUserLinkedTx(ctx, tx, e.TenantID, d.SlackUserID, d.Subject, e.Time, e.Sequence)
	case EventSlackApprovalPosted:
		var d SlackApprovalPosted
		if err := decode(&d); err != nil {
			return true, err
		}
		if d.ApprovalRequestID == "" || d.ChannelID == "" || d.MessageTS == "" {
			return true, errors.New("projections: a posted approval needs its request, channel and message")
		}
		return true, p.store.ApplySlackApprovalPostedTx(ctx, tx, e.TenantID, store.SlackApprovalMessage{ApprovalRequestID: d.ApprovalRequestID,
			ChannelID: d.ChannelID, MessageTS: d.MessageTS, PostedAt: e.Time}, e.Sequence)
	case EventSlackApprovalDecided:
		var d SlackApprovalDecided
		if err := decode(&d); err != nil {
			return true, err
		}
		if d.ApprovalRequestID == "" || (d.Decision != "approve" && d.Decision != "deny") || d.Subject == "" {
			return true, errors.New("projections: a Slack decision needs its request, approve or deny, and the member")
		}
		return true, p.store.ApplySlackApprovalDecidedTx(ctx, tx, e.TenantID, d.ApprovalRequestID, d.Decision, d.Subject, d.SlackUserID, e.Time, e.Sequence)
	}
	return false, nil
}

func addSlackAppPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	policies[privacyEventPolicyKey{EventSlackInstalled, 1}] = privacyRules(
		privacyRule("/team_id", opaque), privacyRule("/team_name", opaque), privacyRule("/bot_user_id", opaque),
		privacyRule("/app_id", opaque), privacyRule("/sealed_bot_token", opaque), privacyRule("/installed_by", exact))
	policies[privacyEventPolicyKey{EventSlackApprovalChannelSet, 1}] = privacyRules(
		privacyRule("/channel_id", opaque), privacyRule("/channel_name", opaque), privacyRule("/set_by", exact))
	policies[privacyEventPolicyKey{EventSlackUninstalled, 1}] = privacyRules(privacyRule("/team_id", opaque), privacyRule("/by", exact))
	policies[privacyEventPolicyKey{EventSlackUserLinked, 1}] = privacyRules(privacyRule("/slack_user_id", exact), privacyRule("/subject", exact))
	policies[privacyEventPolicyKey{EventSlackApprovalPosted, 1}] = privacyRules(
		privacyRule("/approval_request_id", opaque), privacyRule("/channel_id", opaque), privacyRule("/message_ts", opaque))
	policies[privacyEventPolicyKey{EventSlackApprovalDecided, 1}] = privacyRules(
		privacyRule("/approval_request_id", opaque), privacyRule("/decision", opaque), privacyRule("/subject", exact), privacyRule("/slack_user_id", exact))
}

func addSlackAppPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSlackInstalled, 1}] = privacyPayloadShape[SlackInstalled]()
	shapes[privacyEventPolicyKey{EventSlackApprovalChannelSet, 1}] = privacyPayloadShape[SlackApprovalChannelSet]()
	shapes[privacyEventPolicyKey{EventSlackUninstalled, 1}] = privacyPayloadShape[SlackUninstalled]()
	shapes[privacyEventPolicyKey{EventSlackUserLinked, 1}] = privacyPayloadShape[SlackUserLinked]()
	shapes[privacyEventPolicyKey{EventSlackApprovalPosted, 1}] = privacyPayloadShape[SlackApprovalPosted]()
	shapes[privacyEventPolicyKey{EventSlackApprovalDecided, 1}] = privacyPayloadShape[SlackApprovalDecided]()
}
