// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// N8: trstctl's Slack app.

// SlackInstall is the workspace a tenant installed the Slack app in.
type SlackInstall struct {
	TenantID            string    `json:"tenant_id"`
	TeamID              string    `json:"team_id"`
	TeamName            string    `json:"team_name"`
	BotUserID           string    `json:"bot_user_id"`
	AppID               string    `json:"app_id"`
	SealedBotToken      []byte    `json:"-"`
	ApprovalChannelID   string    `json:"approval_channel_id"`
	ApprovalChannelName string    `json:"approval_channel_name"`
	InstalledBy         string    `json:"installed_by"`
	InstalledAt         time.Time `json:"installed_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// SlackApprovalMessage is the message an approval request was posted as.
type SlackApprovalMessage struct {
	ApprovalRequestID string     `json:"approval_request_id"`
	ChannelID         string     `json:"channel_id"`
	MessageTS         string     `json:"message_ts"`
	PostedAt          time.Time  `json:"posted_at"`
	Decision          string     `json:"decision,omitempty"`
	DecidedBy         string     `json:"decided_by,omitempty"`
	SlackUserID       string     `json:"slack_user_id,omitempty"`
	DecidedAt         *time.Time `json:"decided_at,omitempty"`
}

// ErrSlackCodeUnusable is a one-time code that is unknown, expired or used.
var ErrSlackCodeUnusable = errors.New("store: the Slack code is unknown, expired or already used")

func slackSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: Slack event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplySlackInstalledTx records an install; a reinstall replaces the
// workspace and token and keeps the approval channel only for the same
// workspace.
func (s *Store) ApplySlackInstalledTx(ctx context.Context, tx pgx.Tx, in SlackInstall, at time.Time, sequence uint64) error {
	seq, err := slackSequence(sequence)
	if err != nil {
		return err
	}
	if in.TenantID == "" || in.TeamID == "" || in.BotUserID == "" || len(in.SealedBotToken) == 0 || in.InstalledBy == "" {
		return errors.New("store: incomplete Slack install")
	}
	// The table is unique on the tenant (the arbiter) and on the workspace;
	// serialize installs of one tenant so a replayed install cannot race into
	// the workspace index (OPP-C01).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "slack-install\x1f"+in.TenantID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO slack_installs
		(tenant_id, team_id, team_name, bot_user_id, app_id, sealed_bot_token, installed_by, installed_at, updated_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)
		ON CONFLICT (tenant_id) DO UPDATE SET
		  approval_channel_id = CASE WHEN slack_installs.team_id = EXCLUDED.team_id THEN slack_installs.approval_channel_id ELSE '' END,
		  approval_channel_name = CASE WHEN slack_installs.team_id = EXCLUDED.team_id THEN slack_installs.approval_channel_name ELSE '' END,
		  team_id = EXCLUDED.team_id, team_name = EXCLUDED.team_name, bot_user_id = EXCLUDED.bot_user_id,
		  app_id = EXCLUDED.app_id, sealed_bot_token = EXCLUDED.sealed_bot_token, installed_by = EXCLUDED.installed_by,
		  installed_at = EXCLUDED.installed_at, updated_at = EXCLUDED.updated_at, event_sequence = EXCLUDED.event_sequence
		WHERE slack_installs.event_sequence < EXCLUDED.event_sequence`,
		in.TenantID, in.TeamID, in.TeamName, in.BotUserID, in.AppID, in.SealedBotToken, in.InstalledBy, at, seq)
	return err
}

// ApplySlackApprovalChannelSetTx records the channel approval requests go to.
func (s *Store) ApplySlackApprovalChannelSetTx(ctx context.Context, tx pgx.Tx, tenantID, channelID, channelName string, at time.Time, sequence uint64) error {
	seq, err := slackSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE slack_installs SET approval_channel_id = $2, approval_channel_name = $3, updated_at = $4, event_sequence = $5
		WHERE tenant_id = $1 AND event_sequence < $5`, tenantID, channelID, channelName, at, seq)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM slack_installs WHERE tenant_id = $1)`, tenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("store: the tenant has no Slack install")
		}
	}
	return nil
}

// ApplySlackUninstalledTx removes the install, its links and its messages.
func (s *Store) ApplySlackUninstalledTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	for _, q := range []string{
		`DELETE FROM slack_approval_messages WHERE tenant_id = $1`,
		`DELETE FROM slack_user_links WHERE tenant_id = $1`,
		`DELETE FROM slack_installs WHERE tenant_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, tenantID); err != nil {
			return err
		}
	}
	return nil
}

// ApplySlackUserLinkedTx links a Slack user to a member; a relink moves it.
func (s *Store) ApplySlackUserLinkedTx(ctx context.Context, tx pgx.Tx, tenantID, slackUserID, subject string, at time.Time, sequence uint64) error {
	seq, err := slackSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO slack_user_links (tenant_id, slack_user_id, subject, linked_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, slack_user_id) DO UPDATE SET subject = EXCLUDED.subject, linked_at = EXCLUDED.linked_at,
		  event_sequence = EXCLUDED.event_sequence WHERE slack_user_links.event_sequence < EXCLUDED.event_sequence`,
		tenantID, slackUserID, subject, at, seq)
	return err
}

// ApplySlackApprovalPostedTx records the message an approval was posted as.
func (s *Store) ApplySlackApprovalPostedTx(ctx context.Context, tx pgx.Tx, tenantID string, m SlackApprovalMessage, sequence uint64) error {
	seq, err := slackSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO slack_approval_messages (tenant_id, approval_request_id, channel_id, message_ts, posted_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, approval_request_id) DO NOTHING`,
		tenantID, m.ApprovalRequestID, m.ChannelID, m.MessageTS, m.PostedAt, seq)
	return err
}

// ApplySlackApprovalDecidedTx records the decision taken from a message.
func (s *Store) ApplySlackApprovalDecidedTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, decision, subject, slackUserID string, at time.Time, sequence uint64) error {
	seq, err := slackSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE slack_approval_messages SET decision = $3, decided_by = $4, slack_user_id = $5, decided_at = $6, event_sequence = $7
		WHERE tenant_id = $1 AND approval_request_id = $2 AND event_sequence < $7`, tenantID, requestID, decision, subject, slackUserID, at, seq)
	return err
}

// GetSlackInstall reads a tenant's install.
func (s *Store) GetSlackInstall(ctx context.Context, tenantID string) (SlackInstall, error) {
	var in SlackInstall
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, team_id, team_name, bot_user_id, app_id, sealed_bot_token,
			approval_channel_id, approval_channel_name, installed_by, installed_at, updated_at
			FROM slack_installs WHERE tenant_id = $1`, tenantID).Scan(&in.TenantID, &in.TeamID, &in.TeamName, &in.BotUserID,
			&in.AppID, &in.SealedBotToken, &in.ApprovalChannelID, &in.ApprovalChannelName, &in.InstalledBy, &in.InstalledAt, &in.UpdatedAt)
	})
	return in, err
}

// TenantForSlackTeam is the tenant that installed the app in a workspace.
// Interactions arrive from Slack naming only the workspace, so this reads
// across tenants through the system pool and returns one tenant or none
// (pgx.ErrNoRows).
func (s *Store) TenantForSlackTeam(ctx context.Context, teamID string) (string, error) {
	var tenantID string
	err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — a Slack interaction names only its workspace; the lookup is keyed by the globally-unique team_id (one install per workspace) and returns the one owning tenant, whose data is then read under its own RLS context. Cross-tenant by design (AN-1 exemption).
		`SELECT tenant_id::text FROM slack_installs WHERE team_id = $1`, teamID).Scan(&tenantID)
	return tenantID, err
}

// SlackLinkedSubject is the member a Slack user linked, if any.
func (s *Store) SlackLinkedSubject(ctx context.Context, tenantID, slackUserID string) (string, error) {
	var subject string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT subject FROM slack_user_links WHERE tenant_id = $1 AND slack_user_id = $2`, tenantID, slackUserID).Scan(&subject)
	})
	return subject, err
}

// GetSlackApprovalMessage reads the message an approval was posted as.
func (s *Store) GetSlackApprovalMessage(ctx context.Context, tenantID, requestID string) (SlackApprovalMessage, error) {
	var m SlackApprovalMessage
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT approval_request_id::text, channel_id, message_ts, posted_at, decision, decided_by, slack_user_id, decided_at
			FROM slack_approval_messages WHERE tenant_id = $1 AND approval_request_id = $2`, tenantID, requestID).Scan(&m.ApprovalRequestID,
			&m.ChannelID, &m.MessageTS, &m.PostedAt, &m.Decision, &m.DecidedBy, &m.SlackUserID, &m.DecidedAt)
	})
	return m, err
}

// IssueSlackCode stores a one-time code's digest for a purpose and subject.
func (s *Store) IssueSlackCode(ctx context.Context, tenantID, digest, purpose, subject string, expires time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM slack_one_time_codes WHERE tenant_id = $1 AND expires_at < now() - interval '1 day'`, tenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO slack_one_time_codes (tenant_id, code_digest, purpose, subject, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			tenantID, digest, purpose, subject, expires)
		return err
	})
}

// UseSlackCode spends a one-time code once and returns its subject.
func (s *Store) UseSlackCode(ctx context.Context, tenantID, digest, purpose string, now time.Time) (string, error) {
	var subject string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE slack_one_time_codes SET used_at = $4
			WHERE tenant_id = $1 AND code_digest = $2 AND purpose = $3 AND used_at IS NULL AND expires_at > $4
			RETURNING subject`, tenantID, digest, purpose, now).Scan(&subject)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSlackCodeUnusable
	}
	return subject, err
}

// ErrSlackDecisionUsed is a button decision this approver already used.
var ErrSlackDecisionUsed = errors.New("store: the Slack decision was already used")

// UseSlackDecision records one approver's use of a posted decision once
// (A277); a second use is ErrSlackDecisionUsed.
func (s *Store) UseSlackDecision(ctx context.Context, tenantID, digest, subject string, expires time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO slack_one_time_codes (tenant_id, code_digest, purpose, subject, expires_at, used_at)
			VALUES ($1, $2, 'decision', $3, $4, now()) ON CONFLICT DO NOTHING`, tenantID, digest, subject, expires)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrSlackDecisionUsed
		}
		return nil
	})
}
