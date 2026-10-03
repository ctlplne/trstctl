// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

const AWSHoneyScanDestination = "honey.aws.scan"

type AWSHoneyScan struct {
	TenantID         string     `json:"-"`
	HoneyID          string     `json:"honey_id"`
	Region           string     `json:"region"`
	Cycle            int64      `json:"cycle"`
	Page             int        `json:"page"`
	NextToken        string     `json:"-"`
	WindowStart      *time.Time `json:"window_start,omitempty"`
	WindowEnd        *time.Time `json:"window_end,omitempty"`
	Watermark        time.Time  `json:"watermark"`
	LastSuccessAt    *time.Time `json:"last_success_at,omitempty"`
	GapSince         *time.Time `json:"gap_since,omitempty"`
	DeliveryStatus   string     `json:"delivery_status,omitempty"`
	DeliveryAttempts int        `json:"delivery_attempts,omitempty"`
	DeliveryError    string     `json:"delivery_error,omitempty"`
}

type AWSHoneyUse struct {
	EventID         string    `json:"event_id"`
	Region          string    `json:"region"`
	EventSource     string    `json:"event_source"`
	EventName       string    `json:"event_name"`
	SourceIPAddress string    `json:"source_ip_address"`
	UserAgent       string    `json:"user_agent"`
	ErrorCode       string    `json:"error_code,omitempty"`
	EventTime       time.Time `json:"event_time"`
	DetectedAt      time.Time `json:"detected_at"`
}

type AWSHoneyScanPage struct {
	HoneyID      string        `json:"honey_id"`
	Region       string        `json:"region"`
	Cycle        int64         `json:"cycle"`
	Page         int           `json:"page"`
	WindowStart  time.Time     `json:"window_start"`
	WindowEnd    time.Time     `json:"window_end"`
	RequestToken string        `json:"request_token,omitempty"`
	NextToken    string        `json:"next_token,omitempty"`
	GapSince     *time.Time    `json:"gap_since,omitempty"`
	Uses         []AWSHoneyUse `json:"uses"`
}

func AWSHoneyScanKey(id, region string, cycle int64, page int) string {
	return fmt.Sprintf("honey.aws.scan:%s:%s:%d:%d", id, region, cycle, page)
}

func enqueueAWSHoneyScanTx(ctx context.Context, tx pgx.Tx, tenantID, id, region string, cycle int64, page int, due time.Time) error {
	payload, err := json.Marshal(struct {
		ID     string `json:"id"`
		Region string `json:"region"`
		Cycle  int64  `json:"cycle"`
		Page   int    `json:"page"`
	}{id, region, cycle, page})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, next_attempt_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		tenantID, AWSHoneyScanDestination, payload, AWSHoneyScanKey(id, region, cycle, page), due)
	return err
}

// ApplyAWSHoneyTokenCreatedTx records decoy metadata and queues its first
// CloudTrail lookup in the same RLS transaction. An interrupted projector can
// replay the immutable event without scheduling a duplicate scan.
func (s *Store) ApplyAWSHoneyTokenCreatedTx(ctx context.Context, tx pgx.Tx, h HoneyToken) error {
	if h.Kind != "aws" || h.ID == "" || h.TenantID == "" || h.Name == "" || h.Placement == "" ||
		h.AWSAccountConfigID == "" || h.AWSAccountID == "" || h.AWSAccessKeyID == "" || h.AWSLeaseID == "" ||
		len(h.AWSRegions) == 0 || h.AWSPollIntervalSeconds < 60 || h.CreatedAt.IsZero() {
		return errors.New("store: AWS honeytoken event is incomplete")
	}
	if err := lockUpsertArbiterTx(ctx, tx, "honey_tokens", h.TenantID, h.ID); err != nil {
		return err
	}
	hash := crypto.SHA256Hex([]byte("aws-honeytoken:\x00" + h.AWSAccessKeyID))
	_, err := tx.Exec(ctx, `INSERT INTO honey_tokens
		(id, tenant_id, kind, name, placement, token_hash, state, created_at,
		 aws_account_config_id, aws_account_id, aws_access_key_id, aws_lease_id, aws_regions, aws_poll_interval_seconds)
		VALUES ($1, $2, 'aws', $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO NOTHING`,
		h.ID, h.TenantID, h.Name, h.Placement, hash, h.CreatedAt,
		h.AWSAccountConfigID, h.AWSAccountID, h.AWSAccessKeyID, h.AWSLeaseID,
		h.AWSRegions, h.AWSPollIntervalSeconds)
	if err != nil {
		return err
	}
	for _, region := range h.AWSRegions {
		watermark := h.CreatedAt.Add(-5 * time.Minute)
		if _, err := tx.Exec(ctx, `INSERT INTO aws_honey_scans
			(tenant_id, honey_id, region, watermark) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, h.TenantID, h.ID, region, watermark); err != nil {
			return err
		}
		if err := enqueueAWSHoneyScanTx(ctx, tx, h.TenantID, h.ID, region, 0, 0,
			h.CreatedAt.Add(time.Duration(h.AWSPollIntervalSeconds)*time.Second)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListAWSHoneyTokensPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	out := make([]HoneyToken, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+honeyTokenColumns+` FROM honey_tokens
			WHERE tenant_id = $1 AND kind = 'aws' AND id > $2 ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanHoneyToken(rows)
			if err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) GetAWSHoneyScan(ctx context.Context, tenantID, honeyID, region string) (AWSHoneyScan, error) {
	var scan AWSHoneyScan
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, honey_id::text, region, cycle, page,
			next_token, window_start, window_end, watermark, last_success_at, gap_since
			FROM aws_honey_scans WHERE tenant_id = $1 AND honey_id = $2 AND region = $3`,
			tenantID, honeyID, region).Scan(&scan.TenantID, &scan.HoneyID, &scan.Region,
			&scan.Cycle, &scan.Page, &scan.NextToken, &scan.WindowStart, &scan.WindowEnd,
			&scan.Watermark, &scan.LastSuccessAt, &scan.GapSince)
	})
	return scan, err
}

func (s *Store) ListAWSHoneyScans(ctx context.Context, tenantID, honeyID string) ([]AWSHoneyScan, error) {
	out := []AWSHoneyScan{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.tenant_id::text, s.honey_id::text, s.region, s.cycle, s.page,
			s.next_token, s.window_start, s.window_end, s.watermark, s.last_success_at, s.gap_since,
			COALESCE(o.status, 'missing'), COALESCE(o.attempts, 0), COALESCE(o.last_error, '')
			FROM aws_honey_scans s LEFT JOIN outbox o
			  ON o.tenant_id = s.tenant_id AND o.destination = $3
			 AND o.idempotency_key = 'honey.aws.scan:' || s.honey_id::text || ':' || s.region || ':' || s.cycle::text || ':' || s.page::text
			WHERE s.tenant_id = $1 AND s.honey_id = $2 ORDER BY s.region`, tenantID, honeyID, AWSHoneyScanDestination)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AWSHoneyScan
			if err := rows.Scan(&item.TenantID, &item.HoneyID, &item.Region,
				&item.Cycle, &item.Page, &item.NextToken, &item.WindowStart, &item.WindowEnd,
				&item.Watermark, &item.LastSuccessAt, &item.GapSince,
				&item.DeliveryStatus, &item.DeliveryAttempts, &item.DeliveryError); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) ListAWSHoneyUses(ctx context.Context, tenantID, honeyID string, limit int) ([]AWSHoneyUse, error) {
	out := []AWSHoneyUse{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_id, region, event_source, event_name,
			source_ip_address, user_agent, error_code, event_time, detected_at
			FROM aws_honey_uses WHERE tenant_id = $1 AND honey_id = $2
			ORDER BY event_time DESC, event_id LIMIT $3`, tenantID, honeyID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AWSHoneyUse
			if err := rows.Scan(&item.EventID, &item.Region, &item.EventSource,
				&item.EventName, &item.SourceIPAddress, &item.UserAgent, &item.ErrorCode,
				&item.EventTime, &item.DetectedAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// AcquireAWSHoneyCloudTrailPermit serializes the documented two-lookup-per-
// second account/Region quota across processes. One AWS account may be attached
// to only one tenant in the validated operator configuration.
func (s *Store) AcquireAWSHoneyCloudTrailPermit(ctx context.Context, tenantID, accountID, region string) (time.Time, bool, error) {
	var next time.Time
	var acquired bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO aws_honey_cloudtrail_slots
			(tenant_id, account_id, region) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, tenantID, accountID, region)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT next_allowed_at FROM aws_honey_cloudtrail_slots
			WHERE tenant_id = $1 AND account_id = $2 AND region = $3 FOR UPDATE`,
			tenantID, accountID, region).Scan(&next); err != nil {
			return err
		}
		if time.Now().Before(next) {
			return nil
		}
		acquired = true
		next = time.Now().UTC().Add(600 * time.Millisecond)
		_, err = tx.Exec(ctx, `UPDATE aws_honey_cloudtrail_slots SET next_allowed_at = $4
			WHERE tenant_id = $1 AND account_id = $2 AND region = $3`, tenantID, accountID, region, next)
		return err
	})
	return next, acquired, err
}

// ApplyAWSHoneyScanPageTx is the only writer of observed use and scan state.
// Its new outbox intent is in the same transaction as this event projection.
func (s *Store) ApplyAWSHoneyScanPageTx(ctx context.Context, tx pgx.Tx, tenantID string, page AWSHoneyScanPage, at time.Time) error {
	if page.HoneyID == "" || page.Region == "" || page.Cycle < 0 || page.Page < 0 ||
		page.WindowStart.IsZero() || page.WindowEnd.IsZero() || !page.WindowStart.Before(page.WindowEnd) ||
		page.WindowEnd.Sub(page.WindowStart) > 90*24*time.Hour || len(page.NextToken) > 4096 || len(page.RequestToken) > 4096 || len(page.Uses) > 50 {
		return errors.New("store: invalid AWS honeytoken scan page")
	}
	var current AWSHoneyScan
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text, honey_id::text, region, cycle, page,
		next_token, window_start, window_end, watermark, last_success_at, gap_since
		FROM aws_honey_scans WHERE tenant_id = $1 AND honey_id = $2 AND region = $3 FOR UPDATE`,
		tenantID, page.HoneyID, page.Region).Scan(&current.TenantID, &current.HoneyID,
		&current.Region, &current.Cycle, &current.Page, &current.NextToken,
		&current.WindowStart, &current.WindowEnd, &current.Watermark,
		&current.LastSuccessAt, &current.GapSince); err != nil {
		return err
	}
	if current.Cycle > page.Cycle || (current.Cycle == page.Cycle && current.Page > page.Page) {
		return nil
	}
	if current.Cycle != page.Cycle || current.Page != page.Page || current.NextToken != page.RequestToken ||
		(page.Page > 0 && (current.WindowStart == nil || current.WindowEnd == nil ||
			!current.WindowStart.Equal(page.WindowStart) || !current.WindowEnd.Equal(page.WindowEnd))) {
		return errors.New("store: AWS honeytoken scan page does not match projected cursor")
	}
	var pollSeconds int
	var name, placement, state string
	if err := tx.QueryRow(ctx, `SELECT aws_poll_interval_seconds, name, placement, state
		FROM honey_tokens WHERE tenant_id = $1 AND id = $2 AND kind = 'aws'`, tenantID, page.HoneyID).
		Scan(&pollSeconds, &name, &placement, &state); err != nil {
		return err
	}
	for _, use := range page.Uses {
		if use.EventID == "" || use.Region != page.Region || use.EventTime.IsZero() ||
			use.EventTime.Before(page.WindowStart.Add(-time.Second)) || use.EventTime.After(page.WindowEnd.Add(time.Second)) {
			return errors.New("store: AWS honeytoken observed use lies outside its scan")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO aws_honey_uses
			(tenant_id, honey_id, event_id, region, event_source, event_name, source_ip_address,
			 user_agent, error_code, event_time, detected_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT DO NOTHING`, tenantID, page.HoneyID, use.EventID, use.Region,
			use.EventSource, use.EventName, use.SourceIPAddress, use.UserAgent,
			use.ErrorCode, use.EventTime, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 && state == "active" {
			if err := s.ApplyHoneyTokenTriggeredTx(ctx, tx, tenantID, page.HoneyID,
				"AWS", use.EventSource+"/"+use.EventName, at); err != nil {
				return err
			}
			state = "triggered"
		}
	}
	if page.NextToken != "" {
		_, err := tx.Exec(ctx, `UPDATE aws_honey_scans SET page = $4, next_token = $5,
			window_start = $6, window_end = $7, gap_since = COALESCE(gap_since, $8)
			WHERE tenant_id = $1 AND honey_id = $2 AND region = $3`, tenantID, page.HoneyID,
			page.Region, page.Page+1, page.NextToken, page.WindowStart, page.WindowEnd, page.GapSince)
		if err != nil {
			return err
		}
		return enqueueAWSHoneyScanTx(ctx, tx, tenantID, page.HoneyID, page.Region,
			page.Cycle, page.Page+1, at.Add(600*time.Millisecond))
	}
	_, err := tx.Exec(ctx, `UPDATE aws_honey_scans SET cycle = $4, page = 0, next_token = '',
		window_start = NULL, window_end = NULL, watermark = $5, last_success_at = $6,
		gap_since = COALESCE(gap_since, $7)
		WHERE tenant_id = $1 AND honey_id = $2 AND region = $3`, tenantID, page.HoneyID,
		page.Region, page.Cycle+1, page.WindowEnd, at, page.GapSince)
	if err != nil {
		return err
	}
	return enqueueAWSHoneyScanTx(ctx, tx, tenantID, page.HoneyID, page.Region,
		page.Cycle+1, 0, at.Add(time.Duration(pollSeconds)*time.Second))
}
