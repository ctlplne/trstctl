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

// N4: decoy key uses found in a CloudTrail trail's log files — every account
// of an organization trail, and the data events a trail logs.

// MaxAWSHoneyTrailUsesPerObject bounds the uses one log file's event records.
// A file with more decoy records keeps the first ones and the count of all.
const MaxAWSHoneyTrailUsesPerObject = 500

// awsHoneyTrailRetention is how long a read log file's key is kept. The
// monitor reads only today's and yesterday's day folders, so an older key is
// never looked up again.
const awsHoneyTrailRetention = 4 * 24 * time.Hour

// AWSHoneyTrailUse is one decoy-key record from a trail's log file.
type AWSHoneyTrailUse struct {
	HoneyID            string    `json:"honey_id"`
	EventID            string    `json:"event_id"`
	AccountID          string    `json:"account_id"`
	RecipientAccountID string    `json:"recipient_account_id"`
	Region             string    `json:"region"`
	EventSource        string    `json:"event_source"`
	EventName          string    `json:"event_name"`
	EventCategory      string    `json:"event_category"`
	SourceIPAddress    string    `json:"source_ip_address"`
	UserAgent          string    `json:"user_agent"`
	ErrorCode          string    `json:"error_code,omitempty"`
	EventTime          time.Time `json:"event_time"`
}

// AWSHoneyTrailObjectScan is one log file the monitor read, the payload of
// honeytoken.aws.trail_object_scanned. Refused names why a file was not read
// (too large, not a log file); its records and uses are then zero.
type AWSHoneyTrailObjectScan struct {
	AccountConfigID string             `json:"account_config_id"`
	ObjectKey       string             `json:"object_key"`
	SizeBytes       int64              `json:"size_bytes"`
	Records         int                `json:"records"`
	UsesTotal       int                `json:"uses_total"`
	Refused         string             `json:"refused,omitempty"`
	Uses            []AWSHoneyTrailUse `json:"uses"`
}

// AWSHoneyTrailSummary is what the monitor has read from one account
// attachment's trail in the retained window.
type AWSHoneyTrailSummary struct {
	Objects      int        `json:"objects"`
	Records      int64      `json:"records"`
	Uses         int        `json:"uses"`
	Refused      int        `json:"refused"`
	LastObjectAt *time.Time `json:"last_object_at,omitempty"`
}

// ApplyAWSHoneyTrailObjectScannedTx records one read log file and each decoy
// use in it, and triggers an active decoy on its first new use. A file already
// recorded changes nothing, so a replayed or overlapping read never records a
// use twice.
func (s *Store) ApplyAWSHoneyTrailObjectScannedTx(ctx context.Context, tx pgx.Tx, tenantID string, scan AWSHoneyTrailObjectScan, at time.Time, sequence uint64) error {
	if scan.AccountConfigID == "" || scan.ObjectKey == "" || len(scan.ObjectKey) > 1024 || scan.SizeBytes < 0 || scan.Records < 0 ||
		len(scan.Uses) > MaxAWSHoneyTrailUsesPerObject || scan.UsesTotal < len(scan.Uses) || len(scan.Refused) > 512 ||
		(scan.Refused != "" && (scan.Records != 0 || scan.UsesTotal != 0)) || sequence == 0 || sequence > math.MaxInt64 || at.IsZero() {
		return errors.New("store: invalid AWS honeytoken trail object scan")
	}
	eventSequence := int64(sequence) // #nosec G115 -- bounded above (CWE-190)
	tag, err := tx.Exec(ctx, `INSERT INTO aws_honey_trail_objects
		(tenant_id, account_config_id, object_key, size_bytes, records, uses, refused, scanned_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING`,
		tenantID, scan.AccountConfigID, scan.ObjectKey, scan.SizeBytes, scan.Records, scan.UsesTotal, scan.Refused, at, eventSequence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM aws_honey_trail_objects
		WHERE tenant_id = $1 AND account_config_id = $2 AND scanned_at < $3`,
		tenantID, scan.AccountConfigID, at.Add(-awsHoneyTrailRetention)); err != nil {
		return err
	}
	for _, use := range scan.Uses {
		if use.HoneyID == "" || use.EventID == "" || use.Region == "" || use.EventTime.IsZero() {
			return errors.New("store: AWS honeytoken trail use is incomplete")
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM honey_tokens
			WHERE tenant_id = $1 AND id = $2 AND kind = 'aws' FOR UPDATE`, tenantID, use.HoneyID).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("store: AWS honeytoken trail use names no AWS decoy %s", use.HoneyID)
			}
			return err
		}
		inserted, err := tx.Exec(ctx, `INSERT INTO aws_honey_uses
			(tenant_id, honey_id, event_id, region, event_source, event_name, source_ip_address,
			 user_agent, error_code, event_time, detected_at, account_id, recipient_account_id, event_category, found_in)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'trail')
			ON CONFLICT DO NOTHING`, tenantID, use.HoneyID, use.EventID, use.Region,
			use.EventSource, use.EventName, use.SourceIPAddress, use.UserAgent, use.ErrorCode,
			use.EventTime, at, use.AccountID, use.RecipientAccountID, use.EventCategory)
		if err != nil {
			return err
		}
		if inserted.RowsAffected() != 0 && state == "active" {
			if err := s.ApplyHoneyTokenTriggeredTx(ctx, tx, tenantID, use.HoneyID,
				"AWS", use.EventSource+"/"+use.EventName, at); err != nil {
				return err
			}
		}
	}
	return nil
}

// AWSHoneyTrailDecoyKeys maps the access key of each AWS decoy a trail read
// must match to its decoy: every decoy not retired, and a retired one for 72
// hours after its key was deleted, because CloudTrail delivers late.
// AWSHoneyTrailWatchedSince is when the oldest decoy a trail watches for was
// created (N4-L2): a decoy key cannot appear in a log file delivered before
// it existed. The decoys are those AWSHoneyTrailDecoyKeys returns.
func (s *Store) AWSHoneyTrailWatchedSince(ctx context.Context, tenantID string) (time.Time, error) {
	var since *time.Time
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(h.created_at)
			FROM honey_tokens h
			LEFT JOIN dynamic_secret_leases l ON l.tenant_id = h.tenant_id AND l.id = h.aws_lease_id
			WHERE h.tenant_id = $1 AND h.kind = 'aws' AND coalesce(h.aws_access_key_id, '') <> ''
			  AND (l.id IS NULL OR l.state <> 'revoked' OR l.revocation_completed_at IS NULL
			       OR l.revocation_completed_at > now() - interval '72 hours')`, tenantID).Scan(&since)
	})
	if err != nil || since == nil {
		return time.Now().UTC(), err
	}
	return since.UTC(), nil
}

func (s *Store) AWSHoneyTrailDecoyKeys(ctx context.Context, tenantID string) (map[string]string, error) {
	keys := map[string]string{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT h.aws_access_key_id, h.id::text
			FROM honey_tokens h
			LEFT JOIN dynamic_secret_leases l ON l.tenant_id = h.tenant_id AND l.id = h.aws_lease_id
			WHERE h.tenant_id = $1 AND h.kind = 'aws' AND coalesce(h.aws_access_key_id, '') <> ''
			  AND (l.id IS NULL OR l.state <> 'revoked' OR l.revocation_completed_at IS NULL
			       OR l.revocation_completed_at > now() - interval '72 hours')`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key, id string
			if err := rows.Scan(&key, &id); err != nil {
				return err
			}
			keys[key] = id
		}
		return rows.Err()
	})
	return keys, err
}

// AWSHoneyTrailObjectsRead reports which of keys the monitor has already read
// for one account attachment's trail.
func (s *Store) AWSHoneyTrailObjectsRead(ctx context.Context, tenantID, accountConfigID string, keys []string) (map[string]bool, error) {
	read := map[string]bool{}
	if len(keys) == 0 {
		return read, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_key FROM aws_honey_trail_objects
			WHERE tenant_id = $1 AND account_config_id = $2 AND object_key = ANY($3)`, tenantID, accountConfigID, keys)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return err
			}
			read[key] = true
		}
		return rows.Err()
	})
	return read, err
}

// AWSHoneyTrailSummaryFor summarizes the retained reads of one account
// attachment's trail.
func (s *Store) AWSHoneyTrailSummaryFor(ctx context.Context, tenantID, accountConfigID string) (AWSHoneyTrailSummary, error) {
	var out AWSHoneyTrailSummary
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(records), 0), coalesce(sum(uses), 0)::integer,
			count(*) FILTER (WHERE refused <> ''), max(scanned_at)
			FROM aws_honey_trail_objects WHERE tenant_id = $1 AND account_config_id = $2`,
			tenantID, accountConfigID).Scan(&out.Objects, &out.Records, &out.Uses, &out.Refused, &out.LastObjectAt)
	})
	return out, err
}
