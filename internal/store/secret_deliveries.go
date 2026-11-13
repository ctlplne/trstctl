// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Secret delivery reports (A238): per consumer and secret, the version written
// ("injected") and the version its application proved it uses ("verified").

// Delivery states a consumer reports.
const (
	SecretDeliveryInjected = "injected"
	SecretDeliveryVerified = "verified"
)

// SecretDelivery is one consumer's state for one secret.
type SecretDelivery struct {
	Consumer        string
	Name            string
	InjectedVersion int
	InjectedAt      *time.Time
	VerifiedVersion int
	VerifiedAt      *time.Time
	ReportedBy      string
}

// ApplySecretDeliveryReportedTx records a report. A version only moves forward;
// a verified version also counts as injected.
func (s *Store) ApplySecretDeliveryReportedTx(ctx context.Context, tx pgx.Tx, tenantID, consumer, state, name string, version int, reportedBy string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if consumer == "" || name == "" || version <= 0 || at.IsZero() || (state != SecretDeliveryInjected && state != SecretDeliveryVerified) {
		return errors.New("store: a secret delivery report is incomplete")
	}
	verified := 0
	if state == SecretDeliveryVerified {
		verified = version
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_deliveries (tenant_id, consumer, name, injected_version, injected_at, verified_version, verified_at,
		                               reported_by, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $6 > 0 THEN $5::timestamptz END, $7, $8)
		ON CONFLICT (tenant_id, consumer, name) DO UPDATE
		   SET injected_version = GREATEST(secret_deliveries.injected_version, excluded.injected_version),
		       injected_at = CASE WHEN excluded.injected_version > secret_deliveries.injected_version
		                          THEN excluded.injected_at ELSE secret_deliveries.injected_at END,
		       verified_version = GREATEST(secret_deliveries.verified_version, excluded.verified_version),
		       verified_at = CASE WHEN excluded.verified_version > secret_deliveries.verified_version
		                          THEN excluded.verified_at ELSE secret_deliveries.verified_at END,
		       reported_by = excluded.reported_by, event_sequence = excluded.event_sequence
		 WHERE secret_deliveries.event_sequence < excluded.event_sequence`,
		tenantID, consumer, name, version, at.UTC(), verified, reportedBy, seq)
	return err
}

// ListSecretDeliveries lists every consumer's state for one secret, by consumer.
func (s *Store) ListSecretDeliveries(ctx context.Context, tenantID, name string) ([]SecretDelivery, error) {
	var out []SecretDelivery
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT consumer, name, injected_version, injected_at, verified_version, verified_at, reported_by
			  FROM secret_deliveries WHERE tenant_id = $1 AND name = $2 ORDER BY consumer`, tenantID, name)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d SecretDelivery
			if err := rows.Scan(&d.Consumer, &d.Name, &d.InjectedVersion, &d.InjectedAt, &d.VerifiedVersion, &d.VerifiedAt, &d.ReportedBy); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// SecretConsumersBehind returns, for each named secret, the consumers whose
// latest report (injected or verified) is older than the version given for
// it (A236-L3): they hold a value a newer version replaced. Consumers are
// sorted; a secret no consumer is behind on is absent.
func (s *Store) SecretConsumersBehind(ctx context.Context, tenantID string, versions map[string]int) (map[string][]string, error) {
	out := map[string][]string{}
	if len(versions) == 0 {
		return out, nil
	}
	names := make([]string, 0, len(versions))
	for name := range versions {
		names = append(names, name)
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT name, consumer, GREATEST(injected_version, verified_version)
			  FROM secret_deliveries WHERE tenant_id = $1 AND name = ANY($2)
			 ORDER BY name, consumer`, tenantID, names)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name, consumer string
			var reported int
			if err := rows.Scan(&name, &consumer, &reported); err != nil {
				return err
			}
			if reported > 0 && reported < versions[name] {
				out[name] = append(out[name], consumer)
			}
		}
		return rows.Err()
	})
	return out, err
}
