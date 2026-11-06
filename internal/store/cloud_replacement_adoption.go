// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
)

// ApplyCloudReplacementAdoptionTx projects only the original immutable verified
// report, not the aggregate delivery row's most recent reporter. Phase sequencing
// remains independent so a concurrent report cannot suppress a phase event.
func (s *Store) ApplyCloudReplacementAdoptionTx(ctx context.Context, tx pgx.Tx, tenantID, consumer, subject, name string, version int, eventID string, sequence uint64, at time.Time) error {
	receipt, err := json.Marshal(change.Adoption{Consumer: consumer, Subject: subject, Name: name, Version: version, EventID: eventID, Sequence: sequence, VerifiedAt: at})
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `UPDATE cloud_machine_changes SET adoption=$2,updated_at=GREATEST(updated_at,$3) WHERE tenant_id=$1 AND state IN ('queued','preparing_replacement','waiting_adoption') AND intent->>'action'='replace_key' AND intent->>'consumer'=$4 AND intent->>'consumer_subject'=$5 AND intent->>'replacement_role'=$6 AND (intent->>'replacement_expected_version')::integer+1=$7 AND COALESCE((adoption->>'sequence')::bigint,0)<$8 RETURNING id::text,state`, tenantID, receipt, at, consumer, subject, name, version, sequence)
	if err != nil {
		return err
	}
	type accepted struct{ id, state string }
	var values []accepted
	for rows.Next() {
		var value accepted
		if err := rows.Scan(&value.id, &value.state); err != nil {
			rows.Close()
			return err
		}
		values = append(values, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, value := range values {
		if err := s.EnsureCloudMachinePhaseOutboxTx(ctx, tx, tenantID, value.id, value.state); err != nil {
			return err
		}
	}
	return nil
}

// EnsureCloudMachinePhaseOutboxTx runs inside the event projection transaction.
// Adoption and its external retirement intent therefore commit together (AN-6).
func (s *Store) EnsureCloudMachinePhaseOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, id, state string) error {
	phase := ""
	switch state {
	case change.Preparing:
		phase = "prepare"
	case change.WaitingAdoption:
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM cloud_machine_changes WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&expires); err != nil {
			return err
		}
		deadlineRaw, err := json.Marshal(struct {
			ID    string `json:"id"`
			Phase string `json:"phase"`
		}{id, "deadline"})
		if err != nil {
			return err
		}
		if _, err := ensureSecretIntegrationOutboxAtTx(ctx, tx, tenantID, change.Destination, change.Destination+":"+id, "cloud-change:"+id+":deadline", deadlineRaw, &expires); err != nil {
			return err
		}
		var accepted bool
		if err := tx.QueryRow(ctx, `SELECT adoption IS NOT NULL FROM cloud_machine_changes WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&accepted); err != nil {
			return err
		}
		if !accepted {
			return nil
		}
		phase = "retire"
	default:
		return nil
	}
	raw, err := json.Marshal(struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
	}{id, phase})
	if err != nil {
		return err
	}
	_, err = ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, change.Destination, change.Destination+":"+id, "cloud-change:"+id+":"+phase, raw)
	return err
}
