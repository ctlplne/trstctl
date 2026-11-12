// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// ADCSPendingRequest is one request an AD CS CA holds for a manager's approval,
// as the latest relay read of its database listed it (N1-L2).
type ADCSPendingRequest struct {
	RequestID  int    `json:"request_id"`
	Template   string `json:"template,omitempty"`
	CommonName string `json:"common_name,omitempty"`
	Requester  string `json:"requester,omitempty"`
}

// ADCSPendingRequestList is a CA's pending requests from its latest listed
// read, newest first; Truncated says the CA held more than the read listed.
type ADCSPendingRequestList struct {
	CAConfig   string
	Requests   []ADCSPendingRequest
	Truncated  bool
	ObservedAt time.Time
}

// ReplaceADCSPendingRequestsTx records one read's pending requests for a CA,
// replacing the previous read's, unless a later read is already recorded.
func (s *Store) ReplaceADCSPendingRequestsTx(ctx context.Context, tx pgx.Tx, tenantID, caConfig string, requests []ADCSPendingRequest, truncated bool, observedAt time.Time, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return fmt.Errorf("store: AD CS pending requests event sequence %d is out of range", sequence)
	}
	if requests == nil {
		requests = []ADCSPendingRequest{}
	}
	raw, err := json.Marshal(requests)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO adcs_ca_pending_requests (tenant_id, ca_config, requests, truncated, observed_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, ca_config) DO UPDATE
		   SET requests = EXCLUDED.requests, truncated = EXCLUDED.truncated, observed_at = EXCLUDED.observed_at,
		       event_sequence = EXCLUDED.event_sequence
		 WHERE adcs_ca_pending_requests.event_sequence <= EXCLUDED.event_sequence`,
		tenantID, caConfig, raw, truncated, observedAt.UTC(), int64(sequence)) // #nosec G115 -- bounded above (CWE-190)
	return err
}

// ErrADCSPendingRequestsNotRead means no relay read has listed the CA's
// pending requests yet.
var ErrADCSPendingRequestsNotRead = errors.New("store: no read has listed this CA's pending requests")

// GetADCSPendingRequests reads a CA's pending requests from its latest listed
// read.
func (s *Store) GetADCSPendingRequests(ctx context.Context, tenantID, caConfig string) (ADCSPendingRequestList, error) {
	out := ADCSPendingRequestList{CAConfig: caConfig}
	var raw []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT requests, truncated, observed_at FROM adcs_ca_pending_requests
			WHERE tenant_id = $1 AND ca_config = $2`, tenantID, caConfig).Scan(&raw, &out.Truncated, &out.ObservedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ADCSPendingRequestList{}, ErrADCSPendingRequestsNotRead
	}
	if err != nil {
		return ADCSPendingRequestList{}, err
	}
	if err := json.Unmarshal(raw, &out.Requests); err != nil {
		return ADCSPendingRequestList{}, fmt.Errorf("store: decode AD CS pending requests: %w", err)
	}
	return out, nil
}
