// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
)

// PendingEventKeyDestructionAfter reports whether the tenant's inline offboard
// has already erased an event preceding its retained offboard source. The
// pending effect is a commit witness, not permission to erase any new residue.
// Every candidate must match the exact shape written by the offboard command.
func (s *Store) PendingEventKeyDestructionAfter(ctx context.Context, tenantID string, sequence uint64) (bool, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return false, fmt.Errorf("store: invalid event key destruction replay sequence")
	}
	var skip bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT payload,idempotency_key,destination,
			COALESCE(NULLIF(effect_lane,''),destination),required_agent_role,
			COALESCE(required_agent_id::text,'') FROM outbox
			WHERE tenant_id=$1 AND destination=$2`, tenantID, EventKeyDestructionDestination)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			var key, destination, lane, role, agent string
			if err := rows.Scan(&payload, &key, &destination, &lane, &role, &agent); err != nil {
				return err
			}
			var request eventprotect.DestructionRequest
			if err := json.Unmarshal(payload, &request); err != nil || request.Validate() != nil {
				return fmt.Errorf("store: invalid pending event key destruction replay witness for tenant %s", tenantID)
			}
			canonical, err := json.Marshal(request)
			if err != nil || !bytes.Equal(payload, canonical) ||
				request.Ref.TenantID != tenantID || key != EventKeyDestructionOutboxKey(request.OperationID) ||
				destination != EventKeyDestructionDestination || lane != destination || role != "control_plane" || agent != "" {
				return fmt.Errorf("store: invalid pending event key destruction replay witness for tenant %s", tenantID)
			}
			if request.OffboardSequence > sequence {
				skip = true
			}
		}
		return rows.Err()
	})
	return skip, err
}
