// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DiscoveryFindingProviderAction is one step of an action taken at the
// provider on what a finding names (A170, A171): revoking an OAuth grant or
// blocking its application. It is kept on the finding itself, under
// metadata.provider_actions.<action>, so the finding shows what was asked of
// the provider and what the provider confirmed.
type DiscoveryFindingProviderAction struct {
	TenantID  string
	FindingID string
	Action    string
	Status    string
	Provider  string
	Detail    string
	RequestID string
	At        time.Time
}

// ApplyDiscoveryFindingProviderActionTx projects one provider action step.
func (s *Store) ApplyDiscoveryFindingProviderActionTx(ctx context.Context, tx pgx.Tx, a DiscoveryFindingProviderAction) error {
	state, err := json.Marshal(map[string]any{
		"status": a.Status, "provider": a.Provider, "detail": a.Detail,
		"request_id": a.RequestID, "updated_at": a.At.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_findings
		    SET metadata = jsonb_set(
		            CASE WHEN jsonb_typeof(metadata->'provider_actions') = 'object' THEN metadata
		                 ELSE metadata || '{"provider_actions":{}}'::jsonb END,
		            ARRAY['provider_actions', $3::text], $4::jsonb, true)
		  WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.FindingID, a.Action, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: provider action names no finding %s", a.FindingID)
	}
	return nil
}
