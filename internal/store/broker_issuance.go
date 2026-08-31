// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BrokerIssuance is the original public broker command, not today's owner or
// discovery observation. It lives on the shared certificate row and travels in
// the same certificate.recorded event. Proofs, task bodies, claims and keys are
// deliberately absent. Nil means unrecorded or removed by privacy policy.
type BrokerIssuance struct {
	AgentID             string   `json:"agent_id"`
	Subject             string   `json:"subject"`
	Method              string   `json:"method"`
	OwnerID             string   `json:"owner_id"`
	Scopes              []string `json:"scopes"`
	TaskEnvelopeDigest  string   `json:"task_envelope_digest,omitempty"`
	RequestedTTLSeconds int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds int64    `json:"effective_ttl_seconds"`
}

func validateBrokerIssuance(c Certificate) error {
	m := c.BrokerIssuance
	if m == nil {
		return nil
	}
	binding, err := hex.DecodeString(c.IssuanceRequestBinding)
	if err != nil || len(binding) != 32 || m.AgentID == "" || m.Subject == "" || m.Method == "" ||
		len(m.Scopes) == 0 || m.EffectiveTTLSeconds < 0 || c.Source != "broker:"+m.Method ||
		!strings.HasPrefix(c.IssuanceIdempotencyKey, "broker-issue:") {
		return fmt.Errorf("store: incomplete broker issuance facts or authenticated command binding")
	}
	if _, err := uuid.Parse(m.OwnerID); err != nil {
		return fmt.Errorf("store: broker issuance owner must be a stable owner ID")
	}
	for _, scope := range m.Scopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("store: broker issuance scope must not be empty")
		}
	}
	return nil
}

// Called only while projecting the certificate event, in the same transaction.
// A repeated fact converges. A conflicting second issuance fact rolls back the
// whole projection; a later discovery observation cannot silently replace it.
func applyBrokerIssuanceTx(ctx context.Context, tx pgx.Tx, c Certificate) error {
	if c.BrokerIssuance == nil {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE certificates SET broker_issuance = $3
		WHERE tenant_id = $1 AND fingerprint = $2
		  AND (broker_issuance IS NULL OR broker_issuance = $3::jsonb)
		  AND issuance_request_binding = $4`,
		c.TenantID, c.Fingerprint, c.BrokerIssuance, c.IssuanceRequestBinding)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: certificate already has different broker issuance facts", ErrIdempotencyConflict)
	}
	return nil
}
