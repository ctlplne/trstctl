// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrAgentJobReceiptConflict means a signed retry changed the recorded terminal
// observation. A new signature or signing time alone is not a changed outcome.
var ErrAgentJobReceiptConflict = errors.New("store: terminal agent receipt conflicts with recorded observation")

func preserveTerminalReceipt(ctx context.Context, tx pgx.Tx, tenantID string, r AgentJobReceipt) error {
	if r.State != AgentJobReceiptVerified {
		return nil
	}
	// A row lock cannot protect the first insert because the row does not yet
	// exist. This lock also serializes the audit append preceding that insert.
	key := fmt.Sprintf("agent-receipt/v1/%s/%d/%d", tenantID, r.JobID, r.Attempt)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return err
	}
	var previous AgentJobReceipt
	err := tx.QueryRow(ctx, `SELECT agent, outcome, statement FROM agent_job_receipts
		WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='verified'`,
		tenantID, r.JobID, r.Attempt).Scan(&previous.Agent, &previous.Outcome, &previous.Statement)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	switch previous.Outcome {
	case "executed", "verified", "verify_failed", "failed":
		if previous.Agent != r.Agent || previous.Outcome != r.Outcome ||
			!SameAgentJobReceiptObservation(previous.Statement, r.Statement) {
			return ErrAgentJobReceiptConflict
		}
	}
	return nil
}

// SameAgentJobReceiptObservation compares the signed facts while allowing a
// fresh signing timestamp. Unknown statement formats require identical bytes.
func SameAgentJobReceiptObservation(left, right string) bool {
	return receiptObservation(left) == receiptObservation(right)
}

// Retrying after an outage may require a fresh signature and certificate. Only
// the final signing timestamp is excluded; every observation and custody field
// remains bound. Legacy or malformed statements are compared byte-for-byte.
func receiptObservation(statement string) string {
	if !strings.HasPrefix(statement, "trstctl-agent-job-receipt/v1\n") &&
		!strings.HasPrefix(statement, "trstctl-agent-job-receipt/v2\n") {
		return statement
	}
	prefix, timestamp, ok := strings.Cut(statement, "\nissued_at=")
	if !ok || !strings.HasSuffix(timestamp, "\n") {
		return statement
	}
	if n, err := strconv.ParseInt(strings.TrimSuffix(timestamp, "\n"), 10, 64); err != nil || n <= 0 {
		return statement
	}
	return prefix
}
