// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// plainTenantID is the alphabet a tenant ID may be written into SQL in: UUIDs
// and the store's named partitions. Nothing in it needs escaping, whatever the
// server's standard_conforming_strings, so no caller text is ever quoted in.
var plainTenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// tenantTxSetup is a tenant transaction's whole setup as one simple-protocol
// message: BEGIN, the shared backup write fence, the RLS role, the tenant's
// schema route when it has one, and the tenant GUC — the statements and the
// order WithTenant has always used, in one round trip instead of three. A
// tenant ID outside plainTenantID keeps the parameterized path.
func tenantTxSetup(tenantID, schema string) (string, bool) {
	if !plainTenantID.MatchString(tenantID) {
		return "", false
	}
	var b strings.Builder
	b.WriteString("BEGIN; SELECT pg_advisory_xact_lock_shared(")
	b.WriteString(strconv.FormatInt(BackupWriteFenceAdvisoryLockKey, 10))
	b.WriteString("); SET LOCAL ROLE ")
	b.WriteString(appRole)
	if schema != "" {
		b.WriteString("; SET LOCAL search_path TO ")
		b.WriteString(pgx.Identifier{schema}.Sanitize())
		b.WriteString(", public")
	}
	b.WriteString("; SELECT set_config('trstctl.tenant_id', '")
	b.WriteString(tenantID)
	b.WriteString("', true)")
	return b.String(), true
}

// beginTenantTx acquires a connection inside the store's acquire window, then
// sends setup as the transaction's begin under the caller's context, so the
// fence lock waits as long as it always has rather than the acquire window. A
// statement in setup that fails leaves that session in an aborted block, which
// the pool destroys on release, rolling it back; no tenant statement runs.
func (s *Store) beginTenantTx(ctx context.Context, setup string) (pgx.Tx, error) {
	pool := s.poolFor(ctx)
	acquireCtx := ctx
	if s.acquireTimeout > 0 {
		bounded, cancel := context.WithTimeoutCause(ctx, s.acquireTimeout, ErrDatastoreBusy)
		defer cancel()
		acquireCtx = bounded
	}
	conn, err := pool.Acquire(acquireCtx)
	if err != nil {
		if cause := context.Cause(acquireCtx); errors.Is(cause, ErrDatastoreBusy) && ctx.Err() == nil {
			return nil, fmt.Errorf("%w (acquire window %v)", ErrDatastoreBusy, s.acquireTimeout)
		}
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{BeginQuery: setup})
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("store: begin tenant transaction (fence, role, tenant): %w", err)
	}
	return &pooledConnTx{Tx: tx, conn: conn}, nil
}

// prepareTenantRoleTx is the parameterized setup for a tenant ID outside
// plainTenantID: PostgreSQL executes this batch in order within the caller's
// transaction, crossing the backup fence and then assuming the RLS role; route
// resolution and tenant selection follow before any caller query. An
// exclusive-fence owner keeps its existing single-session path instead.
func prepareTenantRoleTx(ctx context.Context, tx pgx.Tx) (err error) {
	batch := &pgx.Batch{}
	batch.Queue("SELECT pg_advisory_xact_lock_shared($1)", BackupWriteFenceAdvisoryLockKey)
	batch.Queue("SET LOCAL ROLE " + appRole)
	results := tx.SendBatch(ctx, batch)
	defer func() {
		if closeErr := results.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("store: finish tenant role setup: %w", closeErr)
		}
	}()
	if _, err := results.Exec(); err != nil {
		return fmt.Errorf("store: acquire backup write fence: %w", err)
	}
	if _, err := results.Exec(); err != nil {
		return fmt.Errorf("store: set role: %w", err)
	}
	return nil
}
