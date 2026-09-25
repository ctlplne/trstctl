// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

type authorityFenceKey struct{}
type authorityFence struct {
	store  *corestore.Store
	active atomic.Bool
}

// Lifecycle commands already hold this fence while checking authority. Nested
// appends reuse it instead of waiting on a second PostgreSQL session.
func withAuthorityFence(ctx context.Context, st *corestore.Store, fn func(context.Context) error) error {
	if fence, _ := ctx.Value(authorityFenceKey{}).(*authorityFence); fence != nil && fence.store == st {
		if !fence.active.Load() {
			return errors.New("provider: authority fence has ended")
		}
		return fn(ctx)
	}
	// An append may need ordered recovery after a crash. Take the privacy
	// replacement barrier first, in the same order as core replay, so recovery
	// cannot restore data during a prepared privacy erasure.
	return st.WithPrivacyReadModelReplacementBarrier(ctx, func(ctx context.Context) error {
		return st.WithProjectionLock(ctx, func(ctx context.Context) error {
			fence := &authorityFence{store: st}
			fence.active.Store(true)
			defer fence.active.Store(false)
			return fn(context.WithValue(ctx, authorityFenceKey{}, fence))
		})
	})
}

// ErrAuthorityRebuildRequired refuses an unproved old application. Returning
// success would lose an event; applying it would overwrite a newer decision.
var ErrAuthorityRebuildRequired = errors.New("provider: authority projection requires ordered event recovery")

func lockAuthorityProjectionTx(ctx context.Context, tx pgx.Tx) error {
	// Relation locks precede the advisory lock so a rebuild holding these tables
	// cannot wait behind a writer that has the advisory lock but needs a table.
	if _, err := tx.Exec(ctx, `LOCK TABLE provider_operator_delegations, provider_operators,
		provider_breakglass_grants, provider_tenant_quotas, tenant_branding,
		provider_tenants, provider_authority_projection_receipts,
		provider_authority_projection_state IN ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(0x70727661757468))
	return err
}

func authorityReceiptDigest(event events.Event) (string, error) {
	if event.Sequence > math.MaxInt64 {
		return "", errors.New("provider: authority event sequence exceeds PostgreSQL bigint")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(encoded), nil
}

func authorityEventCompletedTx(ctx context.Context, tx pgx.Tx, event events.Event, digest string) (bool, error) {
	if event.Sequence == 0 {
		return false, nil // Unsequenced legacy fixtures cannot claim durable completion.
	}
	var needsRebuild bool
	//trstctl:system-query — a missing upgrade-state row is not proof of an initialized Provider projection.
	if err := tx.QueryRow(ctx, `SELECT needs_rebuild FROM provider_authority_projection_state
		WHERE tenant_id = $1`, providerAuthorityTenant).Scan(&needsRebuild); err != nil {
		return false, fmt.Errorf("%w: read upgrade state: %v", ErrAuthorityRebuildRequired, err)
	}
	if needsRebuild {
		return false, fmt.Errorf("%w: legacy authority has no completion receipts", ErrAuthorityRebuildRequired)
	}
	var sequence int64
	var id, recordedDigest string
	//trstctl:system-query — fixed Provider authority partition; the receipt binds the full envelope, including its customer tenant.
	err := tx.QueryRow(ctx, `SELECT event_sequence, event_id, event_digest
		FROM provider_authority_projection_receipts
		WHERE tenant_id = $1 AND (event_sequence = $2::bigint OR event_id = $3)`,
		providerAuthorityTenant, strconv.FormatUint(event.Sequence, 10), event.ID).Scan(&sequence, &id, &recordedDigest)
	if err == nil {
		if sequence < 0 || uint64(sequence) != event.Sequence || id != event.ID || recordedDigest != digest {
			return false, fmt.Errorf("%w: recorded event identity differs", ErrAuthorityRebuildRequired)
		}
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var latest int64
	//trstctl:system-query — fixed Provider authority partition, never a caller-selected tenant.
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(event_sequence), 0)
		FROM provider_authority_projection_receipts WHERE tenant_id = $1`, providerAuthorityTenant).Scan(&latest); err != nil {
		return false, err
	}
	if latest < 0 || uint64(latest) > event.Sequence {
		return false, fmt.Errorf("%w: event %d has no completion receipt before event %d", ErrAuthorityRebuildRequired, event.Sequence, latest)
	}
	return false, nil
}

// recoverOrdered projects one retained history prefix atomically. A missing old
// receipt is not skipped: it and every later decision are folded in event order.
func (p *AuthorityProjection) recoverOrdered(ctx context.Context, log *events.Log) error {
	return p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(ctx context.Context) error {
		return p.recoverHistory(ctx, log)
	})
}

func (p *AuthorityProjection) recoverHistory(ctx context.Context, log *events.Log) error {
	return log.WithHistoryRead(ctx, func(ctx context.Context) error {
		tx, err := p.store.SystemPool().Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := lockAuthorityProjectionTx(ctx, tx); err != nil {
			return err
		}
		var needsRebuild bool
		//trstctl:system-query — the fixed Provider upgrade partition cannot be reset before legacy rows are captured as events.
		if err := tx.QueryRow(ctx, `SELECT needs_rebuild FROM provider_authority_projection_state
			WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&needsRebuild); err != nil {
			return fmt.Errorf("%w: read upgrade state: %v", ErrAuthorityRebuildRequired, err)
		}
		captured, _ := ctx.Value(authorityBootstrapCaptureContext{}).(bool)
		if needsRebuild && !captured {
			return fmt.Errorf("%w: bootstrap must capture legacy authority first", ErrAuthorityRebuildRequired)
		}
		head, err := log.LastSequence(ctx)
		if err != nil {
			return err
		}
		var latest int64
		//trstctl:system-query — refuse to replace a Provider projection with a shorter, incomplete source history.
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(event_sequence), 0)
			FROM provider_authority_projection_receipts WHERE tenant_id = $1`, providerAuthorityTenant).Scan(&latest); err != nil {
			return err
		}
		if latest < 0 || uint64(latest) > head {
			return fmt.Errorf("%w: projected history exceeds retained source", ErrAuthorityRebuildRequired)
		}
		if err := p.ResetTx(ctx, tx); err != nil {
			return err
		}
		if head != 0 {
			if err := log.ReplayThrough(ctx, 1, head, func(event events.Event) error {
				return p.ApplyTx(ctx, tx, event)
			}); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	})
}

func recordAuthorityCompletionTx(ctx context.Context, tx pgx.Tx, event events.Event, digest string) error {
	if event.Sequence == 0 {
		return nil
	}
	//trstctl:system-query — receipt and Provider state commit in the same transaction under the fixed authority partition.
	_, err := tx.Exec(ctx, `INSERT INTO provider_authority_projection_receipts
		(tenant_id, event_sequence, event_id, event_digest) VALUES ($1, $2::bigint, $3, $4)`,
		providerAuthorityTenant, strconv.FormatUint(event.Sequence, 10), event.ID, digest)
	return err
}
