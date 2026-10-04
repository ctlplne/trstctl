// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// auditRetentionScopeKey elects one archiver per source partition across all
// replicas. A hash collision only serializes two scopes; it cannot mix their
// records. The domain prefix keeps the key separate from other advisory locks.
func auditRetentionScopeKey(scope string) int64 {
	digest := crypto.SHA256Sum([]byte("trstctl:audit-retention-scope:v1\x00" + scope))
	return int64(binary.BigEndian.Uint64(digest[:8])) // #nosec G115 -- PostgreSQL advisory keys are signed bit patterns.
}

// WithAuditRetentionScope serializes one logical audit archive/checkpoint
// sequence. Its shared operation grant lets unrelated Provider readers/writers
// proceed but excludes a rewrite or backup taking the exclusive side. The
// caller then holds the shared history-generation barrier through checkpoint
// storage, so neither a cutover nor a backup can split the archive receipt.
func (s *Store) WithAuditRetentionScope(ctx context.Context, scope string, fn func(context.Context) error) error {
	if scope == "" || fn == nil {
		return errors.New("store: audit retention needs a scope and callback")
	}
	if _, err := uuid.Parse(scope); err != nil && scope != events.LegacyProviderGlobalAuditScope {
		return fmt.Errorf("store: unsupported audit retention scope %q", scope)
	}
	return s.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return NewHistoryRewriteCoordinator(s).withLock(
			barrierCtx, auditRetentionScopeKey(scope), false, "audit retention scope", fn,
		)
	})
}
