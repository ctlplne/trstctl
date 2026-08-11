// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"fmt"
	"sort"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

// OpenRequiringSanitizedSchedulerHistory is the fail-closed constructor for
// offline production commands that may read or append history but do not own the
// persistent audit signer needed to perform sanitation. It installs the live
// floor before inspecting raw history, rejects incomplete exact restores, and
// returns a log only when no legacy scheduler payload requires rewriting.
func OpenRequiringSanitizedSchedulerHistory(
	ctx context.Context,
	cfg config.NATS,
	options ...OpenOption,
) (*Log, error) {
	log, err := Open(ctx, cfg, options...)
	if err != nil {
		return nil, err
	}
	log.EnforceLegacySchedulerWriteFloor()
	if err := log.RequireNoPendingBackupRestore(ctx); err != nil {
		_ = log.Close()
		return nil, err
	}
	tenants, err := log.UnsafeLegacySchedulerHistoryTenants(ctx)
	if err != nil {
		_ = log.Close()
		return nil, err
	}
	if len(tenants) != 0 {
		_ = log.Close()
		return nil, schedulerhistory.ErrSanitationRequired
	}
	return log, nil
}

// UnsafeLegacySchedulerHistoryTenants scans raw retained history and returns
// only affected tenant IDs. It is the narrow sanitation discovery seam: unlike
// Replay it never exposes event bytes, so it remains usable after the live read
// floor is installed during an authenticated restore.
func (l *Log) UnsafeLegacySchedulerHistoryTenants(
	ctx context.Context,
) ([]string, error) {
	if l == nil {
		return nil, schedulerhistory.ErrSanitationRequired
	}
	unsafeTenants := make(map[string]struct{})
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, stream, err := l.resolveActiveStream(readCtx)
		if err != nil {
			return fmt.Errorf("events: resolve scheduler sanitation generation: %w", err)
		}
		// Keep the pending-restore decision and the complete sanitation scan in
		// one shared history view. A restore cannot bind its private prefix between
		// the check and replay, so an offline constructor never inspects or blesses
		// an artifact-bound partial generation.
		if err := l.requireNoPendingBackupRestoreStream(readCtx, stream); err != nil {
			return err
		}
		return l.replayActive(readCtx, 0, func(event Event) error {
			unsafe, err := schedulerhistory.RequiresSanitation(
				event.Type, event.SchemaVersion, event.Data,
			)
			if err != nil {
				return schedulerhistory.ErrSanitationRequired
			}
			if unsafe {
				unsafeTenants[event.TenantID] = struct{}{}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	tenants := make([]string, 0, len(unsafeTenants))
	for tenantID := range unsafeTenants {
		tenants = append(tenants, tenantID)
	}
	sort.Strings(tenants)
	return tenants, nil
}
