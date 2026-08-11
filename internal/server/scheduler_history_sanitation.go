// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
	"trstctl.com/trstctl/internal/store"
)

// ensureLegacySchedulerHistorySanitized is the one production entry point for
// AUD-116's repository-controlled live-history closure. It runs before serving,
// projection catch-up, rebuild, or export. Already-written external archives are
// intentionally outside this function's authority and remain disclosed by each
// signed TenantDataRewriteReport.ArchiveExposure value.
func ensureLegacySchedulerHistorySanitized(
	ctx context.Context,
	log *events.Log,
	st *store.Store,
	auditKey *jose.SigningKey,
	fleetReady bool,
) error {
	if log == nil || st == nil || auditKey == nil {
		return errors.New("server: scheduler history sanitation requires event log, store, and audit key")
	}
	if err := log.RequireNoPendingBackupRestore(ctx); err != nil {
		return err
	}
	if err := log.HistoryRewriteReady(); err != nil {
		return err
	}
	return log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		// Exact restore and sanitation share the history-operation lock. Recheck
		// the durable binding after acquiring it so a restore cannot begin in the
		// gap between constructor preflight and rewrite staging.
		if err := log.RequireNoPendingBackupRestore(operationCtx); err != nil {
			return err
		}
		tenants, err := unsafeSchedulerHistoryTenants(operationCtx, log)
		if err != nil {
			return err
		}
		if len(tenants) == 0 {
			return nil
		}
		if !fleetReady {
			return schedulerhistory.ErrSanitationRequired
		}

		options := append(
			historyRewriteProofOptions(st, auditKey),
			events.WithTenantDataPairValidator(schedulerHistoryPairValidator),
			events.WithTenantDataRewriteProfile(schedulerhistory.RewriteProfile),
		)
		if err := events.ValidateTenantDataRewriteOptions(options...); err != nil {
			return err
		}
		for _, tenantID := range tenants {
			if _, err := log.RewriteTenantData(
				operationCtx, tenantID, schedulerHistoryTransform, options...,
			); err != nil {
				return err
			}
		}
		remaining, err := unsafeSchedulerHistoryTenants(operationCtx, log)
		if err != nil {
			return err
		}
		if len(remaining) != 0 {
			return schedulerhistory.ErrSanitationRequired
		}
		return nil
	})
}

func unsafeSchedulerHistoryTenants(ctx context.Context, log *events.Log) ([]string, error) {
	return log.UnsafeLegacySchedulerHistoryTenants(ctx)
}

func schedulerHistoryTransform(
	eventType string,
	schemaVersion int,
	data []byte,
) ([]byte, bool, error) {
	if eventType != schedulerhistory.EventType || schemaVersion != schedulerhistory.LegacySchemaVersion {
		return append([]byte(nil), data...), false, nil
	}
	return schedulerhistory.RewriteLegacyRun(data)
}

func schedulerHistoryPairValidator(
	eventType string,
	schemaVersion int,
	before, after []byte,
) error {
	if eventType != schedulerhistory.EventType || schemaVersion != schedulerhistory.LegacySchemaVersion {
		return errors.New("server: scheduler history sanitation changed an event outside its signed profile")
	}
	if bytes.Equal(before, after) {
		return errors.New("server: scheduler history sanitation reported an unchanged pair")
	}
	return schedulerhistory.ValidateLegacyRunPair(before, after)
}
