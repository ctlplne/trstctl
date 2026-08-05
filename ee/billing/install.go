// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"log/slog"
	"time"

	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

type Installation struct {
	Store        *MemStore
	Recorder     *Recorder
	QuotaChecker *QuotaChecker
	// Durable reports whether usage survives a restart. It is what MaySign
	// consults, so an in-memory installation cannot sign invoice evidence — the
	// fallback is visible rather than silent.
	Durable bool
	// PG is the durable store when there is one, for coverage queries.
	PG *PGStore
}

func InstallInMemory(ctx context.Context, log *slog.Logger, count TenantCounter) *Installation {
	store := NewMemStore()
	recorder := NewRecorder(store, log)
	checker := NewQuotaChecker(store, count, time.Minute)
	usage.SetRecorder(recorder)
	usage.SetQuotaChecker(checker)
	go recorder.Run(ctx, time.Minute)
	return &Installation{Store: store, Recorder: recorder, QuotaChecker: checker, Durable: false}
}

// InstallDurable wires metering to PostgreSQL (L2).
//
// The in-memory installation loses usage on restart SILENTLY, so a provider
// invoices from a figure that is quietly short. This one survives, and records
// what it actually observed so MaySign can refuse a period the store cannot
// prove it covered.
//
// It falls back to in-memory when no store is available rather than failing to
// start — but the fallback is VISIBLE, because Installation.Durable is what
// MaySign consults, and an in-memory installation can never sign evidence.
func InstallDurable(ctx context.Context, log *slog.Logger, count TenantCounter, st *corestore.Store) *Installation {
	if st == nil {
		inst := InstallInMemory(ctx, log, count)
		inst.Durable = false
		return inst
	}
	store := NewPGStore(st)
	recorder := NewRecorder(store, log)
	checker := NewQuotaChecker(store, count, time.Minute)
	usage.SetRecorder(recorder)
	usage.SetQuotaChecker(checker)
	go recorder.Run(ctx, time.Minute)
	return &Installation{Recorder: recorder, QuotaChecker: checker, Durable: true, PG: store}
}
