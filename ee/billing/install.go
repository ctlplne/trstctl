// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

type Installation struct {
	Store        *MemStore
	Recorder     *Recorder
	QuotaChecker *QuotaChecker
}

func InstallInMemory(ctx context.Context, log *slog.Logger, count TenantCounter) *Installation {
	store := NewMemStore()
	recorder := NewRecorder(store, log)
	checker := NewQuotaChecker(store, count, time.Minute)
	usage.SetRecorder(recorder)
	usage.SetQuotaChecker(checker)
	go recorder.Run(ctx, time.Minute)
	return &Installation{Store: store, Recorder: recorder, QuotaChecker: checker}
}
