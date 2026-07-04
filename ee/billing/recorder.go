// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type Recorder struct {
	store Store
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	pending map[recordKey]int64
}

func NewRecorder(store Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: store, log: log, now: time.Now, pending: map[recordKey]int64{}}
}

func (r *Recorder) WithClock(now func() time.Time) *Recorder {
	if now != nil {
		r.now = now
	}
	return r
}

func (r *Recorder) Record(tenantID, meter string, delta int64) {
	if r == nil || tenantID == "" || meter == "" || delta <= 0 {
		return
	}
	k := recordKey{tenant: tenantID, meter: meter, period: PeriodStart(r.now())}
	r.mu.Lock()
	r.pending[k] += delta
	r.mu.Unlock()
}

func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil || r.store == nil {
		return nil
	}
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return nil
	}
	batch := r.pending
	r.pending = map[recordKey]int64{}
	r.mu.Unlock()

	deltas := make([]CounterDelta, 0, len(batch))
	for k, delta := range batch {
		deltas = append(deltas, CounterDelta{TenantID: k.tenant, Meter: k.meter, Period: k.period, Delta: delta})
	}
	if err := r.store.AddCounters(ctx, deltas); err != nil {
		r.mu.Lock()
		for k, delta := range batch {
			r.pending[k] += delta
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := r.Flush(flushCtx); err != nil && r.log != nil {
				r.log.Warn("metering final flush failed", slog.String("error", err.Error()))
			}
			cancel()
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil && r.log != nil {
				r.log.Warn("metering flush failed; deltas retained for retry", slog.String("error", err.Error()))
			}
		}
	}
}
