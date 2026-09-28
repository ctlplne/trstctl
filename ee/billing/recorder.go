// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

type Recorder struct {
	store         Store
	log           *slog.Logger
	now           func() time.Time
	refreshIssued func(context.Context) error

	mu            sync.Mutex
	flushMu       sync.Mutex
	pending       map[recordKey]int64
	observing     map[observationKey]observationState
	registrations map[string]string
	lookups       map[string]uint64
	nextLookup    uint64
}

type observationState struct {
	from       time.Time
	generation uint64
}

type observationKey struct {
	tenant       string
	registration string
}

var errObservationRegistration = errors.New("billing: observation belongs to an erased or replaced tenant registration")

type observationStore interface {
	ObservationRegistration(context.Context, string) (string, error)
	FlushObservedCounters(context.Context, string, string, time.Time, time.Time, []CounterDelta) error
}

func newDurableRecorder(store *PGStore, log *slog.Logger) *Recorder {
	r := NewRecorder(store, log)
	r.refreshIssued = store.RefreshIssuedCounters
	return r
}

func NewRecorder(store Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: store, log: log, now: time.Now, pending: map[recordKey]int64{}, observing: map[observationKey]observationState{}, registrations: map[string]string{}, lookups: map[string]uint64{}}
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
	if meter == usage.MeterCertificatesIssued && r.refreshIssued != nil {
		// The committed certificate event owns both identity and time. An
		// unkeyed process hint cannot safely add another count or select its hour.
		return
	}
	at := r.now()
	registration := ""
	var ticket uint64
	if durable, ok := r.store.(observationStore); ok {
		r.mu.Lock()
		r.nextLookup++
		ticket = r.nextLookup
		r.lookups[tenantID] = ticket
		previous := r.registrations[tenantID]
		r.mu.Unlock()
		// Resolve outside the mutex. Capture the previous lifetime before the
		// read: a transient error may retain its counters, never transfer them
		// to a replacement tenant discovered after the error.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var err error
		registration, err = durable.ObservationRegistration(ctx, tenantID)
		cancel()
		if err != nil {
			r.mu.Lock()
			for key := range r.observing {
				if key.tenant == tenantID {
					delete(r.observing, key)
				}
			}
			if previous != "" && !errors.Is(err, errObservationRegistration) {
				// Flush rechecks this exact registration under the lifecycle
				// lock. Saving the delta does not restore observation coverage.
				k := recordKey{tenant: tenantID, meter: meter, period: PeriodStart(at), registration: previous}
				r.pending[k] += delta
			}
			r.mu.Unlock()
			r.log.Warn("metering observation interrupted; usage requires reconciliation", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			return
		}
	}
	r.mu.Lock()
	k := recordKey{tenant: tenantID, meter: meter, period: PeriodStart(at), registration: registration}
	observer := observationKey{tenant: tenantID, registration: registration}
	if ticket == r.lookups[tenantID] {
		r.registrations[tenantID] = registration
		if _, exists := r.observing[observer]; !exists {
			// Start after the identity read succeeds. An older in-flight read
			// cannot restore observation interrupted by a newer read.
			r.observing[observer] = observationState{from: r.now(), generation: ticket}
		}
	}
	r.pending[k] += delta
	r.mu.Unlock()
}

func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil || r.store == nil {
		return nil
	}
	// Serialize flushes: a newer observation must not cover an older batch
	// whose database transaction is still in flight.
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	until := r.now()
	observed := make(map[observationKey]observationState, len(r.observing))
	for observer, from := range r.observing {
		observed[observer] = from
	}
	batch := r.pending
	r.pending = map[recordKey]int64{}
	r.mu.Unlock()

	// The durable store commits each tenant in its own RLS transaction. Flush
	// those groups independently so a later tenant failure cannot replay an
	// earlier tenant's already committed counters.
	byTenant := make(map[observationKey][]CounterDelta)
	for k, delta := range batch {
		observer := observationKey{tenant: k.tenant, registration: k.registration}
		byTenant[observer] = append(byTenant[observer], CounterDelta{TenantID: k.tenant, Meter: k.meter, Period: k.period, Delta: delta})
	}
	durable, recordsObservation := r.store.(observationStore)
	if recordsObservation {
		// Keep known customers covered during quiet periods. A new process has
		// an empty observing map and cannot inherit its predecessor's start.
		for observer := range observed {
			if _, exists := byTenant[observer]; !exists {
				byTenant[observer] = nil
			}
		}
	}
	var failures []error
	for observer, deltas := range byTenant {
		var err error
		if recordsObservation {
			err = durable.FlushObservedCounters(ctx, observer.tenant, observer.registration, observed[observer].from, until, deltas)
		} else {
			err = r.store.AddCounters(ctx, deltas)
		}
		if err != nil {
			r.mu.Lock()
			if errors.Is(err, errObservationRegistration) {
				delete(r.observing, observer)
				// Erasure owns this old lifecycle, including any late deltas.
				for key := range r.pending {
					if key.tenant == observer.tenant && key.registration == observer.registration {
						delete(r.pending, key)
					}
				}
			} else {
				for _, delta := range deltas {
					k := recordKey{tenant: delta.TenantID, meter: delta.Meter, period: delta.Period, registration: observer.registration}
					r.pending[k] += delta.Delta
				}
			}
			r.mu.Unlock()
			failures = append(failures, err)
		} else if recordsObservation {
			r.mu.Lock()
			if from, exists := r.observing[observer]; exists && from == observed[observer] {
				r.observing[observer] = observationState{from: until, generation: from.generation}
			}
			r.mu.Unlock()
		}
	}
	if r.refreshIssued != nil {
		if err := r.refreshIssued(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	if r.refreshIssued != nil {
		if err := r.Flush(ctx); err != nil && r.log != nil {
			r.log.Warn("initial issuance metering refresh failed; source facts retained for retry", slog.String("error", err.Error()))
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// The final flush runs BECAUSE ctx is done, so it cannot inherit
			// that cancellation — WithoutCancel detaches it while keeping the
			// parent's values, bounded by its own timeout.
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
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
