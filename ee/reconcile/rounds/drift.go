// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

var ErrReplayRegressed = errors.New("xrec drift: replay watermark regressed")

type EventReplayer interface {
	Replay(context.Context, uint64, func(eventspec.Event) error) error
}

type DriftProjection struct {
	mu        sync.RWMutex
	window    time.Duration
	watermark uint64
	counts    map[driftCountKey]int64
	open      map[string]openWitness
	durations []CompletionDuration
}

type DriftSnapshot struct {
	ReplayWatermark     uint64
	WitnessClassCounts  []WitnessClassCount
	CompletionDurations []CompletionDuration
	OpenWitnesses       int
}

type WitnessClassCount struct {
	TenantID    string
	AuthorityID string
	Class       string
	WindowStart time.Time
	Count       int64
}

type CompletionDuration struct {
	TenantID  string
	WitnessID string
	Seconds   int64
}

type driftCountKey struct {
	tenantID    string
	authorityID string
	class       string
	window      time.Time
}

type openWitness struct {
	tenantID   string
	witnessID  string
	recordedAt time.Time
}

type DriftEventProjection struct {
	projection *DriftProjection
}

// NewDriftProjection builds the drift-metric projection. Every counter it exposes
// is derived by replaying ledger events, never incremented out of band, so the
// metrics are reconstructable from the ledger alone (XREC-claim-12).
func NewDriftProjection(window time.Duration) *DriftProjection {
	if window <= 0 {
		window = time.Hour
	}
	return &DriftProjection{
		window: window,
		counts: map[driftCountKey]int64{},
		open:   map[string]openWitness{},
	}
}

func NewDriftEventProjection(projection *DriftProjection) *DriftEventProjection {
	if projection == nil {
		projection = NewDriftProjection(time.Hour)
	}
	return &DriftEventProjection{projection: projection}
}

func WithDriftProjection(projection *DriftProjection) projections.Option {
	return projections.WithEventProjection(NewDriftEventProjection(projection))
}

func (p *DriftProjection) Reset() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.window <= 0 {
		p.window = time.Hour
	}
	p.watermark = 0
	p.counts = map[driftCountKey]int64{}
	p.open = map[string]openWitness{}
	p.durations = nil
}

func (p *DriftProjection) ReplayWatermark() uint64 {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.watermark
}

func (p *DriftEventProjection) Name() string { return "xrec.drift" }

func (p *DriftEventProjection) Reset(context.Context) error {
	if p == nil || p.projection == nil {
		return nil
	}
	p.projection.Reset()
	return nil
}

func (p *DriftEventProjection) Apply(_ context.Context, ev eventspec.Event) error {
	if p == nil || p.projection == nil {
		return nil
	}
	return p.projection.Apply(ev)
}

func (p *DriftEventProjection) ReplayWatermark() uint64 {
	if p == nil || p.projection == nil {
		return 0
	}
	return p.projection.ReplayWatermark()
}

func (p *DriftProjection) Replay(events []eventspec.Event) error {
	for _, ev := range events {
		if err := p.Apply(ev); err != nil {
			return err
		}
	}
	return nil
}

func (p *DriftProjection) Apply(ev eventspec.Event) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ev.Sequence != 0 && ev.Sequence <= p.watermark {
		return ErrReplayRegressed
	}
	switch ev.Type {
	case witness.EventTypeWitnessRecorded:
		var payload witness.WitnessRecorded
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return err
		}
		p.applyWitnessRecorded(ev, payload)
	case quarantine.EventTypeCompleted:
		var payload quarantine.Completed
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return err
		}
		p.applyCompletion(ev, payload)
	default:
	}
	if ev.Sequence > p.watermark {
		p.watermark = ev.Sequence
	}
	return nil
}

func (p *DriftProjection) Snapshot() DriftSnapshot {
	if p == nil {
		return DriftSnapshot{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	counts := make([]WitnessClassCount, 0, len(p.counts))
	for key, count := range p.counts {
		counts = append(counts, WitnessClassCount{
			TenantID:    key.tenantID,
			AuthorityID: key.authorityID,
			Class:       key.class,
			WindowStart: key.window,
			Count:       count,
		})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].TenantID != counts[j].TenantID {
			return counts[i].TenantID < counts[j].TenantID
		}
		if !counts[i].WindowStart.Equal(counts[j].WindowStart) {
			return counts[i].WindowStart.Before(counts[j].WindowStart)
		}
		if counts[i].AuthorityID != counts[j].AuthorityID {
			return counts[i].AuthorityID < counts[j].AuthorityID
		}
		return counts[i].Class < counts[j].Class
	})
	durations := append([]CompletionDuration(nil), p.durations...)
	sort.Slice(durations, func(i, j int) bool {
		if durations[i].TenantID != durations[j].TenantID {
			return durations[i].TenantID < durations[j].TenantID
		}
		return durations[i].WitnessID < durations[j].WitnessID
	})
	return DriftSnapshot{
		ReplayWatermark:     p.watermark,
		WitnessClassCounts:  counts,
		CompletionDurations: durations,
		OpenWitnesses:       len(p.open),
	}
}

func (p *DriftProjection) applyWitnessRecorded(ev eventspec.Event, payload witness.WitnessRecorded) {
	tenantID := strings.TrimSpace(payload.TenantID)
	witnessID := strings.TrimSpace(payload.WitnessID)
	if tenantID == "" || witnessID == "" {
		return
	}
	at := eventTime(ev, payload.Evidence.Body.GeneratedAt)
	p.open[witnessID] = openWitness{tenantID: tenantID, witnessID: witnessID, recordedAt: at}
	authorities := payload.Authorities
	if len(authorities) == 0 {
		for _, ref := range payload.Evidence.Body.DigestRefs {
			if authorityID := strings.TrimSpace(ref.AuthorityID); authorityID != "" {
				authorities = append(authorities, authorityID)
			}
		}
	}
	window := at.Truncate(p.window)
	for _, entry := range payload.Evidence.Body.Entries {
		class := strings.TrimSpace(entry.Class)
		if class == "" {
			continue
		}
		for _, authorityID := range authorities {
			authorityID = strings.TrimSpace(authorityID)
			if authorityID == "" {
				continue
			}
			p.counts[driftCountKey{tenantID: tenantID, authorityID: authorityID, class: class, window: window}]++
		}
	}
}

func (p *DriftProjection) applyCompletion(ev eventspec.Event, payload quarantine.Completed) {
	witnessID := strings.TrimSpace(payload.WitnessID)
	open, ok := p.open[witnessID]
	if !ok {
		return
	}
	completedAt := eventTime(ev, payload.CompletedAt)
	if completedAt.Before(open.recordedAt) {
		return
	}
	p.durations = append(p.durations, CompletionDuration{
		TenantID:  open.tenantID,
		WitnessID: witnessID,
		Seconds:   int64(completedAt.Sub(open.recordedAt).Seconds()),
	})
	delete(p.open, witnessID)
}

func eventTime(ev eventspec.Event, unix int64) time.Time {
	if !ev.Time.IsZero() {
		return ev.Time.UTC()
	}
	if unix != 0 {
		return time.Unix(unix, 0).UTC()
	}
	return time.Unix(0, 0).UTC()
}
