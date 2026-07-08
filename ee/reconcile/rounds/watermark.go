// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rounds

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrWatermarkRegressed = errors.New("xrec rounds: watermark regressed")
	ErrInvalidWatermark   = errors.New("xrec rounds: invalid watermark")
)

type WatermarkDecision struct {
	Divergent bool
	Class     string
	Reason    string
	Previous  string
	Current   Watermark
}

type WatermarkComparator func(current, previous string) int

type watermarkState struct {
	watermark      Watermark
	lastAdvancedAt time.Time
}

type WatermarkTracker struct {
	mu              sync.Mutex
	defaultLiveness time.Duration
	liveness        map[string]time.Duration
	states          map[string]watermarkState
	compare         WatermarkComparator
}

func NewWatermarkTracker(defaultLiveness time.Duration) *WatermarkTracker {
	return &WatermarkTracker{
		defaultLiveness: defaultLiveness,
		liveness:        map[string]time.Duration{},
		states:          map[string]watermarkState{},
		compare:         CompareWatermarkPosition,
	}
}

func (t *WatermarkTracker) SetLiveness(authorityID string, liveness time.Duration) {
	authorityID = strings.TrimSpace(authorityID)
	if authorityID == "" || liveness <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.liveness[authorityID] = liveness
}

func (t *WatermarkTracker) Advance(authorityID string, wm Watermark, observedNow time.Time) (WatermarkDecision, error) {
	authorityID = strings.TrimSpace(authorityID)
	wm.Position = strings.TrimSpace(wm.Position)
	if authorityID == "" || wm.Position == "" || wm.ObservedAt.IsZero() {
		return WatermarkDecision{}, ErrInvalidWatermark
	}
	if observedNow.IsZero() {
		observedNow = time.Now().UTC()
	}
	observedNow = observedNow.UTC()
	wm.ObservedAt = wm.ObservedAt.UTC()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.states == nil {
		t.states = map[string]watermarkState{}
	}
	if t.liveness == nil {
		t.liveness = map[string]time.Duration{}
	}
	compare := t.compare
	if compare == nil {
		compare = CompareWatermarkPosition
	}
	prev, ok := t.states[authorityID]
	if !ok {
		t.states[authorityID] = watermarkState{watermark: wm, lastAdvancedAt: observedNow}
		return WatermarkDecision{Current: wm}, nil
	}

	cmp := compare(wm.Position, prev.watermark.Position)
	if cmp < 0 {
		return WatermarkDecision{
			Divergent: true,
			Class:     DivergenceClassStaleness,
			Reason:    StalenessReasonRegressed,
			Previous:  prev.watermark.Position,
			Current:   wm,
		}, ErrWatermarkRegressed
	}

	advancedAt := prev.lastAdvancedAt
	if cmp > 0 {
		advancedAt = observedNow
	}
	t.states[authorityID] = watermarkState{watermark: wm, lastAdvancedAt: advancedAt}

	liveness := t.livenessFor(authorityID)
	if cmp == 0 && liveness > 0 && observedNow.Sub(prev.lastAdvancedAt) > liveness {
		return WatermarkDecision{
			Divergent: true,
			Class:     DivergenceClassStaleness,
			Reason:    StalenessReasonStalled,
			Previous:  prev.watermark.Position,
			Current:   wm,
		}, nil
	}
	return WatermarkDecision{Current: wm}, nil
}

func (t *WatermarkTracker) livenessFor(authorityID string) time.Duration {
	if d := t.liveness[authorityID]; d > 0 {
		return d
	}
	return t.defaultLiveness
}

// CompareWatermarkPosition orders opaque observation positions. Numeric cursors
// compare numerically; every other cursor falls back to bytewise string order.
func CompareWatermarkPosition(current, previous string) int {
	current = strings.TrimSpace(current)
	previous = strings.TrimSpace(previous)
	if c, cerr := strconv.ParseUint(current, 10, 64); cerr == nil {
		if p, perr := strconv.ParseUint(previous, 10, 64); perr == nil {
			switch {
			case c < p:
				return -1
			case c > p:
				return 1
			default:
				return 0
			}
		}
	}
	return strings.Compare(current, previous)
}
