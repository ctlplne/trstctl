package scep

import (
	"sync"
	"time"
)

type deviceWindowCounter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

func newDeviceWindowCounter(now func() time.Time) *deviceWindowCounter {
	if now == nil {
		now = time.Now
	}
	return &deviceWindowCounter{hits: make(map[string][]time.Time), now: now}
}

func (w *deviceWindowCounter) Allow(key string, max int, window time.Duration) bool {
	if w == nil || max <= 0 || key == "" {
		return true
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	now := w.now()
	cutoff := now.Add(-window)

	w.mu.Lock()
	defer w.mu.Unlock()
	prior := w.hits[key]
	kept := prior[:0]
	for _, ts := range prior {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= max {
		w.hits[key] = kept
		return false
	}
	w.hits[key] = append(kept, now)
	return true
}
