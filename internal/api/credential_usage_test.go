// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type usageSinkStub struct {
	uses    []projections.CredentialUsed
	gaps    []projections.CredentialUsageGap
	failUse bool
	failGap bool
}

func (s *usageSinkStub) RecordCredentialUse(_ context.Context, _, eventID string, used projections.CredentialUsed) error {
	if s.failUse {
		return errors.New("event log unavailable")
	}
	if eventID == "" {
		return errors.New("no event id")
	}
	s.uses = append(s.uses, used)
	return nil
}

func (s *usageSinkStub) RecordCredentialUsageGap(_ context.Context, _, _ string, gap projections.CredentialUsageGap) error {
	if s.failGap {
		return errors.New("event log unavailable")
	}
	s.gaps = append(s.gaps, gap)
	return nil
}

// M1: one token's uses in an hour are recorded at counts 1, 2, 4, … 1024 and
// no more; a new hour starts again at 1. A use that cannot be queued or
// recorded becomes a recorded gap, never silence.
func TestCredentialUsageRecorderBoundsUsesAndRecordsGapsM1(t *testing.T) {
	at := time.Date(2026, 11, 1, 10, 15, 0, 0, time.UTC)
	r := newCredentialUsageRecorder(func() time.Time { return at })
	for i := 0; i < 3000; i++ {
		r.note("tenant-a", "token-1", "ci", "10.20.30.0/24", projections.CredentialActionSecretRead)
	}
	sink := &usageSinkStub{}
	if err := r.drain(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	var counts []int
	for _, u := range sink.uses {
		counts = append(counts, u.Count)
		if !u.WindowStart.Equal(at.Truncate(time.Hour)) || u.Source != "10.20.30.0/24" || u.Action != projections.CredentialActionSecretRead {
			t.Fatalf("use = %+v", u)
		}
	}
	if want := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}; !slices.Equal(counts, want) {
		t.Fatalf("recorded counts %v, want %v", counts, want)
	}
	at = at.Add(time.Hour)
	r.note("tenant-a", "token-1", "ci", "10.20.30.0/24", projections.CredentialActionSecretRead)
	sink.uses = nil
	if err := r.drain(context.Background(), sink); err != nil || len(sink.uses) != 1 || sink.uses[0].Count != 1 {
		t.Fatalf("a new hour = %+v (%v)", sink.uses, err)
	}

	// The queue is full: the overflow is a gap with its count.
	for i := 0; i < credentialUsageQueueSize+10; i++ {
		r.note("tenant-b", fmt.Sprintf("token-%d", i), "svc", "10.0.0.0/24", projections.CredentialActionAPICall)
	}
	sink.uses, sink.gaps = nil, nil
	if err := r.drain(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.uses) != credentialUsageQueueSize || len(sink.gaps) != 1 || sink.gaps[0].Dropped != 10 {
		t.Fatalf("overflow: %d uses, gaps %+v", len(sink.uses), sink.gaps)
	}

	// The event log refuses: the uses become a gap, kept until it is recorded.
	r.note("tenant-c", "token-x", "svc", "10.0.0.0/24", projections.CredentialActionAPICall)
	failing := &usageSinkStub{failUse: true, failGap: true}
	if err := r.drain(context.Background(), failing); err == nil {
		t.Fatal("a failed recording reported success")
	}
	sink.uses, sink.gaps = nil, nil
	if err := r.drain(context.Background(), sink); err != nil || len(sink.gaps) != 1 || sink.gaps[0].Dropped != 1 {
		t.Fatalf("the kept gap = %+v (%v)", sink.gaps, err)
	}
}

func TestCredentialUseSourceAndActionM1(t *testing.T) {
	for addr, want := range map[string]string{
		"10.20.30.40:5555":       "10.20.30.0/24",
		"127.0.0.1:61000":        "127.0.0.0/24",
		"[2001:db8::1]:443":      "2001:db8::/64",
		"[::ffff:10.1.2.3]:80":   "10.1.2.0/24",
		"[fe80::1%eth0]:443":     "fe80::/64",
		"not-an-address":         "unknown",
		"192.0.2.9":              "192.0.2.0/24",
		"[2001:db8:1:2:3::]:900": "2001:db8:1:2::/64",
	} {
		if got := credentialUseNetwork(addr); got != want {
			t.Errorf("credentialUseNetwork(%q) = %q, want %q", addr, got, want)
		}
	}
	for pattern, want := range map[string]string{
		"POST /api/v1/secrets/leases":                 projections.CredentialActionLeaseRequest,
		"GET /v1/{mount}/creds/{role}":                projections.CredentialActionLeaseRequest,
		"GET /api/v1/secrets/store/{name...}":         projections.CredentialActionSecretRead,
		"GET /api/v1/secrets/store/history/{name...}": projections.CredentialActionSecretRead,
		"GET /v1/{mount}/data/{name...}":              projections.CredentialActionSecretRead,
		"GET /api/v1/certificates":                    projections.CredentialActionAPICall,
		"POST /v1/{mount}/data/{name...}":             projections.CredentialActionAPICall,
	} {
		method, _, _ := cutPattern(pattern)
		r := httptest.NewRequest(method, "/", nil)
		r.Pattern = pattern
		if got := credentialUseAction(r); got != want {
			t.Errorf("credentialUseAction(%q) = %q, want %q", pattern, got, want)
		}
	}
}

func cutPattern(pattern string) (string, string, bool) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[:i], pattern[i+1:], true
		}
	}
	return http.MethodGet, pattern, false
}

// M1: "unused" needs complete telemetry: before the first recorded use in the
// tenant nothing is unused, an expired token is not idle, and a recorded gap
// in the window suspends the verdict with the gap as its evidence.
func TestNHIUsageUnusedNeedsCompleteTelemetryM1(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	created := now.AddDate(0, 0, -45)
	item := nhiInventoryItem{Source: "access_api_token"}
	meta := map[string]any{}
	if unused, ev := nhiUsageUnused(item, meta, created, nil, now, defaultNHIStaleOptions()); unused || !slices.Equal(ev, []string{"usage:not_recorded_yet"}) {
		t.Fatalf("before tracking: %v %v", unused, ev)
	}
	meta["usage_tracked_since"] = now.AddDate(0, 0, -40).Format(time.RFC3339)
	opts := nhiStaleOptions{unusedDays: 30}
	if unused, ev := nhiUsageUnused(item, meta, created, nil, now, opts); !unused || len(ev) != 1 {
		t.Fatalf("40 idle days at 30: %v %v", unused, ev)
	}
	opts.gaps = []store.CredentialUsageGap{{ID: "gap-1", From: now.AddDate(0, 0, -20), To: now.AddDate(0, 0, -19), Dropped: 3}}
	if unused, ev := nhiUsageUnused(item, meta, created, nil, now, opts); unused || !slices.Equal(ev, []string{"usage:gap:gap-1"}) {
		t.Fatalf("with a gap: %v %v", unused, ev)
	}
	meta["expires_at"] = now.Add(-time.Hour).Format(time.RFC3339)
	if unused, _ := nhiUsageUnused(item, meta, created, nil, now, nhiStaleOptions{unusedDays: 30}); unused {
		t.Fatal("an expired token was called idle")
	}
}
