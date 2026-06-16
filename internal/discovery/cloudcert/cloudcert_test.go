package cloudcert_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

// fakeProvider enumerates a fixed set of certificates, optionally with a delay
// (to observe concurrency) or an error.
type fakeProvider struct {
	name    string
	found   []cloudcert.Found
	err     error
	delay   time.Duration
	current *atomic.Int32
	peak    *atomic.Int32
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) Enumerate(ctx context.Context) ([]cloudcert.Found, error) {
	if p.current != nil {
		c := p.current.Add(1)
		for {
			pk := p.peak.Load()
			if c <= pk || p.peak.CompareAndSwap(pk, c) {
				break
			}
		}
		defer p.current.Add(-1)
	}
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if p.err != nil {
		return nil, p.err
	}
	return p.found, nil
}

func found(provider, id, fp string) cloudcert.Found {
	return cloudcert.Found{
		Provider: provider, ResourceID: id, Location: "loc",
		Cert: certinfo.Info{Subject: "CN=" + id, SHA256Fingerprint: fp, SerialNumber: "01"},
	}
}

func TestDiscoverRecordsAllToSink(t *testing.T) {
	sink := cloudcert.NewMemorySink()
	d := cloudcert.NewDiscoverer(sink)
	defer d.Close()

	providers := []cloudcert.Provider{
		&fakeProvider{name: "aws-acm", found: []cloudcert.Found{found("aws-acm", "a1", "fp1"), found("aws-acm", "a2", "fp2")}},
		&fakeProvider{name: "gcp", found: []cloudcert.Found{found("gcp", "g1", "fp3")}},
	}
	rep := d.Discover(context.Background(), providers)
	if rep.Discovered != 3 || rep.Failed != 0 || rep.Providers != 2 {
		t.Fatalf("report = %+v, want 3 discovered / 0 failed / 2 providers", rep)
	}
	if len(sink.All()) != 3 {
		t.Errorf("sink has %d, want 3", len(sink.All()))
	}
}

func TestDiscoverCountsProviderFailures(t *testing.T) {
	sink := cloudcert.NewMemorySink()
	d := cloudcert.NewDiscoverer(sink)
	defer d.Close()

	providers := []cloudcert.Provider{
		&fakeProvider{name: "ok", found: []cloudcert.Found{found("ok", "c1", "fp1")}},
		&fakeProvider{name: "broken", err: fmt.Errorf("boom")},
	}
	rep := d.Discover(context.Background(), providers)
	if rep.Discovered != 1 || rep.Failed != 1 {
		t.Errorf("report = %+v, want 1 discovered / 1 failed", rep)
	}
	if len(sink.All()) != 1 {
		t.Errorf("a provider error must not lose the others' results: sink=%d", len(sink.All()))
	}
}

func TestDiscoverBoundsConcurrency(t *testing.T) {
	const workers = 3
	var current, peak atomic.Int32
	var providers []cloudcert.Provider
	for i := 0; i < 12; i++ {
		providers = append(providers, &fakeProvider{
			name: fmt.Sprintf("p%d", i), delay: 5 * time.Millisecond,
			current: &current, peak: &peak,
			found: []cloudcert.Found{found("p", fmt.Sprintf("c%d", i), fmt.Sprintf("fp%d", i))},
		})
	}
	d := cloudcert.NewDiscoverer(cloudcert.NewMemorySink(), cloudcert.WithWorkers(workers), cloudcert.WithQueue(100))
	defer d.Close()

	rep := d.Discover(context.Background(), providers)
	if rep.Discovered != 12 {
		t.Errorf("discovered %d, want 12", rep.Discovered)
	}
	if peak.Load() > workers {
		t.Errorf("peak concurrency %d exceeded the %d-worker bound", peak.Load(), workers)
	}
}

// Fetch retries a rate-limited (429) response up to the policy limit, honoring a
// short Retry-After, and returns the eventual body.
func TestFetchRetriesOnRateLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	body, err := cloudcert.Fetch(context.Background(), srv.Client(), req, nil, cloudcert.DefaultRetry())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one 429 + one success)", calls.Load())
	}
}

func TestFetchGivesUpAfterMaxRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := cloudcert.Fetch(context.Background(), srv.Client(), req, nil, cloudcert.RetryPolicy{Max: 2, Base: time.Millisecond}); err == nil {
		t.Error("Fetch should error after exhausting retries on persistent 429")
	}
}
