package telemetry_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"certctl.io/certctl/internal/telemetry"
)

// fakeCounter reports fixed credential counts by type.
type fakeCounter struct{ counts map[string]int }

func (f fakeCounter) CredentialCounts(context.Context) (map[string]int, error) {
	return f.counts, nil
}

// recordingPoster captures the payloads it is asked to send instead of touching
// the network.
type recordingPoster struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (p *recordingPoster) post(_ context.Context, _ string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bodies = append(p.bodies, append([]byte(nil), body...))
	return nil
}

func (p *recordingPoster) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.bodies)
}

func (p *recordingPoster) last() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bodies[len(p.bodies)-1]
}

// TestReporterDoesNotSendWhenDisabled is the central acceptance criterion:
// telemetry is off unless explicitly enabled, so a disabled reporter sends
// nothing.
func TestReporterDoesNotSendWhenDisabled(t *testing.T) {
	rp := &recordingPoster{}
	r := &telemetry.Reporter{
		Enabled:    false,
		Endpoint:   "https://telemetry.example.test/v1",
		InstanceID: "anon",
		Version:    "v1",
		Counter:    fakeCounter{map[string]int{"x509_certificate": 5}},
		Post:       rp.post,
	}
	if err := r.ReportOnce(context.Background()); err != nil {
		t.Fatalf("ReportOnce while disabled: %v", err)
	}
	if rp.count() != 0 {
		t.Errorf("telemetry sent %d payloads while disabled; want 0", rp.count())
	}
}

// TestRunIsNoopWhenDisabled: the reporting loop returns immediately and sends
// nothing when telemetry is off.
func TestRunIsNoopWhenDisabled(t *testing.T) {
	rp := &recordingPoster{}
	r := &telemetry.Reporter{Enabled: false, Interval: time.Hour, Counter: fakeCounter{}, Post: rp.post}
	r.Run(context.Background()) // must return without blocking
	if rp.count() != 0 {
		t.Errorf("disabled Run sent %d payloads; want 0", rp.count())
	}
}

// TestReportsCoarsePayloadWhenEnabled: an explicitly enabled reporter sends a
// well-formed, coarse payload with the instance metadata and bucketed counts.
func TestReportsCoarsePayloadWhenEnabled(t *testing.T) {
	rp := &recordingPoster{}
	r := &telemetry.Reporter{
		Enabled:    true,
		Endpoint:   "https://telemetry.example.test/v1",
		InstanceID: "anon-123",
		Version:    "v1.2.3",
		Counter:    fakeCounter{map[string]int{"x509_certificate": 137, "ssh_key": 3}},
		Post:       rp.post,
	}
	if err := r.ReportOnce(context.Background()); err != nil {
		t.Fatalf("ReportOnce: %v", err)
	}
	if rp.count() != 1 {
		t.Fatalf("want exactly one payload, got %d", rp.count())
	}
	var p telemetry.Payload
	if err := json.Unmarshal(rp.last(), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.InstanceID != "anon-123" || p.Version != "v1.2.3" {
		t.Errorf("payload metadata wrong: %+v", p)
	}
	if p.OS != runtime.GOOS || p.Arch != runtime.GOARCH {
		t.Errorf("os/arch = %q/%q, want %q/%q", p.OS, p.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if p.CredentialBuckets["x509_certificate"] != "101-1000" {
		t.Errorf("137 should bucket to 101-1000, got %q", p.CredentialBuckets["x509_certificate"])
	}
	if p.CredentialBuckets["ssh_key"] != "1-10" {
		t.Errorf("3 should bucket to 1-10, got %q", p.CredentialBuckets["ssh_key"])
	}
}

// TestPayloadIsCoarseAndCarriesNoPII encodes "payloads carry no PII or
// credential content": only the allowed non-identifying fields appear, exact
// counts are bucketed (never sent raw), and every bucket is a known coarse
// label.
func TestPayloadIsCoarseAndCarriesNoPII(t *testing.T) {
	rp := &recordingPoster{}
	r := &telemetry.Reporter{
		Enabled:    true,
		Endpoint:   "https://telemetry.example.test/v1",
		InstanceID: "fixed-anon-id",
		Version:    "v9",
		Counter:    fakeCounter{map[string]int{"x509_certificate": 137}},
		Post:       rp.post,
	}
	if err := r.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := rp.last()

	// The exact credential count never leaves the process — only coarse buckets.
	if strings.Contains(string(body), "137") {
		t.Errorf("payload leaked the exact credential count: %s", body)
	}

	// Only the allowed, non-identifying top-level fields appear.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"schema": true, "instance_id": true, "version": true,
		"os": true, "arch": true, "credential_buckets": true,
	}
	for k := range raw {
		if !allowed[k] {
			t.Errorf("unexpected telemetry field %q (possible PII/credential leak)", k)
		}
	}

	// Every reported bucket is a known coarse range, never a raw number.
	var p telemetry.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"0": true, "1-10": true, "11-100": true, "101-1000": true, "1001-10000": true, "10000+": true}
	for typ, b := range p.CredentialBuckets {
		if !known[b] {
			t.Errorf("credential bucket for %q is %q, not a coarse range", typ, b)
		}
	}
}

// TestBucketBoundaries pins the coarse bucketing at its boundaries.
func TestBucketBoundaries(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{-1, "0"}, {0, "0"}, {1, "1-10"}, {10, "1-10"}, {11, "11-100"}, {100, "11-100"},
		{101, "101-1000"}, {1000, "101-1000"}, {1001, "1001-10000"}, {10000, "1001-10000"}, {10001, "10000+"},
	}
	for _, c := range cases {
		if got := telemetry.Bucket(c.n); got != c.want {
			t.Errorf("Bucket(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestInstanceIDStableAndAnonymous: the instance ID is generated once and
// persisted (stable), random (two instances differ), and not derived from the
// host (anonymous).
func TestInstanceIDStableAndAnonymous(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")

	id1, err := telemetry.LoadOrCreateInstanceID(path)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := telemetry.LoadOrCreateInstanceID(path)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Errorf("instance ID is not stable across loads: %q vs %q", id1, id2)
	}
	if len(id1) < 16 {
		t.Errorf("instance ID is too short to be a random identifier: %q", id1)
	}

	other, err := telemetry.LoadOrCreateInstanceID(filepath.Join(dir, "other"))
	if err != nil {
		t.Fatal(err)
	}
	if other == id1 {
		t.Errorf("two fresh instances share an ID %q; it is not random", id1)
	}

	if host, _ := os.Hostname(); host != "" && strings.Contains(id1, host) {
		t.Errorf("instance ID %q contains the hostname; it is not anonymous", id1)
	}
}

// TestRunReportsOnceThenStops: an enabled loop reports immediately and then
// stops cleanly when its context is cancelled.
func TestRunReportsOnceThenStops(t *testing.T) {
	rp := &recordingPoster{}
	r := &telemetry.Reporter{
		Enabled:    true,
		Endpoint:   "https://telemetry.example.test/v1",
		Interval:   time.Hour,
		InstanceID: "anon",
		Version:    "v1",
		Counter:    fakeCounter{map[string]int{}},
		Post:       rp.post,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop within 2s of context cancellation")
	}
	if rp.count() < 1 {
		t.Errorf("an enabled Run should report once on start; sent %d", rp.count())
	}
}
