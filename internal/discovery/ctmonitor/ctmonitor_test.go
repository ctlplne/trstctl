// SPDX-License-Identifier: BUSL-1.1

package ctmonitor_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
)

// fakeFetcher serves a fixed in-memory tree of entries.
type fakeFetcher struct {
	tree []ctlog.Entry
}

func (f *fakeFetcher) TreeSize(_ context.Context, _ string) (int64, error) {
	return int64(len(f.tree)), nil
}

func (f *fakeFetcher) Entries(_ context.Context, _ string, start, end int64) ([]ctlog.Entry, error) {
	if start < 0 || end > int64(len(f.tree)) || start > end {
		return nil, nil
	}
	out := make([]ctlog.Entry, 0, end-start)
	for i := start; i < end; i++ {
		e := f.tree[i]
		e.Index = i
		out = append(out, e)
	}
	return out, nil
}

func entry(dnsNames ...string) ctlog.Entry {
	return ctlog.Entry{
		Subject:           "CN=" + dnsNames[0],
		Issuer:            "CN=Some CA",
		SerialHex:         "0a0b0c",
		FingerprintSHA256: "fp-" + dnsNames[0],
		DNSNames:          dnsNames,
		NotAfter:          time.Now().Add(24 * time.Hour),
	}
}

const tenant = "11111111-1111-1111-1111-111111111111"

func newMonitor(t *testing.T, f ctmonitor.Fetcher, known bool, domains ...string) (*ctmonitor.Monitor, *ctmonitor.MemoryAlerter) {
	t.Helper()
	alerter := ctmonitor.NewMemoryAlerter()
	kg := ctmonitor.KnownGoodFunc(func(_ context.Context, _ string, _ ctlog.Entry) (bool, error) { return known, nil })
	m := ctmonitor.New(f, kg, alerter, ctmonitor.Config{WatchedDomains: domains})
	return m, alerter
}

func TestPollAlertsOnUnexpectedIssuance(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{entry("shadow.example.com")}}
	m, alerter := newMonitor(t, f, false, "example.com")

	state, findings, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(findings) != 1 || len(alerter.Raised()) != 1 {
		t.Fatalf("findings=%d raised=%d, want 1/1", len(findings), len(alerter.Raised()))
	}
	got := alerter.Raised()[0]
	if got.MatchedDomain != "example.com" || got.LogURL != "log-a" {
		t.Errorf("finding = %+v", got)
	}
	if got.Subject == "" || got.Fingerprint == "" {
		t.Errorf("finding missing cert metadata: %+v", got)
	}
	if state.Checkpoint != 1 {
		t.Errorf("checkpoint = %d, want 1", state.Checkpoint)
	}
}

func TestPollSuppressesKnownGood(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{entry("svc.example.com")}}
	m, alerter := newMonitor(t, f, true, "example.com") // known-good

	_, findings, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(findings) != 0 || len(alerter.Raised()) != 0 {
		t.Errorf("known-good issuance must not alert: findings=%d raised=%d", len(findings), len(alerter.Raised()))
	}
}

func TestPollIgnoresUnwatchedDomain(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{entry("api.other-org.net")}}
	m, alerter := newMonitor(t, f, false, "example.com")

	_, findings, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(findings) != 0 || len(alerter.Raised()) != 0 {
		t.Errorf("unwatched domain must not alert: findings=%d", len(findings))
	}
}

func TestPollIsIncremental(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{
		entry("a.example.com"), entry("b.example.com"), entry("c.example.com"),
	}}
	m, alerter := newMonitor(t, f, false, "example.com")
	ctx := context.Background()

	state, findings, err := m.Poll(ctx, tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 || state.Checkpoint != 3 {
		t.Fatalf("first poll: findings=%d checkpoint=%d, want 3/3", len(findings), state.Checkpoint)
	}
	// Re-polling from the advanced checkpoint sees nothing new and does not
	// re-alert on already-seen entries.
	state2, findings2, err := m.Poll(ctx, tenant, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings2) != 0 || state2.Checkpoint != 3 {
		t.Errorf("second poll: findings=%d checkpoint=%d, want 0/3", len(findings2), state2.Checkpoint)
	}
	if len(alerter.Raised()) != 3 {
		t.Errorf("total raised = %d, want 3 (no double-alerting)", len(alerter.Raised()))
	}
}

func TestPollRespectsMaxBatch(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{
		entry("a.example.com"), entry("b.example.com"), entry("c.example.com"),
	}}
	alerter := ctmonitor.NewMemoryAlerter()
	kg := ctmonitor.KnownGoodFunc(func(_ context.Context, _ string, _ ctlog.Entry) (bool, error) { return false, nil })
	m := ctmonitor.New(f, kg, alerter, ctmonitor.Config{WatchedDomains: []string{"example.com"}, MaxBatch: 2})

	state, findings, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"})
	if err != nil {
		t.Fatal(err)
	}
	if state.Checkpoint != 2 || len(findings) != 2 {
		t.Errorf("batched poll: checkpoint=%d findings=%d, want 2/2", state.Checkpoint, len(findings))
	}
}

func TestPollAllAggregatesAcrossLogs(t *testing.T) {
	f := &fakeFetcher{tree: []ctlog.Entry{entry("x.example.com")}}
	m, alerter := newMonitor(t, f, false, "example.com")

	logs := []ctmonitor.LogState{{URL: "log-a"}, {URL: "log-b"}}
	states, findings, err := m.PollAll(context.Background(), tenant, logs)
	if err != nil {
		t.Fatalf("PollAll: %v", err)
	}
	if len(findings) != 2 || len(alerter.Raised()) != 2 {
		t.Errorf("PollAll across 2 logs: findings=%d raised=%d, want 2/2", len(findings), len(alerter.Raised()))
	}
	for _, s := range states {
		if s.Checkpoint != 1 {
			t.Errorf("log %s checkpoint = %d, want 1", s.URL, s.Checkpoint)
		}
	}
}

func TestDomainMatch(t *testing.T) {
	cases := []struct {
		name, watched string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true}, // subdomain
		{"*.example.com", "example.com", true},   // wildcard
		{"deep.svc.example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},           // case-insensitive
		{"example.com.evil.net", "example.com", false}, // suffix trick
		{"notexample.com", "example.com", false},
		{"example.org", "example.com", false},
	}
	for _, c := range cases {
		if got := ctmonitor.DomainMatch(c.name, c.watched); got != c.want {
			t.Errorf("DomainMatch(%q, %q) = %v, want %v", c.name, c.watched, got, c.want)
		}
	}
}

// ipEntry is a logged certificate whose only names are IP addresses.
func ipEntry(ips ...string) ctlog.Entry {
	return ctlog.Entry{
		Subject: "CN=" + ips[0], Issuer: "CN=Some CA", SerialHex: "0d0e0f", FingerprintSHA256: "fp-" + ips[0],
		IPAddresses: ips, NotAfter: time.Now().Add(24 * time.Hour),
	}
}

// TestPollWatchesIPAddressNamesN10L2 is N10-L2: a watched IP address or CIDR
// range catches a logged certificate for an IP in it, by the certificate's IP
// address names; one outside every watched range, and a DNS name that only
// spells an address, are not caught.
func TestPollWatchesIPAddressNamesN10L2(t *testing.T) {
	spelled := entry("203.0.113.9")
	spelled.FingerprintSHA256 = "fp-spelled"
	f := &fakeFetcher{tree: []ctlog.Entry{
		ipEntry("203.0.113.9"),
		ipEntry("198.51.100.8"),
		ipEntry("198.51.100.7"),
		ipEntry("2001:db8:5::1"),
		spelled,
	}}
	m, alerter := newMonitor(t, f, false, "example.com", "203.0.113.0/24", "198.51.100.7", "2001:db8::/32")
	if _, _, err := m.Poll(context.Background(), tenant, ctmonitor.LogState{URL: "log-a"}); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	got := map[string]string{}
	for _, f := range alerter.Raised() {
		if len(f.IPAddresses) == 0 {
			t.Fatalf("a hit by DNS name: %+v", f)
		}
		got[f.IPAddresses[0]] = f.MatchedDomain
	}
	want := map[string]string{"203.0.113.9": "203.0.113.0/24", "198.51.100.7": "198.51.100.7", "2001:db8:5::1": "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("hits = %v; want %v", got, want)
	}
	for ip, watched := range want {
		if got[ip] != watched {
			t.Fatalf("hit %s matched %q; want %q (all: %v)", ip, got[ip], watched, got)
		}
	}
}
