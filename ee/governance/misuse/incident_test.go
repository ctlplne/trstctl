// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/governance/misuse"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// M2-L3: a finding opens an incident for its token; a token has one open
// incident and its later findings attach to it, whether or not they alert;
// an operator closes it with a resolution (once); a finding after the close
// opens a new one; and the incidents rebuild from the event log.
func TestMisuseFindingOpensAnIncidentM2L3(t *testing.T) {
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "responder"})
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f := &usageFixture{t: t, ctx: ctx, st: st, log: log, proj: projections.New(st)}
	reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: misuseTenant, Data: []byte(`{"name":"misuse tenant"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.proj.Apply(ctx, reg); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hour := now.Truncate(time.Hour)
	day := func(n int) time.Time { return hour.AddDate(0, 0, -n) }
	for _, token := range []string{"deployer", "reader"} {
		for n := 6; n >= 2; n-- {
			f.use(token, "127.0.0.0/24", projections.CredentialActionAPICall, day(n), 1)
			f.use(token, "127.0.0.0/24", projections.CredentialActionSecretRead, day(n), 2)
		}
	}
	f.use("deployer", "10.20.30.0/24", projections.CredentialActionLeaseRequest, hour, 1)
	f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, hour, 64)
	clock := now
	detector, findingsProj := misuse.NewDetector(misuse.Options{Store: st, Log: log, Now: func() time.Time { return clock }})
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	incidents := misuse.IncidentStore{Store: st, Log: log}
	summary := func(status string) []string {
		t.Helper()
		list, err := incidents.List(ctx, misuseTenant, status, 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, in := range list {
			out = append(out, in.CredentialID+"|"+in.Status+"|"+itoa(in.Findings)+"|"+in.Resolution+"|"+in.ClosedBy)
		}
		return out
	}
	if got, want := summary("open"), []string{"deployer|open|1||", "reader|open|1||"}; !sameSet(got, want) {
		t.Fatalf("after the first findings: %v, want %v", got, want)
	}

	// The reader also leases from a new network: a second finding attaches to
	// its open incident rather than opening another.
	f.use("reader", "10.99.0.0/24", projections.CredentialActionLeaseRequest, hour, 1)
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := summary(""), []string{"deployer|open|1||", "reader|open|2||"}; !sameSet(got, want) {
		t.Fatalf("a second finding for the reader: %v, want %v", got, want)
	}

	list, err := incidents.List(ctx, misuseTenant, "open", 50)
	if err != nil {
		t.Fatal(err)
	}
	var readerIncident string
	for _, in := range list {
		if in.CredentialID == "reader" {
			readerIncident = in.ID
		}
	}
	closed, err := incidents.Close(ctx, misuseTenant, readerIncident, misuse.ResolutionTokenRevoked, "revoked after review")
	if err != nil || closed.Status != "closed" || closed.ClosedBy != "responder" || closed.Note != "revoked after review" || closed.ClosedAt == nil {
		t.Fatalf("close = %+v, %v", closed, err)
	}
	if _, err := incidents.Close(ctx, misuseTenant, readerIncident, misuse.ResolutionOther, ""); !errors.Is(err, misuse.ErrIncidentNotOpen) {
		t.Fatalf("a second close = %v, want not open", err)
	}
	if _, err := incidents.Close(ctx, misuseTenant, "no-such-incident", misuse.ResolutionOther, ""); !errors.Is(err, misuse.ErrIncidentNotFound) {
		t.Fatalf("closing a missing incident = %v", err)
	}
	if _, err := incidents.Close(ctx, misuseTenant, readerIncident, "shrug", ""); err == nil {
		t.Fatal("an unknown resolution was accepted")
	}

	// The next day the reader bursts again: a new incident opens.
	clock = now.Add(24 * time.Hour)
	f.use("reader", "127.0.0.0/24", projections.CredentialActionSecretRead, hour.Add(24*time.Hour), 512) // four times yesterday's 64
	if err := detector.DetectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := summary(""), []string{"deployer|open|1||", "reader|open|1||", "reader|closed|2|token_revoked|responder"}; !sameSet(got, want) {
		t.Fatalf("after the close and a new burst: %v, want %v", got, want)
	}

	// Rebuild from the log.
	before := summary("")
	if err := findingsProj.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if err := log.Replay(ctx, 1, func(ev events.Event) error { return findingsProj.Apply(ctx, ev) }); err != nil {
		t.Fatal(err)
	}
	if after := summary(""); !reflect.DeepEqual(before, after) {
		t.Fatalf("rebuild changed the incidents:\nbefore %v\nafter  %v", before, after)
	}
	t.Logf("M2L3_INCIDENTS_OK %v", before)
}

func itoa(n int) string { return strconv.Itoa(n) }

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
