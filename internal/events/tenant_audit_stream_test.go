// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenancy"
)

// A94: a tenant audit stream holds exactly the tenant's own lane, sourced from
// the live events stream, under its own name; a neighbour's events never enter
// it, deleting it leaves the source of truth intact, and an absent stream is
// reported as absent rather than as empty.
func TestTenantAuditStreamSourcesOnlyTheTenantLaneA94(t *testing.T) {
	tenancy.SetRouter(nil)
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendAs := func(lane string, n int) {
		t.Helper()
		tenancy.SetRouter(replayLaneRouter{lane: lane})
		for i := 0; i < n; i++ {
			if _, err := log.Append(t.Context(), events.Event{Type: "audit.probe", TenantID: "tenant-" + lane, Data: []byte(`{}`)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	appendAs("lane-a", 3)
	appendAs("lane-b", 2)
	tenancy.SetRouter(nil)

	if absent, err := log.TenantAuditStreamInfo(t.Context(), "lane-a"); err != nil || absent.Exists {
		t.Fatalf("audit stream before ensure = %+v %v, want absent", absent, err)
	}
	created, err := log.EnsureTenantAuditStream(t.Context(), "lane-a")
	if err != nil || !created.Exists || created.SourceStream == "" || created.Name == "" {
		t.Fatalf("ensure = %+v %v", created, err)
	}
	// Sourcing is asynchronous; the mirror catches up within moments.
	deadline := time.Now().Add(10 * time.Second)
	var info events.TenantAuditStream
	for {
		info, err = log.TenantAuditStreamInfo(t.Context(), "lane-a")
		if err != nil {
			t.Fatal(err)
		}
		if info.Messages >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if info.Messages != 3 {
		t.Fatalf("lane-a audit stream holds %d messages, want exactly the lane's 3 (lane-b's 2 must not enter it)", info.Messages)
	}
	// A later append on the lane is sourced too; a neighbour's is not.
	appendAs("lane-a", 1)
	appendAs("lane-b", 1)
	tenancy.SetRouter(nil)
	deadline = time.Now().Add(10 * time.Second)
	for {
		info, _ = log.TenantAuditStreamInfo(t.Context(), "lane-a")
		if info.Messages >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	info, _ = log.TenantAuditStreamInfo(t.Context(), "lane-a")
	if info.Messages != 4 {
		t.Fatalf("lane-a audit stream holds %d after further appends, want 4", info.Messages)
	}
	// Ensure is idempotent and keeps the messages.
	if again, err := log.EnsureTenantAuditStream(t.Context(), "lane-a"); err != nil || again.Name != created.Name || again.Messages != 4 {
		t.Fatalf("second ensure = %+v %v, want the same stream with its messages", again, err)
	}
	if err := log.DeleteTenantAuditStream(t.Context(), "lane-a"); err != nil {
		t.Fatal(err)
	}
	if gone, err := log.TenantAuditStreamInfo(t.Context(), "lane-a"); err != nil || gone.Exists {
		t.Fatalf("after delete = %+v %v, want absent", gone, err)
	}
	if err := log.DeleteTenantAuditStream(t.Context(), "lane-a"); err != nil {
		t.Fatalf("deleting an absent audit stream = %v, want nil", err)
	}
	// The source of truth kept every event.
	if n, err := log.LaneSubjectCount(t.Context(), "lane-a"); err != nil || n != 4 {
		t.Fatalf("lane-a source count after delete = %d %v, want 4", n, err)
	}
	if _, err := log.EnsureTenantAuditStream(t.Context(), "bad.lane"); err == nil {
		t.Fatal("a multi-token lane was accepted as an audit stream lane")
	}
}
