// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestReprotect_CompletionEventOneAcrossWorkersAndColdRestart(t *testing.T) {
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	if port <= 0 || port > math.MaxUint16 {
		t.Fatalf("invalid embedded PostgreSQL port %d", port)
	}
	pgPort := uint32(port) // #nosec G115 -- port was checked against the uint16 maximum above.
	pgDir := filepath.Join(t.TempDir(), "postgres")
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(pgPort).
		RuntimePath(filepath.Join(pgDir, "rt")).DataPath(filepath.Join(pgDir, "data")).
		BinariesPath(filepath.Join(pgDir, "bin")).Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Fatalf("start PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	st, err := corestore.Open(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate PostgreSQL: %v", err)
	}
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	ev := depstate.ReprotectionCompletedV1{
		TenantID: "11111111-1111-4111-8111-111111111111", KeyID: "ca-a", JobID: "job-a",
		Dependent:              depstate.Dependent{Class: depstate.DependentCredential, ID: "leaf-a"},
		SuccessorKeyID:         "ca-b",
		CredentialSupersession: &depstate.CredentialSupersessionV1{OldCredentialID: "leaf-a", NewCredentialID: "leaf-b"},
	}
	first := eventSink{log: log, store: st}
	var group sync.WaitGroup
	errorsSeen := make(chan error, 2)
	recorded := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			newEvent, err := first.AppendReprotectionCompleted(ctx, ev)
			recorded <- newEvent
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(errorsSeen)
	close(recorded)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent exact completion: %v", err)
		}
	}
	created := 0
	for wasCreated := range recorded {
		if wasCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent completion appends = %d, want 1", created)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second := eventSink{log: log, store: st}
	if newEvent, err := second.AppendReprotectionCompleted(ctx, ev); err != nil || newEvent {
		t.Fatalf("cold replay of exact completion: %v", err)
	}
	conflict := ev
	conflict.SuccessorKeyID = "ca-other"
	if _, err := second.AppendReprotectionCompleted(ctx, conflict); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed successor after restart = %v, want ErrCompletionConflict", err)
	}
	count := 0
	if err := log.Replay(ctx, 0, func(item events.Event) error {
		if item.TenantID == ev.TenantID && item.Type == depstate.TypeReprotectionCompleted &&
			strings.Contains(string(item.Data), `"job_id":"job-a"`) {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("durable completion events = %d, want 1", count)
	}
}
