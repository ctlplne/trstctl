package app_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/bulkhead"
)

// TestServiceSubsystemPoolsWired checks the AN-7 wiring: the Service provisions a
// bounded, isolated pool per subsystem. Submit runs work on a subsystem's pool;
// an unknown subsystem is rejected with a structured error; Close is safe. The
// pools need no database, so a bare Service suffices.
func TestServiceSubsystemPoolsWired(t *testing.T) {
	svc := app.New(nil, nil)
	defer svc.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	if err := svc.Submit(bulkhead.SubsystemProjections, func() { wg.Done() }); err != nil {
		t.Fatalf("submit to projections pool: %v", err)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("submitted task did not run on the subsystem pool")
	}

	if err := svc.Submit("not-a-subsystem", func() {}); !errors.Is(err, bulkhead.ErrRejected) {
		t.Errorf("submit to unknown subsystem = %v, want ErrRejected", err)
	}
}

func TestServiceCloseIsIdempotent(t *testing.T) {
	svc := app.New(nil, nil)
	svc.Close()
	svc.Close() // must not panic
}
