// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
)

// TestServedConcurrentObserversUnderOneNameRegisterOnceLS1L1 (served): eight
// registrations of one observer name at once register it once; the rest are
// refused with 409 before anything is appended, so the log grows by exactly
// one event and a rebuild applies it. The command checks the name under the
// projection lock, so no two registrations pass the check together and leave
// an event failing the (tenant, name) index.
func TestServedConcurrentObserversUnderOneNameRegisterOnceLS1L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	const racers = 8
	// A name of this run's own: the served tenant outlives one run.
	name := "ls1l1-edge-probe-" + uuid.NewString()[:8]
	statuses := make([]int, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses[i], _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/observers", tok,
				fmt.Sprintf("%s-register-%d", name, i), map[string]any{"name": name})
		}()
	}
	close(start)
	wg.Wait()
	created, refused := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("a registration answered %d", status)
		}
	}
	if created != 1 || refused != racers-1 {
		t.Fatalf("eight registrations under one name: %d created, %d refused (%v), want 1 and 7", created, refused, statuses)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before+1 {
		t.Fatalf("the log grew from %d to %d (%v), want exactly one event", before, after, err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	observers, err := h.store.ListExternalObservers(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, o := range observers {
		if o.Name == name {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("after the rebuild %d observers are named %s, want 1", named, name)
	}
	t.Logf("LS1L1_OBSERVERS_OK statuses=%v", statuses)
}
