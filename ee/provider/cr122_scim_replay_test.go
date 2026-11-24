// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
)

// An IdP sends the same DELETE after an operator is reactivated. The second
// offboard must be a new authority decision, even without an explicit key.
func TestCR122SecondHeaderlessDeactivationTakesEffect(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true},
		events.WithDuplicateWindowForTesting(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	var tick atomic.Int64
	clock := func() time.Time {
		return time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC).Add(time.Duration(tick.Add(1)) * time.Second)
	}
	s := newA221SCIM(t, NewPGAccessStore(st), runtime.Mutations, clock)
	userID := s.create("cr122-operator")
	path := "/provider/scim/v2/Users/" + userID
	if rec := s.call(http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("first deactivation: HTTP %d %s", rec.Code, rec.Body.String())
	}
	reactivate := `{"schemas":["` + scim.SchemaUser + `"],"externalId":"cr122-operator","userName":"cr122-operator@example.test","active":true}`
	if rec := s.call(http.MethodPut, path, reactivate); rec.Code != http.StatusOK {
		t.Fatalf("reactivation: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.call(http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("second deactivation: HTTP %d %s", rec.Code, rec.Body.String())
	}
	identity, err := NewPGAccessStore(st).ResolveOperator(ctx, userID)
	if err != nil || identity.Active {
		t.Fatalf("headerless repeated deactivation left operator active: %+v, %v", identity, err)
	}
	// A retry of the most recent DELETE must not append another event.
	countBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if rec := s.call(http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE retry: HTTP %d %s", rec.Code, rec.Body.String())
	}
	countAfter, err := log.LastSequence(ctx)
	if err != nil || countAfter != countBefore {
		t.Fatalf("DELETE retry appended a second event: %d -> %d, %v", countBefore, countAfter, err)
	}
	// Explicit keys remain stable after the broker's duplicate window too.
	withKey := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(reactivate))
		req.Header.Set("Authorization", "Bearer "+s.token)
		req.Header.Set("Idempotency-Key", "cr122-reactivate")
		rec := httptest.NewRecorder()
		s.h.ServeHTTP(rec, req)
		return rec
	}
	if rec := withKey(); rec.Code != http.StatusOK {
		t.Fatalf("explicit-key reactivation: HTTP %d %s", rec.Code, rec.Body.String())
	}
	countBefore, err = log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if rec := withKey(); rec.Code != http.StatusOK {
		t.Fatalf("explicit-key replay after duplicate window: HTTP %d %s", rec.Code, rec.Body.String())
	}
	countAfter, err = log.LastSequence(ctx)
	if err != nil || countAfter != countBefore {
		t.Fatalf("explicit-key replay appended a second event: %d -> %d, %v", countBefore, countAfter, err)
	}
}
