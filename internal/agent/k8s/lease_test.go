// SPDX-License-Identifier: MPL-2.0

package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// leaseAPI is a minimal coordination.k8s.io stand-in: it stores one lease and
// applies the same compare-and-swap the real API server does, so a stale PUT
// loses with 409 exactly as it would in a cluster.
type leaseAPI struct {
	t       *testing.T
	obj     *leaseObject
	version int
	creates int
	puts    int
}

func (a *leaseAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if a.obj == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","code":404}`))
				return
			}
			_ = json.NewEncoder(w).Encode(a.obj)
		case http.MethodPost:
			a.creates++
			if a.obj != nil {
				w.WriteHeader(http.StatusConflict)
				return
			}
			var in leaseObject
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				a.t.Fatalf("decode create: %v", err)
			}
			a.version++
			in.Metadata["resourceVersion"] = itoaVersion(a.version)
			a.obj = &in
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(a.obj)
		case http.MethodPut:
			a.puts++
			var in leaseObject
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				a.t.Fatalf("decode update: %v", err)
			}
			// Compare-and-swap on resourceVersion, like the API server.
			if got, want := in.Metadata["resourceVersion"], a.obj.Metadata["resourceVersion"]; got != want {
				w.WriteHeader(http.StatusConflict)
				return
			}
			a.version++
			in.Metadata["resourceVersion"] = itoaVersion(a.version)
			a.obj = &in
			_ = json.NewEncoder(w).Encode(a.obj)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func itoaVersion(v int) string { return string(rune('0' + v%10)) }

func newLeaseFixture(t *testing.T) (*leaseAPI, *Client, func()) {
	t.Helper()
	api := &leaseAPI{t: t}
	srv := httptest.NewServer(api.handler())
	client := New(srv.URL, "", "trstctl", srv.Client())
	return api, client, srv.Close
}

// TestLeaseElectsExactlyOneLeader is the property that matters: with two pods
// contending, exactly one reconciles.
func TestLeaseElectsExactlyOneLeader(t *testing.T) {
	api, client, done := newLeaseFixture(t)
	defer done()

	a := NewLease(client, "ctl", "pod-a")
	b := NewLease(client, "ctl", "pod-b")

	leadA, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatalf("pod-a acquire: %v", err)
	}
	leadB, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatalf("pod-b acquire: %v", err)
	}
	if !leadA || leadB {
		t.Fatalf("leadership = a:%v b:%v, want exactly pod-a", leadA, leadB)
	}
	// pod-b saw an existing, fresh lease and never tried to create one.
	if api.creates != 1 {
		t.Fatalf("creates = %d, want 1", api.creates)
	}

	// The holder keeps renewing without handing leadership away.
	for i := 0; i < 3; i++ {
		lead, err := a.Acquire(context.Background())
		if err != nil || !lead {
			t.Fatalf("pod-a renewal %d: lead=%v err=%v", i, lead, err)
		}
		if lead, _ := b.Acquire(context.Background()); lead {
			t.Fatal("pod-b took leadership while pod-a was renewing")
		}
	}
}

// TestLeaseCreateRaceLoserDoesNotLead covers the genuine cold-start race: two
// pods both find no lease and both POST. The API server lets exactly one
// create it; the loser gets 409 and must NOT consider itself leader.
func TestLeaseCreateRaceLoserDoesNotLead(t *testing.T) {
	api, client, done := newLeaseFixture(t)
	defer done()

	// Seed the "both saw 404" state by creating on behalf of pod-a first,
	// then letting pod-b POST into an occupied slot.
	if lead, err := NewLease(client, "ctl", "pod-a").Acquire(context.Background()); err != nil || !lead {
		t.Fatalf("pod-a acquire: lead=%v err=%v", lead, err)
	}
	loser := NewLease(client, "ctl", "pod-b")
	st, _, err := client.request(context.Background(), http.MethodPost, loser.path(), leaseObject{
		APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Metadata: map[string]any{"name": "ctl"},
		Spec:     leaseSpec{HolderIdentity: "pod-b", LeaseDurationSeconds: 30},
	})
	if err != nil {
		t.Fatalf("racing create: %v", err)
	}
	if st != http.StatusConflict {
		t.Fatalf("racing create status = %d, want 409", st)
	}
	if api.obj.Spec.HolderIdentity != "pod-a" {
		t.Fatalf("holder = %q, want pod-a to survive the race", api.obj.Spec.HolderIdentity)
	}
}

// TestLeaseTakeoverAfterExpiry proves a dead holder does not wedge the
// controller: once the renewal window lapses, a follower takes over.
func TestLeaseTakeoverAfterExpiry(t *testing.T) {
	_, client, done := newLeaseFixture(t)
	defer done()

	base := time.Now()
	a := NewLease(client, "ctl", "pod-a")
	a.now = func() time.Time { return base }
	if lead, err := a.Acquire(context.Background()); err != nil || !lead {
		t.Fatalf("pod-a initial acquire: lead=%v err=%v", lead, err)
	}

	b := NewLease(client, "ctl", "pod-b")
	// Still inside the lease window: pod-b must wait.
	b.now = func() time.Time { return base.Add(LeaseDuration / 2) }
	if lead, err := b.Acquire(context.Background()); err != nil || lead {
		t.Fatalf("pod-b took over inside the lease window: lead=%v err=%v", lead, err)
	}
	// Window lapsed (pod-a died): pod-b takes over.
	b.now = func() time.Time { return base.Add(LeaseDuration + time.Second) }
	if lead, err := b.Acquire(context.Background()); err != nil || !lead {
		t.Fatalf("pod-b did not take over an expired lease: lead=%v err=%v", lead, err)
	}
}
