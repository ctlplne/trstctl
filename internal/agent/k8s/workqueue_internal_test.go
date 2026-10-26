// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"
)

// A key queued twice before it is processed is processed once; a key re-added
// while it is processed is processed again afterwards, never concurrently.
func TestWorkQueueDeduplicatesAndRequeuesKeysChangedDuringProcessing(t *testing.T) {
	q := newWorkQueue(time.Millisecond, 10*time.Millisecond)
	q.add("a")
	q.add("a")
	q.add("b")
	first, _ := q.get()
	second, _ := q.get()
	if first != "a" || second != "b" || len(q.queue) != 0 {
		t.Fatalf("got %q then %q with %d still queued, want a then b and nothing else", first, second, len(q.queue))
	}
	q.add("a") // changed while "a" is being processed
	if len(q.queue) != 0 {
		t.Fatal("a key being processed was queued for a second, concurrent worker")
	}
	q.done("a")
	q.done("b")
	again, ok := q.get()
	if !ok || again != "a" {
		t.Fatalf("after done, got %q (%v), want the key that changed during processing", again, ok)
	}
	q.done("a")
	if !q.idle() {
		t.Fatal("queue not idle after every key was processed")
	}
}

// A failing key backs off exponentially up to the cap; forget resets it; a
// later addAfter for the same key replaces the earlier one; shutDown releases
// a blocked worker.
func TestWorkQueueBacksOffRetriesAndReplacesScheduledKeys(t *testing.T) {
	q := newWorkQueue(10*time.Millisecond, 40*time.Millisecond)
	var delays []time.Duration
	for range 4 {
		delays = append(delays, q.retry("k"))
	}
	if delays[0] != 10*time.Millisecond || delays[1] != 20*time.Millisecond || delays[2] != 40*time.Millisecond || delays[3] != 40*time.Millisecond {
		t.Fatalf("retry delays = %v, want doubling from 10ms capped at 40ms", delays)
	}
	q.forget("k")
	if delay := q.retry("k"); delay != 10*time.Millisecond {
		t.Fatalf("after forget, retry delay = %v, want the base delay", delay)
	}
	key, _ := q.get()
	q.done(key)

	q.addAfter("r", time.Hour)
	q.addAfter("r", 5*time.Millisecond) // a rescheduled renewal replaces the first
	got := make(chan string, 1)
	go func() {
		key, _ := q.get()
		got <- key
	}()
	select {
	case key := <-got:
		if key != "r" {
			t.Fatalf("scheduled key = %q", key)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the rescheduled key never fired")
	}
	q.done("r")

	released := make(chan bool)
	go func() {
		_, ok := q.get()
		released <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	q.shutDown()
	select {
	case ok := <-released:
		if ok {
			t.Fatal("get returned a key after shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutDown did not release a waiting worker")
	}
}

// The informer lists, then follows the watch: every add, change and delete
// reaches onChange with the object, the cache matches the server, and a 410
// Gone relists and reports only what differs. A collection the server does not
// serve reports not installed instead of an error loop.
func TestInformerFollowsListWatchAndRelistsWhenTheVersionExpires(t *testing.T) {
	const resource = "trstctl.com/v1alpha1/trustbundles"
	api := newFakeAPI(resource)
	api.seed(resource, map[string]any{"metadata": map[string]any{"name": "existing"}})
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	client := New(srv.URL, "tok", "apps", srv.Client())

	var mu sync.Mutex
	var seen []string
	inf := newInformer(client, "/apis/trstctl.com/v1alpha1/trustbundles", "", func(key string, obj map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, key+":"+objectResourceVersion(obj))
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		inf.run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	eventually(t, "the informer lists", func() bool {
		synced, installed, _ := inf.state()
		return synced && installed && len(inf.keys()) == 1
	})

	api.seed(resource, map[string]any{"metadata": map[string]any{"name": "added"}})
	api.mutate(resource, "", "existing", func(obj map[string]any) { obj["spec"] = map[string]any{"changed": true} })
	api.remove(resource, "", "added")
	eventually(t, "the informer follows add, change and delete", func() bool {
		obj, ok := inf.get("existing")
		_, stillThere := inf.get("added")
		return ok && obj["spec"] != nil && !stillThere
	})
	mu.Lock()
	events := len(seen)
	mu.Unlock()
	if events != 4 {
		t.Fatalf("onChange saw %v, want the initial list plus add, change and delete", seen)
	}

	// The watch expires while a new object appears: the relist reports it,
	// and nothing that did not change.
	api.expireWatches(resource)
	api.seed(resource, map[string]any{"metadata": map[string]any{"name": "after-expiry"}})
	eventually(t, "the informer relists after 410 Gone", func() bool {
		_, ok := inf.get("after-expiry")
		return ok
	})
	mu.Lock()
	tail := append([]string(nil), seen[events:]...)
	mu.Unlock()
	sort.Strings(tail)
	if len(tail) != 1 || tail[0][:len("after-expiry")] != "after-expiry" {
		t.Fatalf("relist reported %v, want only the object that appeared", tail)
	}

	missing := newInformer(client, "/apis/cert-manager.io/v1/certificaterequests", "", func(string, map[string]any) {})
	missingDone := make(chan struct{})
	go func() {
		defer close(missingDone)
		missing.run(ctx)
	}()
	eventually(t, "an uninstalled resource reports not installed", func() bool {
		synced, installed, _ := missing.state()
		return synced && !installed
	})
	cancel()
	<-missingDone
}

// eventually polls cond until it holds or five seconds pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
