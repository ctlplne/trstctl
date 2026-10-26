// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"sync"
	"time"
)

// workQueue hands object keys to the controller's worker the way a client-go
// work queue does: a key queued twice before it is processed is processed once,
// a key re-queued while it is being processed is processed again afterwards
// (never concurrently), and a failed key is retried with per-key exponential
// backoff. It is bounded by the number of distinct keys, not by event volume.
type workQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	queue      []string
	queued     map[string]bool
	processing map[string]bool
	// dirty marks a key re-added while processing; done re-queues it.
	dirty    map[string]bool
	failures map[string]int
	timers   map[string]*time.Timer
	shutdown bool

	baseDelay, maxDelay time.Duration
}

func newWorkQueue(baseDelay, maxDelay time.Duration) *workQueue {
	q := &workQueue{
		queued: map[string]bool{}, processing: map[string]bool{}, dirty: map[string]bool{},
		failures: map[string]int{}, timers: map[string]*time.Timer{},
		baseDelay: baseDelay, maxDelay: maxDelay,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// add queues key now.
func (q *workQueue) add(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.addLocked(key)
}

func (q *workQueue) addLocked(key string) {
	if q.shutdown {
		return
	}
	if q.processing[key] {
		q.dirty[key] = true
		return
	}
	if q.queued[key] {
		return
	}
	q.queued[key] = true
	q.queue = append(q.queue, key)
	q.cond.Signal()
}

// addAfter queues key once delay has passed. A later addAfter for the same
// key replaces the earlier one, so a rescheduled renewal does not fire twice.
func (q *workQueue) addAfter(key string, delay time.Duration) {
	if delay <= 0 {
		q.add(key)
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.shutdown {
		return
	}
	if timer := q.timers[key]; timer != nil {
		timer.Stop()
	}
	q.timers[key] = time.AfterFunc(delay, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		delete(q.timers, key)
		q.addLocked(key)
	})
}

// retry re-queues a failed key after its backoff: baseDelay doubled per
// consecutive failure, capped at maxDelay.
func (q *workQueue) retry(key string) time.Duration {
	q.mu.Lock()
	failures := q.failures[key]
	q.failures[key] = failures + 1
	q.mu.Unlock()
	delay := q.baseDelay
	for i := 0; i < failures && delay < q.maxDelay; i++ {
		delay *= 2
	}
	delay = min(delay, q.maxDelay)
	q.addAfter(key, delay)
	return delay
}

// forget clears a key's failure count after it succeeds.
func (q *workQueue) forget(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.failures, key)
}

// get blocks for the next key; ok is false once the queue is shut down.
func (q *workQueue) get() (key string, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.queue) == 0 && !q.shutdown {
		q.cond.Wait()
	}
	if q.shutdown {
		return "", false
	}
	key, q.queue = q.queue[0], q.queue[1:]
	delete(q.queued, key)
	q.processing[key] = true
	return key, true
}

// done ends processing of key, re-queuing it when it changed meanwhile.
func (q *workQueue) done(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.processing, key)
	if q.dirty[key] {
		delete(q.dirty, key)
		q.addLocked(key)
	}
}

// idle reports whether nothing is queued or being processed. Scheduled
// (delayed) keys do not count: they are future work.
func (q *workQueue) idle() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue) == 0 && len(q.processing) == 0
}

// shutDown wakes every waiter and drops scheduled keys.
func (q *workQueue) shutDown() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.shutdown = true
	for key, timer := range q.timers {
		timer.Stop()
		delete(q.timers, key)
	}
	q.cond.Broadcast()
}
