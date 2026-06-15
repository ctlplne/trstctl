package leader_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trustctl.io/trustctl/internal/leader"
	"trustctl.io/trustctl/internal/store"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL for the leader-election integration
// tests (RESIL-004): leadership is a real PostgreSQL session advisory lock, so it is
// exercised against a real database, never mocked.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trustctl-pg-leader")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin"). // per-package, not a shared /tmp dir: parallel `go test ./...` packages race the file-by-file extraction into a shared BinariesPath
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestLeaderLockIsMutuallyExclusiveAndFailsOver pins the core RESIL-004 primitive:
// against one database, exactly ONE replica can hold leadership at a time, and when
// the leader releases (or its process dies, freeing the session lock) a follower can
// acquire it (failover). Two stores open SEPARATE connection pools, modeling two
// replicas; both compete for the same advisory lock.
func TestLeaderLockIsMutuallyExclusiveAndFailsOver(t *testing.T) {
	ctx := context.Background()
	a := openStore(t)
	b := openStore(t)

	// Replica A becomes leader.
	leaseA, err := a.TryBecomeLeader(ctx)
	if err != nil {
		t.Fatalf("A TryBecomeLeader: %v", err)
	}
	if leaseA == nil {
		t.Fatal("A got a nil lease despite no error")
	}

	// Replica B must NOT be able to become leader while A holds it.
	leaseB, err := b.TryBecomeLeader(ctx)
	if !errors.Is(err, store.ErrNotLeader) {
		if leaseB != nil {
			leaseB.Release()
		}
		t.Fatalf("B TryBecomeLeader while A leads = %v, want ErrNotLeader (two leaders at once breaks RESIL-004)", err)
	}

	// A is healthy while it holds the lease.
	if !leaseA.Healthy(ctx) {
		t.Fatal("A lease reports unhealthy while held")
	}

	// A steps down; now B can take over (failover).
	leaseA.Release()
	// The advisory lock release may be processed slightly asynchronously by the server;
	// retry briefly so the test is not flaky.
	leaseB, err = tryBecomeLeaderEventually(ctx, b, 2*time.Second)
	if err != nil {
		t.Fatalf("B TryBecomeLeader after A released = %v, want success (failover, RESIL-004)", err)
	}
	defer leaseB.Release()

	// And now A cannot reacquire while B holds it.
	if _, err := a.TryBecomeLeader(ctx); !errors.Is(err, store.ErrNotLeader) {
		t.Fatalf("A TryBecomeLeader while B leads = %v, want ErrNotLeader", err)
	}
}

// tryBecomeLeaderEventually retries TryBecomeLeader until it succeeds or the deadline
// passes, absorbing the brief window after another session releases the lock.
func tryBecomeLeaderEventually(ctx context.Context, s *store.Store, within time.Duration) (*store.LeaderLease, error) {
	deadline := time.Now().Add(within)
	for {
		lease, err := s.TryBecomeLeader(ctx)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, store.ErrNotLeader) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestElectorRunsLeaderWorkOnExactlyOneReplica is the EXC-RESIL-01 "no double-apply"
// proof at the election layer: two Electors campaign against one database, each with a
// leader function that marks itself ACTIVE and runs until its context is cancelled.
// The test asserts that NEVER are both leader functions active at once (a shared
// active-count that would exceed 1 if two leaders ran), and that on killing the
// current leader, the OTHER elector takes over (failover) and runs its leader work.
// This is the guarantee every continuous background worker relies on: the dispatcher,
// the GC sweeps, the CRL scheduler, the snapshot worker, and the projector tailer all
// run inside this leader function, so proving exactly-one-leader proves none of them
// double-applies (RESIL-004).
func TestElectorRunsLeaderWorkOnExactlyOneReplica(t *testing.T) {
	a := openStore(t)
	b := openStore(t)

	var active int32           // how many leader functions are currently running (must never exceed 1)
	var maxActive int32        // the observed peak — asserted == 1
	var ranA, ranB atomic.Bool // which electors ever became leader (both, after failover)

	// makeLeaderFn returns a leader function that records concurrency and which replica
	// ran, then blocks until its leadership context is cancelled.
	makeLeaderFn := func(ran *atomic.Bool) func(context.Context) {
		return func(ctx context.Context) {
			ran.Store(true)
			now := atomic.AddInt32(&active, 1)
			for { // track the peak concurrency
				p := atomic.LoadInt32(&maxActive)
				if now <= p || atomic.CompareAndSwapInt32(&maxActive, p, now) {
					break
				}
			}
			defer atomic.AddInt32(&active, -1)
			<-ctx.Done()
		}
	}

	// Fast campaign interval so failover happens within the test.
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	eA := leader.New(a, makeLeaderFn(&ranA), leader.WithInterval(50*time.Millisecond))
	eB := leader.New(b, makeLeaderFn(&ranB), leader.WithInterval(50*time.Millisecond))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); eA.Run(ctxA) }()
	go func() { defer wg.Done(); eB.Run(ctxB) }()

	// Let one of them win and run for a while.
	if !waitFor(func() bool { return ranA.Load() || ranB.Load() }, 3*time.Second) {
		cancelA()
		cancelB()
		wg.Wait()
		t.Fatal("neither elector became leader within 3s")
	}
	time.Sleep(300 * time.Millisecond) // let the leader run; the follower must stay idle

	// Exactly one leader so far.
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		cancelA()
		cancelB()
		wg.Wait()
		t.Fatalf("peak concurrent leaders = %d, want 1 (two leaders ran at once — double-apply hazard, RESIL-004)", got)
	}

	// Determine the current leader and KILL it, forcing failover to the other.
	leaderIsA := ranA.Load() && !ranB.Load()
	if leaderIsA {
		cancelA()
	} else {
		cancelB()
	}

	// The OTHER replica must take over (failover) and run its leader work.
	otherRan := func() bool {
		if leaderIsA {
			return ranB.Load()
		}
		return ranA.Load()
	}
	if !waitFor(otherRan, 3*time.Second) {
		cancelA()
		cancelB()
		wg.Wait()
		t.Fatal("the surviving replica did not take over leadership after the leader was killed (failover failed, RESIL-004)")
	}

	// Still never two at once, across the failover.
	if got := atomic.LoadInt32(&maxActive); got != 1 {
		cancelA()
		cancelB()
		wg.Wait()
		t.Fatalf("peak concurrent leaders across failover = %d, want 1 (RESIL-004)", got)
	}

	cancelA()
	cancelB()
	wg.Wait()
	// After both stop, nothing is active.
	if got := atomic.LoadInt32(&active); got != 0 {
		t.Fatalf("active leaders after shutdown = %d, want 0", got)
	}
}

func waitFor(cond func() bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
