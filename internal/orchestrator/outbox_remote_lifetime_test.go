// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/store"
)

const remoteLifetimeChildDSN = "TRSTCTL_TEST_REMOTE_LIFETIME_CHILD_DSN"

func TestOutboxRemoteAdmissionUsesOneRequestConnection(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	worker, err := store.Open(t.Context(), testDSN, store.WithPoolSizes(store.PoolSizes{Request: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	ob := orchestrator.NewOutbox(worker, orchestrator.WithTenantServiceCheck(worker.RequireLiveTenantService))
	enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "one-connection.probe", IdempotencyKey: "one-connection", Payload: []byte(`{}`)})
	// Bound the admission operation, not fixture pool construction.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	calls := 0
	claimed, err := ob.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		calls++
		return nil
	}), orchestrator.DestinationScope{IncludePrefixes: []string{"one-connection.probe"}})
	if err != nil || !claimed || calls != 1 {
		t.Fatalf("one request connection must admit and finish delivery: claimed=%v calls=%d error=%v", claimed, calls, err)
	}
}

func TestOutboxRemoteEffectSurvivesWorkerProcessDeath(t *testing.T) {
	if os.Getenv(remoteLifetimeChildDSN) != "" {
		worker, err := store.Open(t.Context(), testDSN+"?application_name=remote-lifetime-killed-worker")
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		// The parent supplies an already connected socket to its exact owned
		// receiver. The child neither resolves a host nor accepts a target URL.
		inherited := os.NewFile(3, "owned-receiver")
		if inherited == nil {
			t.Fatal("worker receiver socket is missing")
		}
		connection, err := net.FileConn(inherited)
		closeErr := inherited.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("inherit receiver socket: %v; close: %v", err, closeErr)
		}
		defer func() { _ = connection.Close() }()
		client := &http.Client{
			Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				return connection, nil
			}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		defer client.CloseIdleConnections()
		_, err = orchestrator.NewOutbox(worker).DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://owned-receiver.invalid/", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Idempotency-Key", m.IdempotencyKey)
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			return nil
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"worker-death.probe"}})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	started, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	done := make(chan error, 1)
	receiptRoot := remoteLifetimeTestRoot(t, t.TempDir())
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "killed-worker" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		close(started)
		select {
		case <-finish:
			done <- receiptRoot.WriteFile("remote-write-after-process-death", []byte("completed after worker death"), 0600)
		case <-ctx.Done():
			done <- ctx.Err()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	defer release()
	id := enqueue(t, s, orchestrator.NewOutbox(s), orchestrator.Entry{TenantID: tenantA, Destination: "worker-death.probe", IdempotencyKey: "killed-worker", Payload: []byte(`{}`)})
	workingDir := copyRemoteLifetimeWorker(t)
	cmd := exec.CommandContext(ctx, "./remote-worker.test", "-test.run=^TestOutboxRemoteEffectSurvivesWorkerProcessDeath$", "-test.timeout=20s")
	cmd.Dir = workingDir
	connection, err := net.DialTCP("tcp", nil, receiver.Listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := connection.File()
	closeErr := connection.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("prepare owned receiver socket: %v; close: %v", err, closeErr)
	}
	defer func() { _ = inherited.Close() }()
	cmd.ExtraFiles = []*os.File{inherited}
	cmd.Env = append(os.Environ(), remoteLifetimeChildDSN+"="+testDSN)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Only the child retains the client end; killing it must close that socket.
	if err := inherited.Close(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-exited
		}
	}()
	select {
	case <-started:
	case err := <-exited:
		joined = true
		t.Fatalf("worker exited before remote admission: %v, %s", err, output.String())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	exitErr := <-exited
	joined = true
	if exitErr == nil {
		t.Fatal("worker ended normally instead of being killed")
	}
	// PostgreSQL can notice the dead socket slightly after the OS reports exit.
	// Prove the session locks are gone before exercising the durable guard.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var sessions int
		if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name='remote-lifetime-killed-worker'`).Scan(&sessions); err != nil {
			t.Fatal(err)
		}
		if sessions == 0 {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var pending int
	if err := s.SystemPool().QueryRow(ctx, `SELECT cardinality(receiver_pending_ids) FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, id).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("dead process lost durable receiver token: count=%d, error=%v", pending, err)
	}
	if err := s.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		_, err := s.OffboardTenant(fenced, tenantA)
		return err
	}); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("dead worker permitted erasure while its receiver remains active: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if data, err := receiptRoot.ReadFile("remote-write-after-process-death"); err != nil || string(data) != "completed after worker death" {
		t.Fatalf("remote action did not finish after process death: %q, %v", data, err)
	}
	if err := s.RequireTenantAgentWorkQuiescent(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("lost completion acknowledgement was treated as terminal proof: %v", err)
	}
	t.Logf("worker %d terminated (%v); all its database sessions ended; remote write completed; unresolved delivery remains protected", cmd.Process.Pid, exitErr)
}

// Losing the dispatcher's database session is not proof that its remote
// receiver stopped. The independent HTTP receiver deliberately finishes after
// that session is gone, just as a CA or ticket system can finish an accepted
// request after the caller disappears.
func TestOutboxRemoteEffectBlocksErasureAfterServiceSessionLoss(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	const application = "outbox-remote-lifetime-fixture"
	worker, err := store.Open(ctx, testDSN+"?application_name="+application)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	started := make(chan struct{})
	finish := make(chan struct{})
	var finishOnce sync.Once
	releaseReceiver := func() { finishOnce.Do(func() { close(finish) }) }
	defer releaseReceiver()
	result := make(chan error, 1)
	receiptRoot := remoteLifetimeTestRoot(t, t.TempDir())
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "remote-lifetime" {
			result <- errors.New("receiver got a different command")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		close(started)
		// This remote operation has already been admitted. Client cancellation
		// does not undo it, so do not couple its lifetime to r.Context().
		select {
		case <-finish:
		case <-ctx.Done():
			result <- ctx.Err()
			return
		}
		err := receiptRoot.WriteFile("receiver-effect", []byte("external action completed\n"), 0600)
		result <- err
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	ob := orchestrator.NewOutbox(worker)
	enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "remote-lifetime.probe", IdempotencyKey: "remote-lifetime", Payload: []byte(`{}`)})
	dispatched := make(chan error, 1)
	go func() {
		_, err := ob.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(callCtx context.Context, m orchestrator.Message) error {
			req, err := http.NewRequestWithContext(callCtx, http.MethodPost, receiver.URL, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Idempotency-Key", m.IdempotencyKey)
			resp, err := receiver.Client().Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("receiver status %d", resp.StatusCode)
			}
			return nil
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"remote-lifetime.probe"}})
		dispatched <- err
	}()
	joined := false
	defer func() {
		releaseReceiver()
		if !joined {
			<-dispatched
		}
	}()
	select {
	case <-started:
	case err := <-dispatched:
		joined = true
		t.Fatalf("dispatch ended before receiver accepted work: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := s.WithTenantServiceBarrier(ctx, tenantA, func(context.Context) error { return nil }); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("live session did not protect the admitted call: %v", err)
	}
	// Select exactly the shared service-lock holder in this test's private PG
	// instance. Do not terminate other worker, fixture or installed-lab sessions.
	var pid int32
	if err := s.SystemPool().QueryRow(ctx, `SELECT a.pid FROM pg_stat_activity a
		WHERE a.application_name=$1 AND EXISTS (
		 SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory'
		 AND l.mode='ShareLock' AND l.granted)`, application).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	var terminated bool
	if err := s.SystemPool().QueryRow(ctx, `SELECT pg_terminate_backend($1, 5000)`, pid).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate owned service session: %v, terminated=%v", err, terminated)
	}
	var attestation store.TenantDeletionAttestation
	eraseErr := s.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		var err error
		attestation, err = s.OffboardTenant(fenced, tenantA)
		return err
	})
	if !errors.Is(eraseErr, store.ErrTenantServiceBusy) {
		t.Errorf("erasure did not retain unfinished remote work after session loss: attestation=%+v, error=%v", attestation, eraseErr)
	}
	if _, err := receiptRoot.Stat("receiver-effect"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receiver completed before lifecycle attempt: %v", err)
	}
	releaseReceiver()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if content, err := receiptRoot.ReadFile("receiver-effect"); err != nil || string(content) != "external action completed\n" {
		t.Fatalf("independent receiver did not complete its external action: %q, %v", content, err)
	}
	dispatchErr := <-dispatched
	joined = true
	t.Logf("receiver effect finished after lifecycle attempt; erasure=%v, dispatch=%v", eraseErr, dispatchErr)
	if dispatchErr != nil {
		t.Fatal(dispatchErr)
	}
	if err := s.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		_, err := s.OffboardTenant(fenced, tenantA)
		return err
	}); err != nil {
		t.Fatalf("completed original receiver did not release the lifecycle hold: %v", err)
	}
}

func TestOutboxUncertainReceiverSurvivesSuccessfulRetryAndRetention(t *testing.T) {
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	ctx := t.Context()
	ob := orchestrator.NewOutbox(s, orchestrator.WithBackoff(func(int) time.Duration { return 0 }), orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }))
	id := enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "remote-unknown.probe", IdempotencyKey: "ambiguous-then-successful", Payload: []byte(`{}`)})
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{"remote-unknown.probe"}}
	for _, outcome := range []error{errors.New("receiver response lost"), nil} {
		claimed, err := ob.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return outcome }), scope)
		if err != nil || !claimed {
			t.Fatalf("dispatch=%v, %v", claimed, err)
		}
	}
	var pending int
	var status string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE outbox SET delivered_at=now()-interval '48 hours' WHERE tenant_id=$1 AND id=$2`, tenantA, id); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT status, cardinality(receiver_pending_ids) FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, id).Scan(&status, &pending)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "delivered" || pending != 1 {
		t.Fatalf("later success overwrote original uncertainty: status=%s pending=%d", status, pending)
	}
	if n, err := outboxgc.New(s, time.Hour).Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("retention removed unresolved receiver authority: n=%d error=%v", n, err)
	}
	if err := s.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		_, err := s.OffboardTenant(fenced, tenantA)
		return err
	}); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("later success/retention released original uncertainty: %v", err)
	}
}

func TestOutboxKnownNoReceiverEffectDoesNotBlockLifecycle(t *testing.T) {
	for _, outcome := range []struct {
		name string
		err  error
	}{
		{"completed", nil},
		{"not-started", orchestrator.DefiniteNoEffect(errors.New("before IO"))},
		{"deferred", orchestrator.DeferDelivery(errors.New("before IO"))},
	} {
		t.Run(outcome.name, func(t *testing.T) {
			s := newStore(t)
			mustRegisterTenant(t, s, tenantA)
			ob := orchestrator.NewOutbox(s)
			enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "known.probe", IdempotencyKey: outcome.name, Payload: []byte(`{}`)})
			if _, err := ob.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error { return outcome.err }), orchestrator.DestinationScope{IncludePrefixes: []string{"known.probe"}}); err != nil {
				t.Fatal(err)
			}
			if err := s.WithTenantServiceBarrier(t.Context(), tenantA, func(ctx context.Context) error {
				_, err := s.OffboardTenant(ctx, tenantA)
				return err
			}); err != nil {
				t.Fatalf("known outcome retained a phantom remote action: %v", err)
			}
		})
	}
}

func remoteLifetimeTestRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

// Execute the same instrumented test bytes from a fixed relative filename in an
// owned directory. Both ends of the copy are rooted; no PATH or environment value
// chooses the child executable.
func copyRemoteLifetimeWorker(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := remoteLifetimeTestRoot(t, filepath.Dir(executable))
	source, err := sourceRoot.Open(filepath.Base(executable))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	dir := t.TempDir()
	root := remoteLifetimeTestRoot(t, dir)
	destination, err := root.OpenFile("remote-worker.test", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy current test binary: %v; close: %v", copyErr, closeErr)
	}
	return dir
}
