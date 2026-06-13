package signing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// StartChild launches the signer binary as a child process listening on
// socketPath (single-node mode), waits until it is healthy, and returns a
// connected Client plus a stop function. This is the control-plane side of the
// AN-4 process boundary: the signer runs as its own process, reached only over
// the UDS.
func StartChild(ctx context.Context, binaryPath, socketPath string) (*Client, func(), error) {
	cmd := exec.Command(binaryPath, "--socket", socketPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start signer: %w", err)
	}

	client, err := dialReady(ctx, socketPath, 10*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, nil, err
	}

	stop := func() {
		_ = client.Close()
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	return client, stop, nil
}

// Supervisor keeps the signer child process running: it launches
// cmd/trustctl-signer, and if the child exits it relaunches it with capped
// exponential backoff until its context is cancelled. The control plane signs
// only through the current child (AN-4); when the child is down, Client returns
// nil and signing operations fail closed.
//
// Keys live in the signer's memory and do NOT survive a restart — recovery means
// the process is back and serving, not that prior keys are restored.
type Supervisor struct {
	mu     sync.RWMutex
	client *Client
	pid    int

	restarts atomic.Uint64 // cumulative relaunches after the first healthy start (SF.3 telemetry)

	cancel context.CancelFunc
	done   chan struct{}
}

// Supervise starts the signer child and supervises it. It blocks until the first
// launch is healthy (returning a connected Supervisor) or that first launch
// fails (returning an error) — so a bad binary fails fast rather than looping.
func Supervise(ctx context.Context, binaryPath, socketPath string, extraArgs ...string) (*Supervisor, error) {
	sctx, cancel := context.WithCancel(ctx)
	s := &Supervisor{cancel: cancel, done: make(chan struct{})}
	ready := make(chan error, 1)
	go s.run(sctx, binaryPath, socketPath, ready, extraArgs)
	select {
	case err := <-ready:
		if err != nil {
			cancel()
			<-s.done
			return nil, err
		}
		return s, nil
	case <-sctx.Done():
		cancel()
		<-s.done
		return nil, sctx.Err()
	}
}

// Client returns the current connected signer client, or nil while no child is
// healthy (e.g. mid-restart). Callers must treat nil as "signer unavailable" and
// fail closed.
func (s *Supervisor) Client() *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// Pid returns the current child process id, or 0 when no child is running.
func (s *Supervisor) Pid() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid
}

// Restarts returns the cumulative number of times the signer child has been
// relaunched after the first healthy start. The control plane samples this for
// the trustctl_signer_restarts_total metric (SF.3).
func (s *Supervisor) Restarts() uint64 { return s.restarts.Load() }

// Close stops supervision and the child, and waits for the loop to exit.
func (s *Supervisor) Close() {
	s.cancel()
	<-s.done
}

func (s *Supervisor) set(c *Client, pid int) {
	s.mu.Lock()
	old := s.client
	s.client = c
	s.pid = pid
	s.mu.Unlock()
	if old != nil && old != c {
		_ = old.Close()
	}
}

func (s *Supervisor) run(ctx context.Context, binaryPath, socketPath string, ready chan<- error, extraArgs []string) {
	defer close(s.done)
	const maxBackoff = 5 * time.Second
	backoff := 100 * time.Millisecond
	first := true

	for ctx.Err() == nil {
		// A stale socket from a dead child would block the new child's listen.
		_ = os.Remove(socketPath)

		// Every (re)launch after the first healthy start is a restart.
		if !first {
			s.restarts.Add(1)
		}

		// CommandContext so cancelling the supervisor terminates the child; a
		// graceful SIGINT with a kill fallback after WaitDelay.
		cmd := exec.CommandContext(ctx, binaryPath, append([]string{"--socket", socketPath}, extraArgs...)...)
		cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
		cmd.WaitDelay = 5 * time.Second
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			if first {
				ready <- fmt.Errorf("start signer: %w", err)
				return
			}
			s.backoffSleep(ctx, &backoff, maxBackoff)
			continue
		}

		client, err := dialReady(ctx, socketPath, 10*time.Second)
		if err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			if first {
				ready <- err
				return
			}
			s.backoffSleep(ctx, &backoff, maxBackoff)
			continue
		}

		s.set(client, cmd.Process.Pid)
		if first {
			ready <- nil
			first = false
		}
		backoff = 100 * time.Millisecond // healthy run resets backoff

		// Block until the child exits (killed, crashed, or stopped on cancel).
		_ = cmd.Wait()
		s.set(nil, 0)
		if ctx.Err() != nil {
			return
		}
		s.backoffSleep(ctx, &backoff, maxBackoff)
	}
}

func (s *Supervisor) backoffSleep(ctx context.Context, backoff *time.Duration, max time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(*backoff):
	}
	if *backoff < max {
		*backoff *= 2
	}
}

// dialReady connects and retries Health until the signer is serving or the
// timeout passes.
func dialReady(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	client, err := Dial(socketPath)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		hctx, cancel := context.WithTimeout(ctx, time.Second)
		ok := client.Healthy(hctx)
		cancel()
		if ok {
			return client, nil
		}
		if time.Now().After(deadline) {
			_ = client.Close()
			return nil, fmt.Errorf("signer not ready within %s", timeout)
		}
		select {
		case <-ctx.Done():
			_ = client.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
