// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
)

// JobLeaseMaintainer extends only the currently held job and attempt. A refusal
// means this agent must stop; it cannot recover authority by claiming anew.
type JobLeaseMaintainer interface {
	ExtendJobClaim(context.Context, int64, int) (time.Time, error)
}

// ErrJobClaimLost prevents installation after the server refuses the claim.
var ErrJobClaimLost = errors.New("relay: job claim is no longer held")

const hostRenewMaxDuration = 10 * time.Minute

type hostRenewClaim struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	ch     JobLeaseMaintainer
	job    Job
	mu     sync.Mutex // serializes extension RPCs and the confirmed expiry
	until  time.Time
}

func maintainHostRenewClaim(ctx context.Context, ch JobLeaseMaintainer, job Job) (*hostRenewClaim, error) {
	ctx, cancel := context.WithTimeout(ctx, hostRenewMaxDuration)
	g := &hostRenewClaim{ctx: ctx, cancel: cancel, done: make(chan struct{}), ch: ch, job: job}
	if err := g.confirm(); err != nil {
		cancel()
		return nil, err
	}
	go g.maintain()
	return g, nil
}

func (g *hostRenewClaim) stop() {
	g.cancel()
	<-g.done
}

// confirm obtains fresh server authority, including before exporting the key.
// An extension never waits beyond the last confirmed lease's expiry.
func (g *hostRenewClaim) confirm() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	if !g.until.IsZero() && g.until.Before(deadline) {
		deadline = g.until
	}
	ctx, cancel := context.WithDeadline(g.ctx, deadline)
	defer cancel()
	until, err := g.ch.ExtendJobClaim(ctx, g.job.JobID, g.job.Attempt)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !until.After(time.Now()) {
		return ErrJobClaimLost
	}
	g.until = until
	return nil
}

func (g *hostRenewClaim) remaining() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return time.Until(g.until)
}

func (g *hostRenewClaim) maintain() {
	defer close(g.done)
	delay := g.remaining() / 3
	for {
		if delay <= 0 || !waitHostRenew(g.ctx, delay) {
			g.cancel()
			return
		}
		err := g.confirm()
		remaining := g.remaining()
		if remaining <= 0 || (err != nil && !retryableClaimTransport(err)) {
			g.cancel()
			return
		}
		delay = remaining / 3
		if err != nil && delay > time.Second {
			delay = time.Second
		}
	}
}

func retryableClaimTransport(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return errors.Is(err, context.DeadlineExceeded)
	}
}

func signHostCSR(ctx context.Context, signer CSRSigner, job Job, csr []byte, maintained bool) ([]byte, []byte, string, error) {
	for {
		callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		cert, chain, fingerprint, err := signer.SignJobCSR(callCtx, job.JobID, job.Attempt, csr)
		cancel()
		if err == nil || !maintained || ctx.Err() != nil {
			return cert, chain, fingerprint, err
		}
		delay, pending := transport.CSRPendingRetryDelay(err)
		if !pending {
			if !retryableClaimTransport(err) {
				return nil, nil, "", err
			}
			delay = time.Second
		}
		if !waitHostRenew(ctx, delay) {
			return nil, nil, "", ctx.Err()
		}
	}
}

func waitHostRenew(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
