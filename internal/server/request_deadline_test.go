// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// passedDeadline is a request whose deadline has passed before its context's
// timer has run, so Err is still nil.
type passedDeadline struct{ context.Context }

func (passedDeadline) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }

// B10-G1: a deadline that expires during a store write reaches the caller as
// the deadline, not as a socket error naming local addresses.
func TestRequestDeadlineErrorReportsTheDeadlineNotTheSocket(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	socket := fmt.Errorf("write failed: %w", &net.OpError{Op: "write", Net: "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 63707},
		Addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52426}, Err: os.ErrDeadlineExceeded})
	for name, ctx := range map[string]context.Context{"expired": expired, "timer not yet run": passedDeadline{context.Background()}} {
		err := requestDeadlineError(ctx, "codesign", socket)
		if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "same idempotency key") {
			t.Fatalf("%s request = %v", name, err)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := requestDeadlineError(canceled, "codesign", socket); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("canceled request = %v", err)
	}
	// An error that already names the deadline, any error other than a
	// timeout, and a timeout while the request is live are the caller's to
	// read as they are.
	pending := fmt.Errorf("codesign: signing remains pending: %w", context.DeadlineExceeded)
	refused := errors.New("codesign: managed signing key is not configured for this tenant")
	for name, tc := range map[string]struct {
		ctx context.Context
		err error
	}{
		"pending": {expired, pending}, "refusal": {expired, refused}, "live": {context.Background(), socket}, "nil": {expired, nil},
	} {
		if got := requestDeadlineError(tc.ctx, "codesign", tc.err); got != tc.err {
			t.Fatalf("%s = %v, want it unchanged", name, got)
		}
	}
}
