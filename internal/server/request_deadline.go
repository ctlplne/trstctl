// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// requestDeadlineError reports the caller's ended request instead of the
// socket timeout a store or transport returned once its deadline passed
// (B10-G1). A deadline that expires in the middle of a database write fails the
// write with "write tcp <local>-><peer>: i/o timeout"; the honest outcome for
// the caller is the deadline, which the API answers as a retryable 503, and an
// idempotent retry with the same key finds the command if it was recorded.
// Only a timeout is rewritten: any other error, or a timeout while the request
// is still live, passes through unchanged.
func requestDeadlineError(ctx context.Context, op string, err error) error {
	ended := ctx.Err()
	if deadline, ok := ctx.Deadline(); ended == nil && ok && !time.Now().Before(deadline) {
		// The deadline has passed, though the context's own timer has not run yet.
		ended = context.DeadlineExceeded
	}
	var timeout net.Error
	if err == nil || ended == nil || errors.Is(err, ended) || !errors.As(err, &timeout) || !timeout.Timeout() {
		return err
	}
	return fmt.Errorf("%s: the request ended before the outcome was confirmed; retry with the same idempotency key: %w", op, ended)
}
