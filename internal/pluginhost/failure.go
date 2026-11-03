// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"context"
	"errors"
	"strings"

	"github.com/tetratelabs/wazero/sys"

	"trstctl.com/trstctl/internal/bulkhead"
)

// Why a call failed, in a closed vocabulary (A242). A module's own error text
// is whatever the guest or its target chose to say; the class is what the
// host observed, so a receipt can carry it without carrying anything else.
const (
	FailureTimeout  = "timeout"            // interrupted at its time limit
	FailureCanceled = "canceled"           // the caller gave up first
	FailureRejected = "rejected"           // the module's worker pool was full
	FailureTrap     = "trap"               // the guest trapped: unreachable, out of bounds, stack, divide by zero
	FailureNoEntry  = "missing-entrypoint" // the module exports no such function
	FailureInstance = "instantiate"        // the call's fresh instance did not start
	FailureError    = "error"              // anything else the host returned
)

// ErrNoEntrypoint is returned for a call to a function the module does not
// export.
var ErrNoEntrypoint = errors.New("pluginhost: plugin has no exported function")

// errCallInstance marks a per-call instance that did not start.
var errCallInstance = errors.New("pluginhost: instantiate call module")

// FailureClass names what kind of failure err, returned by Invoke or
// InvokeWith, was.
func FailureClass(err error) string {
	var exit *sys.ExitError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, bulkhead.ErrRejected):
		return FailureRejected
	case errors.As(err, &exit) && exit.ExitCode() == sys.ExitCodeDeadlineExceeded,
		errors.Is(err, context.DeadlineExceeded):
		return FailureTimeout
	case errors.As(err, &exit) && exit.ExitCode() == sys.ExitCodeContextCanceled,
		errors.Is(err, context.Canceled):
		return FailureCanceled
	case errors.Is(err, ErrNoEntrypoint):
		return FailureNoEntry
	case errors.Is(err, errCallInstance):
		return FailureInstance
	case strings.Contains(err.Error(), "wasm error: "):
		// wazero reports every trap as "wasm error: <kind>"; its error type is
		// internal to the runtime, so the prefix is the stable signal.
		return FailureTrap
	default:
		return FailureError
	}
}
