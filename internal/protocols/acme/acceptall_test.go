// SPDX-License-Identifier: MPL-2.0

package acme

import "context"

// AcceptAll is a Validator that accepts every challenge without checking. It
// exists ONLY in the test binary (this is an internal `_test.go` file, so it is
// not compiled into the production build) — it gives the ACME server tests a
// trivial validator without putting an accept-everything path anywhere a real
// deployment could reach. Production uses Validators (real per-method validation,
// fail-closed). Closing B9: no AcceptAll on any production path.
type AcceptAll struct{}

// Validate always succeeds.
func (AcceptAll) Validate(context.Context, string, string, string, string) error { return nil }
