// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "errors"

// ConfirmedNoMutation records a protocol adapter's positive proof that the
// mutation protected by DoAtMostOnceEffect was never submitted. Preparatory
// calls may have performed I/O. This differs from DefiniteNoEffect, which only
// covers refusal before all receiver I/O. Never use this for a generic timeout,
// lost response, uncertain receiver, or a callback that returned partial output.
// A process crash has no such proof and continues to retain its pending claim.
func ConfirmedNoMutation(cause error) error {
	if cause == nil {
		return nil
	}
	return &confirmedNoMutationError{cause: cause}
}

type confirmedNoMutationError struct{ cause error }

func (e *confirmedNoMutationError) Error() string {
	return "orchestrator: protected mutation was not submitted"
}
func (e *confirmedNoMutationError) Unwrap() error { return e.cause }

func isConfirmedNoMutation(err error) bool {
	var proof *confirmedNoMutationError
	return errors.As(err, &proof)
}

type noMutationSafeError struct{ class string }

func (e noMutationSafeError) Error() string {
	return "orchestrator: protected mutation was not submitted; retry permitted"
}
func (e noMutationSafeError) SafeDeliveryClass() string { return e.class }
func noMutationSafeResult(err error) error {
	class, _ := safePersistableDeliveryClass(err)
	return noMutationSafeError{class: class}
}
