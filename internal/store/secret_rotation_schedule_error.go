// SPDX-License-Identifier: MPL-2.0

package store

import "trstctl.com/trstctl/internal/schedulerhistory"

const (
	SecretRotationScheduleRollbackError = schedulerhistory.RollbackError

	SecretRotationScheduleTickInterruptedError = schedulerhistory.TickInterruptedError
	SecretRotationScheduleTickProcessingError  = schedulerhistory.TickProcessingError

	SecretRotationScheduleApprovalPendingError   = schedulerhistory.ApprovalPendingError
	SecretRotationScheduleCommandInProgressError = schedulerhistory.CommandInProgressError
	SecretRotationScheduleConfigUnanchoredError  = schedulerhistory.ConfigUnanchoredError
	SecretRotationScheduleGenericDeferredError   = schedulerhistory.GenericDeferredError
)

// CanonicalSecretRotationScheduleError is the only free-text-shaped value that
// may leave the scheduled-rotation boundary. The input can come from immutable
// v1 history or an old read-model row, so an unknown value is classified from
// the package-owned terminal status instead of being returned verbatim.
func CanonicalSecretRotationScheduleError(status, detail string) string {
	return schedulerhistory.CanonicalError(status, detail)
}

// IsCanonicalSecretRotationScheduleError reports whether a producer already
// supplied an exact member of the closed scheduler vocabulary. New durable
// command/event producers must pass this check; only the v1 compatibility path
// is allowed to collapse historical arbitrary text.
func IsCanonicalSecretRotationScheduleError(status, detail string) bool {
	return schedulerhistory.IsCanonicalError(status, detail)
}

// SecretRotationScheduleDeferredError maps one closed row-local reason to the
// only operator detail the durable receiver may persist for that reason.
func SecretRotationScheduleDeferredError(reason string) string {
	return schedulerhistory.DeferredError(reason)
}

func isCanonicalSecretRotationScheduleTickSystemError(detail string) bool {
	return schedulerhistory.IsCanonicalTickSystemError(detail, SecretRotationScheduleTickSupersededError)
}
