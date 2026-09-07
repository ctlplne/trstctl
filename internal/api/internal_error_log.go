// SPDX-License-Identifier: MPL-2.0

package api

import (
	"log/slog"
	"reflect"
)

// logInternalError records an error that is about to be answered as a bare
// "internal error". The message is the Go error text (never a request body or
// a secret: errors carry identifiers and SQL states, not payloads), so an
// operator can correlate a 500 with its cause.
func (a *API) logInternalError(err error) {
	if err == nil {
		return
	}
	slog.Error("api: internal error answered as 500", slog.String("error", err.Error()), slog.String("type", reflect.TypeOf(err).String()))
}
