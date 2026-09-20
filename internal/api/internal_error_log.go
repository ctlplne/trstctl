// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// logInternalError records an error that is about to be answered as a bare
// "internal error" so an operator can correlate the 500 with its cause. The
// record carries the trace id the response already exposes, the error's type
// chain and a redacted message: PostgreSQL detail/hint fields (which quote row
// values) are never logged, and any quoted literal in a message is masked, so a
// secret name or a tenant's input cannot reach the log through an error string.
func (a *API) logInternalError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	attrs := []any{
		slog.String("trace", w.Header().Get("traceparent")),
		slog.String("types", errorTypeChain(err)),
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		attrs = append(attrs,
			slog.String("sqlstate", pgErr.Code),
			slog.String("pg_message", redactQuoted(pgErr.Message)),
			slog.String("pg_constraint", pgErr.ConstraintName),
			slog.String("pg_table", pgErr.TableName))
	} else {
		attrs = append(attrs, slog.String("error", redactQuoted(truncateForLog(err.Error(), 240))))
	}
	slog.Error("api: internal error answered as 500", attrs...)
}

var quotedLiteral = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// redactQuoted masks every double- or single-quoted segment: PostgreSQL and
// most Go errors quote the offending value, and the value is what must not be
// logged. The surrounding message (constraint, column, operation) stays.
func redactQuoted(s string) string {
	return quotedLiteral.ReplaceAllString(s, "\"[redacted]\"")
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// errorTypeChain names the concrete error types along the Unwrap chain (first
// four), which is what distinguishes a driver error from a handler error
// without reproducing any message text.
func errorTypeChain(err error) string {
	var parts []string
	for i := 0; err != nil && i < 4; i++ {
		parts = append(parts, fmt.Sprintf("%T", err))
		err = errors.Unwrap(err)
	}
	return strings.Join(parts, " > ")
}
