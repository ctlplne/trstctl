// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantConfinementLeavesRetryableFailuresVisible(t *testing.T) {
	q := newTenantPoisonQuarantine(nil)
	base := events.Event{Sequence: 10, Type: EventOwnerCreated,
		TenantID: "00000000-0000-4000-8000-0000000000a1"}
	keyState := base
	keyState.Type = EventTenantOffboarded
	for _, tc := range []struct {
		name  string
		event events.Event
		err   error
	}{
		{"transaction retry", base, &pgconn.PgError{Code: "40001"}},
		{"connection unavailable", base, &pgconn.PgError{Code: "08006"}},
		{"resource unavailable", base, &pgconn.PgError{Code: "53100"}},
		{"canceled", base, context.Canceled},
		{"datastore busy", base, store.ErrDatastoreBusy},
		{"unknown failure", base, errors.New("temporary extension failure")},
		{"network unavailable", base, &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}},
		{"transaction unavailable", base, pgx.ErrTxClosed},
		{"canonical event unavailable", base, ErrCanonicalEventRequired},
		{"restore admission unavailable", base, store.ErrRestoreAdmissionLost},
		{"key custody", keyState, &pgconn.PgError{Code: "22P02"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			confined, err := q.confineApplyFailure(context.Background(), nil, tc.event, tc.err)
			if confined || err != nil {
				t.Fatalf("retryable failure confined=%t, err=%v", confined, err)
			}
		})
	}
}
