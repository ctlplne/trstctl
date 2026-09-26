// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

// acmeRegistrationLog binds the serving view and every new state event to one
// live registration. Tenant deletion keeps audit history but cannot lend that
// history's account authority to a replacement tenant using the same UUID.
type acmeRegistrationLog struct {
	log      *events.Log
	store    *store.Store
	tenantID string
}

var errACMERegistrationChanged = errors.New("server: ACME request belongs to another tenant registration")

const acmeRegistrationEventNamespace = "acme-state-registration/"

func acmeRegistrationEventPrefix(scope acme.StateScope) string {
	return acmeRegistrationEventNamespace + "v1/" + crypto.SHA256Hex([]byte(scope.Identity)) + "/"
}

// Check again inside the issuer's tenant-key-domain lifetime, before signing or
// revocation. An old request must not use a newly registered tenant's authority
// merely because its outer HTTP admission session disappeared.
func requireACMERequestRegistration(ctx context.Context, st *store.Store, log *events.Log, tenantID string) error {
	expected, bound := acme.RequestStateScope(ctx)
	if !bound {
		return nil
	}
	if st == nil || log == nil || expected.Identity == "" {
		return errACMERegistrationChanged
	}
	current, err := (acmeRegistrationLog{log: log, store: st, tenantID: tenantID}).scope(ctx)
	if err != nil {
		return err
	}
	if current != expected {
		return errACMERegistrationChanged
	}
	return nil
}

func (l acmeRegistrationLog) scope(ctx context.Context) (acme.StateScope, error) {
	if _, err := l.store.GetTenant(ctx, l.tenantID); errors.Is(err, pgx.ErrNoRows) {
		return acme.StateScope{}, nil
	} else if err != nil {
		return acme.StateScope{}, err
	}
	a, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, l.log, l.store, l.tenantID)
	return acme.StateScope{Identity: a.EventID, FirstSequence: a.EventSequence}, err
}

func (l acmeRegistrationLog) Replay(ctx context.Context, from uint64, apply func(events.Event) error) error {
	expected, ok := acme.RequestStateScope(ctx)
	if !ok || expected.Identity == "" || from < expected.FirstSequence {
		return errors.New("server: ACME replay lacks a registration binding")
	}
	return l.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		current, err := l.scope(readCtx)
		if err != nil {
			return err
		}
		if current != expected {
			return errors.New("server: ACME registration changed during replay")
		}
		return l.log.Replay(readCtx, from, func(event events.Event) error {
			// Event positions can change during restore, and a publish can finish
			// after a database session disappears. New producers bind the immutable
			// envelope ID as well as checking the live transaction. History rewrites
			// preserve that ID. Never grant a delayed old event current authority.
			if strings.HasPrefix(event.ID, acmeRegistrationEventNamespace) &&
				!strings.HasPrefix(event.ID, acmeRegistrationEventPrefix(expected)) {
				return nil
			}
			return apply(event)
		})
	})
}

func (l acmeRegistrationLog) Append(ctx context.Context, event events.Event) (events.Event, error) {
	expected, ok := acme.RequestStateScope(ctx)
	if !ok || expected.Identity == "" || expected.FirstSequence == 0 || event.TenantID != l.tenantID {
		return events.Event{}, errors.New("server: ACME event lacks a registration binding")
	}
	if event.ID != "" {
		return events.Event{}, errors.New("server: ACME state producer must not supply an unverified event identity")
	}
	// This envelope namespace changes no payload fields or schema version.
	// Legacy envelopes still replay after their original registration boundary;
	// every new event carries its explicit producer-registration binding.
	event.ID = acmeRegistrationEventPrefix(expected) + events.NewID()
	var appended events.Event
	err := l.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		return l.store.WithTenant(readCtx, l.tenantID, func(tx pgx.Tx) error {
			// A lost outer HTTP admission session must not let a late event enter
			// the next registration. Protect this append with independent xact locks.
			if err := l.store.TryTenantServiceAdmissionTx(readCtx, tx, l.tenantID); err != nil {
				return err
			}
			snapshot, err := l.store.LockLiveTenantRegistrationSnapshotTx(readCtx, tx, l.tenantID)
			if err != nil {
				return err
			}
			if snapshot.EventSeq != expected.FirstSequence {
				return errors.New("server: ACME registration changed before append")
			}
			registration, found, err := l.log.EventAtSequence(readCtx, snapshot.EventSeq)
			if err != nil {
				return err
			}
			if !found || registration.ID != expected.Identity || registration.TenantID != l.tenantID || registration.Type != "tenant.registered" {
				return errors.New("server: ACME registration history changed before append")
			}
			appended, err = l.log.Append(readCtx, event)
			return err
		})
	})
	return appended, err
}
