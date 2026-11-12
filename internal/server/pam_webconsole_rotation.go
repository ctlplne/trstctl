// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A273-O4: a web console target may name an in-place account provider. The
// gateway signed in to the console as the vaulted account, so once a session
// ends, its account rotates through that provider: the password the session
// used no longer signs in. The expiry worker queues the rotation once per
// session, the static rotation engine performs it, and a rotation that cannot
// be queued now is queued on a later pass and raises one alert.

func pamSessionAccountRotationQueuedEventID(tenantID, sessionID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-session-account-rotation-queued\x00"+tenantID+"\x00"+sessionID)).String()
}

// rotateEndedWebConsoleAccounts queues the rotation of each ended web console
// session's account whose rotation is not yet queued.
func (s *pamService) rotateEndedWebConsoleAccounts(ctx context.Context) error {
	if s.rotation.afterSession == nil {
		return nil
	}
	due, err := s.store.ListPAMSessionsAwaitingAccountRotation(ctx, 100)
	if err != nil {
		return err
	}
	var first error
	for _, r := range due {
		if err := s.rotateWebConsoleAccount(ctx, r); err != nil {
			s.alertSessionAccountRotationBlocked(ctx, r, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// rotateWebConsoleAccount queues one session's rotation and records it.
func (s *pamService) rotateWebConsoleAccount(ctx context.Context, r store.PAMSessionAccountRotation) error {
	commandID, err := s.rotation.afterSession(ctx, r.TenantID, r.Provider, r.AccountSecret, r.ID, r.StartedAt)
	if err != nil {
		return err
	}
	data, err := json.Marshal(projections.PAMSessionAccountRotationQueued{ID: r.ID, Provider: r.Provider, RotationCommandID: commandID, At: s.clock().UTC()})
	if err != nil {
		return err
	}
	candidate := events.Event{ID: pamSessionAccountRotationQueuedEventID(r.TenantID, r.ID), Type: projections.EventPAMSessionAccountRotationQueued,
		TenantID: r.TenantID, Time: s.clock().UTC(), Data: data}
	canonical, err := s.log.Append(ctx, candidate)
	if err != nil {
		return err
	}
	if canonical.Type != candidate.Type || canonical.TenantID != r.TenantID {
		return fmt.Errorf("%w: the session's account rotation record belongs to another record", orchestrator.ErrIdempotencyConflict)
	}
	return s.store.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error { return s.projector.ApplyTx(ctx, tx, canonical) })
}

// alertSessionAccountRotationBlocked raises one critical alert per session
// whose account rotation could not be queued: the password its gateway
// signed in with still signs in.
func (s *pamService) alertSessionAccountRotationBlocked(ctx context.Context, r store.PAMSessionAccountRotation, cause error) {
	if s.outbox == nil {
		return
	}
	entry, err := pamSessionAccountRotationBlockedAlert(r, cause)
	if err != nil {
		return
	}
	var inserted bool
	if err := s.store.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		var err error
		inserted, err = s.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	}); err == nil && inserted && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
}

func pamSessionAccountRotationBlockedAlert(r store.PAMSessionAccountRotation, cause error) (orchestrator.Entry, error) {
	why := api.ErrorDetail(cause)
	if why == "" {
		why = "the control plane could not record the rotation"
	}
	key := "pam-session-account-rotation-blocked:" + r.ID
	payload, err := json.Marshal(notify.Alert{
		Kind: notify.KindSessionAccountRotationBlocked, TenantID: r.TenantID, OperationID: key,
		Subject: r.TargetType + "/" + r.TargetID, Severity: notify.AlertSeverityCritical,
		Detail: fmt.Sprintf("Web console session %s to %s/%s ended, and the rotation of the account its gateway signed in as "+
			"could not be queued through provider %s (%s), so that password still signs in. Restore the provider, or rotate "+
			"the account; the rotation is queued at the next expiry tick once it can be.", r.ID, r.TargetType, r.TargetID, r.Provider, why),
	})
	if err != nil {
		return orchestrator.Entry{}, err
	}
	return orchestrator.Entry{TenantID: r.TenantID, Destination: notify.DestinationRisk, IdempotencyKey: key, Payload: payload}, nil
}
