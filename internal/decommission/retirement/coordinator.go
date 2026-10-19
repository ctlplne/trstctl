// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

// Request asks to retire one superseded/revoked signer-backed CA key.
type Request struct {
	FinalEpoch          uint64
	ConfirmIrreversible bool
	KeyClass            string
	Approvals           []string
}

type Receipt struct {
	KeyID          string `json:"key_id"`
	CommandEventID string `json:"command_event_id"`
	Status         string `json:"status"`
	LedgerPosition uint64 `json:"ledger_position"`
	FinalEpoch     uint64 `json:"final_epoch"`
}

type RetryRequest struct {
	CommandEventID      string
	ExpectedAttempts    int
	Reason              string
	RequestKey          string
	ConfirmIrreversible bool
}

type RetryReceipt struct {
	KeyID          string `json:"key_id"`
	CommandEventID string `json:"command_event_id"`
	GrantEventID   string `json:"grant_event_id"`
	OutboxID       int64  `json:"outbox_id"`
	AttemptsBefore int    `json:"attempts_before"`
	AttemptLimit   int    `json:"attempt_limit"`
	Status         string `json:"status"`
}

// Coordinator freezes one exact event prefix, appends the command, and applies
// its derived state plus outbox intent. A duplicate append is accepted only when
// every command byte is identical.
type Coordinator struct {
	store      *corestore.Store
	log        *events.Log
	projection *Projection
}

func NewCoordinator(store *corestore.Store, log *events.Log, projection *Projection) *Coordinator {
	return &Coordinator{store: store, log: log, projection: projection}
}

func (c *Coordinator) Request(ctx context.Context, tenantID, keyID string, request Request) (Receipt, error) {
	if c == nil || c.store == nil || c.log == nil || c.projection == nil {
		return Receipt{}, ErrProjectionMissing
	}
	tenantID, keyID = strings.TrimSpace(tenantID), strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" || request.FinalEpoch == 0 || !request.ConfirmIrreversible {
		return Receipt{}, fmt.Errorf("%w: tenant, key, final epoch, and irreversible confirmation are required", ErrInvalidCommand)
	}
	authority, err := c.store.GetCAAuthority(ctx, tenantID, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Receipt{}, err
		}
		return Receipt{}, fmt.Errorf("vdec retirement: load CA authority: %w", err)
	}
	if authority.SignerHandle == "" || (authority.Status != "superseded" && authority.Status != "revoked") {
		return Receipt{}, fmt.Errorf("%w: CA authority must be signer-backed and superseded or revoked", ErrInvalidCommand)
	}

	eventHead, tenantEvents, err := c.snapshot(ctx, tenantID)
	if err != nil {
		return Receipt{}, err
	}
	active, activeFound, err := c.projection.Fetch(ctx, tenantID, keyID)
	if err != nil {
		return Receipt{}, err
	}
	if activeFound && active.Status == StatusDestroyed {
		return Receipt{}, fmt.Errorf("%w: CA key already has a terminal destruction record", ErrCommandConflict)
	}
	if activeFound && active.Status == StatusPending {
		changed, err := c.dependencyChangedBetween(ctx, tenantID, keyID, active.LedgerPosition+1, eventHead)
		if err != nil {
			return Receipt{}, err
		}
		if !changed {
			frozenEvent, found, err := c.log.EventByID(ctx, active.CommandEventID)
			if err != nil {
				return Receipt{}, err
			}
			frozen, decodeErr := DecodeRequested(frozenEvent)
			if !found || decodeErr != nil || frozen.FinalEpoch != request.FinalEpoch ||
				frozen.SignerHandle != authority.SignerHandle || frozen.KeyClass != KeyClass(request.KeyClass) ||
				!slices.Equal(frozen.Approvals, normalizedApprovals(request.Approvals)) {
				return Receipt{}, fmt.Errorf("%w: a different retirement command is pending", ErrCommandConflict)
			}
			return Receipt{
				KeyID: keyID, CommandEventID: active.CommandEventID, Status: active.Status,
				LedgerPosition: active.LedgerPosition, FinalEpoch: active.FinalEpoch,
			}, nil
		}
	}
	projection, err := depstate.Fold(tenantEvents)
	if err != nil {
		return Receipt{}, fmt.Errorf("vdec retirement: fold dependency evidence: %w", err)
	}
	state, found := projection.Lookup(tenantID, keyID)
	if !found || len(state.Registered) == 0 {
		return Receipt{}, fmt.Errorf("%w: no dependency evidence exists for this key", ErrInvalidCommand)
	}
	requiredSet, err := gate.RequiredSetBytes(state)
	if err != nil {
		return Receipt{}, err
	}
	requested := RequestedV1{
		TenantID: tenantID, KeyID: keyID, SignerHandle: authority.SignerHandle,
		FinalEpoch: request.FinalEpoch, LedgerPosition: eventHead,
		RequiredSet: requiredSet, RequiredSetDigest: gateDigest(requiredSet),
		AuditChainHead: gate.AuditChainHead(tenantEvents),
		CompletionEventsDigest: CompletionDigest(tenantEvents,
			depstate.TypeReprotectionCompleted, depstate.TypeDependencyReleased,
			depstate.TypeDependencyErasureDesignated, depstate.TypeRevocationCompleted),
		RevocationCompletionDigest: CompletionDigest(tenantEvents, depstate.TypeRevocationCompleted),
		KeyClass:                   KeyClass(request.KeyClass), Approvals: normalizedApprovals(request.Approvals),
	}
	wanted, err := EncodeRequested(requested)
	if err != nil {
		return Receipt{}, err
	}
	wanted.ID = CommandEventID(requested)
	canonical, found, err := c.log.EventByID(ctx, wanted.ID)
	if err != nil {
		return Receipt{}, fmt.Errorf("vdec retirement: reconcile request: %w", err)
	}
	if !found {
		canonical, err = c.log.Append(ctx, wanted)
		if err != nil {
			return Receipt{}, fmt.Errorf("vdec retirement: append request: %w", err)
		}
	}
	if canonical.ID != wanted.ID || canonical.Type != wanted.Type || canonical.TenantID != wanted.TenantID ||
		canonical.SchemaVersion != wanted.SchemaVersion || !bytes.Equal(canonical.Data, wanted.Data) {
		return Receipt{}, fmt.Errorf("%w: command event identity resolved to different bytes", ErrCommandConflict)
	}
	if canonical.Sequence > eventHead+1 {
		changed, err := c.dependencyChangedBetween(ctx, tenantID, keyID, eventHead+1, canonical.Sequence-1)
		if err != nil {
			return Receipt{}, err
		}
		if changed {
			return Receipt{}, fmt.Errorf("%w: dependency evidence changed while the command was being frozen; retry", ErrCommandConflict)
		}
	}
	if err := c.projection.Apply(ctx, canonical); err != nil {
		return Receipt{}, fmt.Errorf("vdec retirement: project request: %w", err)
	}
	active, found, err = c.projection.Fetch(ctx, tenantID, keyID)
	if err != nil {
		return Receipt{}, err
	}
	if !found || active.CommandEventID != canonical.ID {
		return Receipt{}, ErrCommandConflict
	}
	return Receipt{
		KeyID: keyID, CommandEventID: canonical.ID, Status: active.Status,
		LedgerPosition: requested.LedgerPosition, FinalEpoch: requested.FinalEpoch,
	}, nil
}

// Retry grants exactly one more delivery attempt to an exhausted original
// command. The signer sees the same command event and can return its durable
// signed journal result if the first response was lost. An event append that
// survives a SQL commit failure is reconciled from its deterministic identity.
func (c *Coordinator) Retry(ctx context.Context, tenantID, keyID string, request RetryRequest) (RetryReceipt, error) {
	var receipt RetryReceipt
	if c == nil || c.store == nil || c.log == nil || c.projection == nil {
		return receipt, ErrProjectionMissing
	}
	tenantID, keyID = strings.TrimSpace(tenantID), strings.TrimSpace(keyID)
	request.CommandEventID = strings.TrimSpace(request.CommandEventID)
	request.Reason = strings.TrimSpace(request.Reason)
	request.RequestKey = strings.TrimSpace(request.RequestKey)
	actor, found := events.ActorFromContext(ctx)
	if !found || actor.Subject == "" || tenantID == "" || keyID == "" || request.CommandEventID == "" ||
		request.ExpectedAttempts < 1 || request.ExpectedAttempts >= 2147483647 ||
		request.Reason == "" || len(request.Reason) > 1024 || request.RequestKey == "" ||
		len(request.RequestKey) > 256 || !request.ConfirmIrreversible {
		return receipt, ErrInvalidCommand
	}
	grantID := RetryEventID(tenantID, keyID, request.CommandEventID,
		request.ExpectedAttempts, request.RequestKey, actor.Subject)
	retained, exists, err := c.log.EventByID(ctx, grantID)
	if err != nil {
		return receipt, err
	}
	if exists {
		grant, err := DecodeRetryRequested(retained)
		if err != nil || grant.TenantID != tenantID || grant.KeyID != keyID ||
			grant.CommandEventID != request.CommandEventID || grant.Attempts != request.ExpectedAttempts ||
			grant.RequestKey != request.RequestKey || grant.Reason != request.Reason || grant.Actor != actor.Subject {
			return receipt, ErrCommandConflict
		}
		if err := c.projection.Apply(ctx, retained); err != nil {
			return receipt, err
		}
		return retryReceipt(grant, retained.ID), nil
	}
	command, exists, err := c.log.EventByID(ctx, request.CommandEventID)
	if err != nil {
		return receipt, err
	}
	if !exists {
		return receipt, ErrRetryUnavailable
	}
	frozen, err := DecodeRequested(command)
	if err != nil || frozen.TenantID != tenantID || frozen.KeyID != keyID {
		return receipt, ErrCommandConflict
	}
	for _, terminal := range []string{StatusRefused, StatusDestroyed} {
		result, terminalFound, err := c.log.EventByID(ctx, TerminalEventID(command.ID, terminal))
		if err != nil {
			return receipt, err
		}
		if terminalFound {
			if err := c.projection.Apply(ctx, result); err != nil {
				return receipt, err
			}
			return receipt, ErrRetryUnavailable
		}
	}
	expectedPayload, err := json.Marshal(struct {
		CommandEventID string      `json:"command_event_id"`
		Requested      RequestedV1 `json:"requested"`
	}{CommandEventID: command.ID, Requested: frozen})
	if err != nil {
		return receipt, err
	}
	err = c.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var signerHandle, authorityStatus string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(signer_handle,''),status FROM ca_authorities
		    WHERE tenant_id=$1 AND id=$2::uuid FOR SHARE`, tenantID, keyID).
			Scan(&signerHandle, &authorityStatus); err != nil {
			return err
		}
		if signerHandle != frozen.SignerHandle ||
			(authorityStatus != "superseded" && authorityStatus != "revoked") {
			return ErrRetryUnavailable
		}
		var activeCommand, retirementStatus string
		var ledgerPosition uint64
		if err := tx.QueryRow(ctx, `SELECT command_event_id,status,ledger_position
		    FROM decommission_retirements WHERE tenant_id=$1 AND key_id=$2 FOR UPDATE`, tenantID, keyID).
			Scan(&activeCommand, &retirementStatus, &ledgerPosition); err != nil {
			return err
		}
		// The first writer may have appended while this caller waited for this
		// exact row lock. Reconcile its retained event before interpreting the
		// now-pending outbox row as a conflicting command.
		if prior, priorFound, err := c.log.EventByID(ctx, grantID); err != nil {
			return err
		} else if priorFound {
			grant, err := DecodeRetryRequested(prior)
			if err != nil || grant.TenantID != tenantID || grant.KeyID != keyID ||
				grant.CommandEventID != request.CommandEventID || grant.Attempts != request.ExpectedAttempts ||
				grant.RequestKey != request.RequestKey || grant.Reason != request.Reason || grant.Actor != actor.Subject {
				return ErrCommandConflict
			}
			if err := c.projection.ApplyTx(ctx, tx, prior); err != nil {
				return err
			}
			receipt = retryReceipt(grant, prior.ID)
			return nil
		}
		if activeCommand != request.CommandEventID || retirementStatus != StatusPending ||
			ledgerPosition != frozen.LedgerPosition {
			return ErrRetryUnavailable
		}
		var outboxStatus, destination, outboxKey string
		var outboxID int64
		var payload []byte
		var attempts, retryLimit int
		if err := tx.QueryRow(ctx, `SELECT id,destination,idempotency_key,payload,status,attempts,retry_attempt_limit
		    FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`, tenantID, command.ID).
			Scan(&outboxID, &destination, &outboxKey, &payload, &outboxStatus, &attempts, &retryLimit); err != nil {
			return err
		}
		if destination != DestinationRetirement || outboxKey != command.ID || !bytes.Equal(payload, expectedPayload) {
			return ErrCommandConflict
		}
		if outboxStatus != "failed" || attempts != request.ExpectedAttempts || retryLimit > attempts {
			return ErrRetryUnavailable
		}
		head, err := c.log.LastSequence(ctx)
		if err != nil {
			return err
		}
		changed, err := c.dependencyChangedBetween(ctx, tenantID, keyID, frozen.LedgerPosition+1, head)
		if err != nil {
			return err
		}
		if changed {
			return ErrRetryUnavailable
		}
		grant := RetryRequestedV1{
			TenantID: tenantID, KeyID: keyID, CommandEventID: command.ID, OutboxID: outboxID,
			PayloadSHA256: crypto.SHA256Hex(payload), Attempts: attempts,
			RequestKey: request.RequestKey, Reason: request.Reason, Actor: actor.Subject,
			RequestedAt: time.Now().UTC(),
		}
		wanted, err := EncodeRetryRequested(grant)
		if err != nil {
			return err
		}
		wanted.ID = grantID
		canonical, err := c.log.Append(ctx, wanted)
		if err != nil {
			return err
		}
		if canonical.ID != wanted.ID || canonical.TenantID != wanted.TenantID ||
			canonical.Type != wanted.Type || !bytes.Equal(canonical.Data, wanted.Data) {
			return ErrCommandConflict
		}
		if err := c.projection.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		receipt = retryReceipt(grant, canonical.ID)
		return nil
	})
	return receipt, err
}

func retryReceipt(grant RetryRequestedV1, eventID string) RetryReceipt {
	return RetryReceipt{
		KeyID: grant.KeyID, CommandEventID: grant.CommandEventID, GrantEventID: eventID,
		OutboxID: grant.OutboxID, AttemptsBefore: grant.Attempts,
		AttemptLimit: grant.Attempts + 1, Status: StatusPending,
	}
}

func (c *Coordinator) snapshot(ctx context.Context, tenantID string) (uint64, []eventspec.Event, error) {
	var head uint64
	var tenantEvents []eventspec.Event
	err := c.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		var err error
		head, err = c.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return c.log.ReplayTenantThrough(readCtx, tenantID, 1, head, func(ev events.Event) error {
			tenantEvents = append(tenantEvents, ev)
			return nil
		})
	})
	if err != nil {
		return 0, nil, fmt.Errorf("vdec retirement: snapshot event head: %w", err)
	}
	if head == 0 {
		return 0, nil, fmt.Errorf("%w: empty event history", ErrInvalidCommand)
	}
	return head, tenantEvents, nil
}

func (c *Coordinator) dependencyChangedBetween(ctx context.Context, tenantID, keyID string, from, through uint64) (bool, error) {
	changed := false
	eventTypes := append([]string{
		depstate.TypeDependencyRegistered, depstate.TypeDependencyReleased,
		depstate.TypeDependencyErasureDesignated, depstate.TypeReprotectionCompleted,
		depstate.TypeRevocationCompleted,
	}, depstate.CARegistrationEventTypes()...)
	err := c.log.ReplayTenantTypesThrough(ctx, tenantID, from, through,
		eventTypes, func(ev events.Event) error {
			if ev.TenantID != tenantID {
				return nil
			}
			registrations, err := depstate.CARegistrations(ev)
			if err != nil {
				return err
			}
			for _, registration := range registrations {
				if registration.KeyID == keyID {
					changed = true
				}
			}
			switch ev.Type {
			case depstate.TypeDependencyRegistered, depstate.TypeDependencyReleased,
				depstate.TypeDependencyErasureDesignated, depstate.TypeReprotectionCompleted,
				depstate.TypeRevocationCompleted:
			default:
				return nil
			}
			payload, err := depstate.Decode(ev)
			if err != nil {
				return err
			}
			switch value := payload.(type) {
			case depstate.DependencyRegisteredV1:
				changed = changed || value.KeyID == keyID
			case depstate.DependencyReleasedV1:
				changed = changed || value.KeyID == keyID
			case depstate.DependencyReleasedV2:
				changed = changed || value.KeyID == keyID
			case depstate.DependencyReleasedV3:
				changed = changed || value.KeyID == keyID
			case depstate.DependencyErasureDesignatedV1:
				changed = changed || value.KeyID == keyID
			case depstate.ReprotectionCompletedV1:
				changed = changed || value.KeyID == keyID
			case depstate.RevocationCompletedV1:
				changed = changed || value.KeyID == keyID
			}
			return nil
		})
	return changed, err
}

func normalizedApprovals(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func gateDigest(raw []byte) []byte {
	_, digest := RequiredSetAndDigest(raw)
	return digest
}
