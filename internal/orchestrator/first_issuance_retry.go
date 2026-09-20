// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// FirstIssuanceRetryQualifier must prove that the selected issuer can recover
// this exact command. It runs before append while the original row is locked;
// it must not sign, enqueue work, or call an external provider.
type FirstIssuanceRetryQualifier func(context.Context, store.FirstIssuanceRetryCommand) (string, error)

func (o *Orchestrator) RequestFirstIssuanceRetry(ctx context.Context, tenantID, identityID, requestKey, retryKey, reason string, qualify FirstIssuanceRetryQualifier) (store.FirstIssuanceRetryReceipt, error) {
	var receipt store.FirstIssuanceRetryReceipt
	reason = strings.TrimSpace(reason)
	requestKey = strings.TrimSpace(requestKey)
	if tenantID == "" || identityID == "" || requestKey == "" || len(requestKey) > 256 || retryKey == "" || len(retryKey) > 256 || reason == "" || len(reason) > 1024 || qualify == nil {
		return receipt, store.ErrIssuanceRetryUnavailable
	}
	actor, _ := events.ActorFromContext(ctx)
	identity, err := json.Marshal([]any{"first-issuance-retry-v1", tenantID, retryKey, actor})
	if err != nil {
		return receipt, err
	}
	eventID := "issuance-retry:" + crypto.SHA256Hex(identity)
	retained, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return receipt, err
	}
	if found {
		if retained.TenantID != tenantID || retained.Type != projections.EventFirstIssuanceRetryRequested ||
			json.Unmarshal(retained.Data, &receipt) != nil || receipt.EventID != eventID ||
			receipt.IdentityID != identityID || receipt.RequestKey != requestKey || receipt.Reason != reason {
			return store.FirstIssuanceRetryReceipt{}, store.ErrIdempotencyConflict
		}
		// A lost SQL commit after append is completed from the retained grant.
		// Its original attempt fence prevents a later replay from refunding it.
		err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error { return o.proj.ApplyTx(ctx, tx, retained) })
		return receipt, err
	}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		command, err := o.store.FirstIssuanceRetryCommandTx(ctx, tx, tenantID, identityID, requestKey, true)
		if err != nil {
			return err
		}
		if command.Status != "failed" || command.Attempts < 1 || command.Attempts >= 2147483647 ||
			(command.Identity.Status != string(StateIssued) && command.Identity.Status != string(StateDeployed)) {
			return store.ErrIssuanceRetryUnavailable
		}
		proof, err := qualify(ctx, command)
		if err != nil {
			return err
		}
		switch proof {
		case "recorded_certificate", "prepared_signing_operation", "external_issuer_result":
		default:
			return errors.New("orchestrator: unsupported first-issuance recovery proof")
		}
		receipt = store.FirstIssuanceRetryReceipt{
			EventID: eventID, IdentityID: identityID, RequestKey: requestKey,
			OutboxID: command.OutboxID, OriginalPayloadSHA256: crypto.SHA256Hex(command.Payload),
			Attempts: command.Attempts, ProofKind: proof, Reason: reason, RequestedAt: time.Now().UTC(),
		}
		payload, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventFirstIssuanceRetryRequested, TenantID: tenantID, SchemaVersion: 1, Data: payload})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.TenantID != tenantID || event.Type != projections.EventFirstIssuanceRetryRequested || !bytes.Equal(event.Data, payload) {
			return fmt.Errorf("%w: retained first-issuance retry grant differs", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
	return receipt, err
}
