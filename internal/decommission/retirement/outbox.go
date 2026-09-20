// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
)

type outboxPayload struct {
	CommandEventID string      `json:"command_event_id"`
	Requested      RequestedV1 `json:"requested"`
}

type Handler struct {
	log        *events.Log
	projection *Projection
	signer     editionseam.GatedDestruction
}

func NewOutboxFactory(projection *Projection) editionseam.LicensedOutboxFactory {
	return func(deps editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		return &Handler{log: deps.Log, projection: projection, signer: deps.GatedDestruction}, nil
	}
}

func (h *Handler) DeliverLicensed(ctx context.Context, message orchestrator.Message) (bool, error) {
	if message.Destination != DestinationRetirement {
		return false, nil
	}
	if h == nil || h.log == nil || h.projection == nil {
		return true, ErrProjectionMissing
	}
	if h.signer == nil {
		return true, ErrSignerUnavailable
	}
	payload, err := decodeOutboxPayload(message.Payload)
	if err != nil {
		return true, err
	}
	if payload.CommandEventID != message.IdempotencyKey || payload.Requested.TenantID != message.TenantID {
		return true, fmt.Errorf("%w: outbox identity mismatch", ErrInvalidCommand)
	}
	state, found, err := h.projection.Fetch(ctx, message.TenantID, payload.Requested.KeyID)
	if err != nil {
		return true, err
	}
	if !found || state.CommandEventID != payload.CommandEventID {
		// A newer command froze later dependency evidence. This old effect is
		// intentionally complete as a no-op; retrying it can never become safe or
		// change the active projection.
		return true, nil
	}
	if state.Status == StatusRefused || state.Status == StatusDestroyed {
		return true, nil
	}

	tenantEvents, laterRegistration, err := h.replayEvidence(ctx, payload.Requested)
	if err != nil {
		return true, err
	}
	if laterRegistration {
		return true, fmt.Errorf("%w: a dependent was registered after the frozen evidence head", ErrCommandConflict)
	}
	if err := verifyFrozenCommand(payload.Requested, tenantEvents); err != nil {
		return true, err
	}
	segment, err := gate.EncodeLedgerSegment(payload.Requested.FinalEpoch, tenantEvents)
	if err != nil {
		return true, err
	}
	approvals, err := EncodeApprovals(payload.Requested.KeyClass, payload.Requested.Approvals)
	if err != nil {
		return true, err
	}
	finalization, err := EncodeFinalizationContext(payload.CommandEventID, payload.Requested)
	if err != nil {
		return true, err
	}
	decision, err := h.signer.GatedDestroy(ctx, signing.GatedDestroyRequest{
		TenantID: payload.Requested.TenantID, Handle: payload.Requested.SignerHandle,
		SubjectRef: payload.Requested.KeyID, AssertedFinalEpoch: payload.Requested.FinalEpoch,
		LedgerPosition: payload.Requested.LedgerPosition,
		RequiredSet:    payload.Requested.RequiredSet, RequiredSetDigest: payload.Requested.RequiredSetDigest,
		SatisfactionEvidence: segment, Approvals: approvals,
		AuditChainHead: payload.Requested.AuditChainHead, Context: finalization,
	})
	if err != nil {
		return true, err
	}
	if !decision.Approved {
		if len(decision.RefusalRecord) == 0 {
			return true, fmt.Errorf("%w: signer returned an unsigned refusal", ErrInvalidCommand)
		}
		event, err := EncodeRefused(RefusedV1{
			TenantID: payload.Requested.TenantID, KeyID: payload.Requested.KeyID,
			CommandEventID: payload.CommandEventID, FinalEpoch: payload.Requested.FinalEpoch,
			LedgerPosition: payload.Requested.LedgerPosition,
			RefusalRecord:  decision.RefusalRecord, SignerEvidence: decision.Evidence,
		})
		if err != nil {
			return true, err
		}
		event.ID = TerminalEventID(payload.CommandEventID, StatusRefused)
		if _, err := h.appendAndProject(ctx, event); err != nil {
			return true, err
		}
		return true, nil
	}

	signed, err := record.DecodeRecord(decision.Evidence)
	if err != nil {
		return true, fmt.Errorf("%w: signer approval omitted the full record: %v", ErrInvalidCommand, err)
	}
	if err := verifyRecordBinding(payload, signed); err != nil {
		return true, err
	}
	event, err := EncodeRecorded(RecordedV1{
		TenantID: payload.Requested.TenantID, KeyID: payload.Requested.KeyID,
		CommandEventID: payload.CommandEventID, Record: signed,
	})
	if err != nil {
		return true, err
	}
	event.ID = TerminalEventID(payload.CommandEventID, StatusDestroyed)
	_, err = h.appendAndProject(ctx, event)
	return true, err
}

func (h *Handler) replayEvidence(ctx context.Context, requested RequestedV1) ([]eventspec.Event, bool, error) {
	var tenantEvents []eventspec.Event
	err := h.log.ReplayThrough(ctx, 1, requested.LedgerPosition, func(ev events.Event) error {
		if ev.TenantID == requested.TenantID {
			tenantEvents = append(tenantEvents, ev)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	laterRegistration := false
	err = h.log.Replay(ctx, requested.LedgerPosition+1, func(ev events.Event) error {
		if ev.TenantID != requested.TenantID || ev.Type != depstate.TypeDependencyRegistered {
			return nil
		}
		payload, err := depstate.Decode(ev)
		if err != nil {
			return err
		}
		registered, ok := payload.(depstate.DependencyRegisteredV1)
		if ok && registered.KeyID == requested.KeyID {
			laterRegistration = true
		}
		return nil
	})
	return tenantEvents, laterRegistration, err
}

func verifyFrozenCommand(requested RequestedV1, tenantEvents []eventspec.Event) error {
	projection, err := depstate.Fold(tenantEvents)
	if err != nil {
		return err
	}
	state, found := projection.Lookup(requested.TenantID, requested.KeyID)
	if !found {
		return fmt.Errorf("%w: frozen dependency state is absent", ErrInvalidCommand)
	}
	required, err := gate.RequiredSetBytes(state)
	if err != nil {
		return err
	}
	digest, err := gate.RequiredSetDigest(state)
	if err != nil {
		return err
	}
	if !bytes.Equal(required, requested.RequiredSet) || !bytes.Equal(digest, requested.RequiredSetDigest) ||
		!bytes.Equal(gate.AuditChainHead(tenantEvents), requested.AuditChainHead) ||
		!bytes.Equal(CompletionDigest(tenantEvents,
			depstate.TypeReprotectionCompleted, depstate.TypeDependencyReleased,
			depstate.TypeDependencyErasureDesignated, depstate.TypeRevocationCompleted), requested.CompletionEventsDigest) ||
		!bytes.Equal(CompletionDigest(tenantEvents, depstate.TypeRevocationCompleted), requested.RevocationCompletionDigest) {
		return fmt.Errorf("%w: frozen event/audit evidence digest mismatch", ErrInvalidCommand)
	}
	return nil
}

func verifyRecordBinding(payload outboxPayload, signed record.SignedRecord) error {
	c := signed.Commitment
	wantAudit := hex.EncodeToString(payload.Requested.AuditChainHead)
	if c.TenantID != payload.Requested.TenantID || c.StableKeyID != payload.Requested.KeyID ||
		c.FinalEpoch != payload.Requested.FinalEpoch ||
		!bytes.Equal(c.CompletionEventsDigest, payload.Requested.CompletionEventsDigest) ||
		!bytes.Equal(c.RequiredSetDigest, payload.Requested.RequiredSetDigest) ||
		!bytes.Equal(c.RevocationCompletionDigest, payload.Requested.RevocationCompletionDigest) ||
		c.AuditChainHead != wantAudit {
		return fmt.Errorf("%w: destruction record is not bound to the exact command", ErrInvalidCommand)
	}
	return nil
}

func (h *Handler) appendAndProject(ctx context.Context, wanted events.Event) (events.Event, error) {
	canonical, found, err := h.log.EventByID(ctx, wanted.ID)
	if err != nil {
		return events.Event{}, err
	}
	if !found {
		canonical, err = h.log.Append(ctx, wanted)
		if err != nil {
			return events.Event{}, err
		}
	}
	if canonical.ID != wanted.ID || canonical.Type != wanted.Type || canonical.TenantID != wanted.TenantID ||
		canonical.SchemaVersion != wanted.SchemaVersion || !bytes.Equal(canonical.Data, wanted.Data) {
		// A prior terminal event wins. Project and return it when it is the exact
		// command's valid terminal fact; never overwrite retained evidence.
		if canonical.ID != wanted.ID || canonical.Type != wanted.Type || canonical.TenantID != wanted.TenantID {
			return events.Event{}, ErrCommandConflict
		}
	}
	if err := h.projection.Apply(ctx, canonical); err != nil {
		return events.Event{}, err
	}
	return canonical, nil
}

func decodeOutboxPayload(raw []byte) (outboxPayload, error) {
	var payload outboxPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return outboxPayload{}, fmt.Errorf("%w: decode outbox command: %v", ErrInvalidCommand, err)
	}
	payload.CommandEventID = strings.TrimSpace(payload.CommandEventID)
	if payload.CommandEventID == "" {
		return outboxPayload{}, ErrInvalidCommand
	}
	if err := payload.Requested.Validate(); err != nil {
		return outboxPayload{}, err
	}
	return payload, nil
}
