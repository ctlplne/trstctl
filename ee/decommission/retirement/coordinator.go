// SPDX-License-Identifier: LicenseRef-trstctl-EE

package retirement

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/gate"
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
	if !found {
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

func (c *Coordinator) snapshot(ctx context.Context, tenantID string) (uint64, []eventspec.Event, error) {
	var head uint64
	var tenantEvents []eventspec.Event
	err := c.log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.Sequence > head {
			head = ev.Sequence
		}
		if ev.TenantID == tenantID {
			tenantEvents = append(tenantEvents, ev)
		}
		return nil
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
	err := c.log.ReplayThrough(ctx, from, through, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
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
