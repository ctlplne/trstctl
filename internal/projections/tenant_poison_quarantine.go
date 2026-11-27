// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/inputtext"
	"trstctl.com/trstctl/internal/risk"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/delegation"
)

// tenantPoisonQuarantine caches positive durable lookups during an ordered
// replay. A healthy answer is checked again on the next event, because a peer
// projector may quarantine that tenant between events. Only known,
// deterministic text, workload-target uniqueness, or signed PCAS floor range
// failures are quarantined;
// transport, custody, and unknown projection errors still stop replay.
type tenantPoisonQuarantine struct {
	store                    *store.Store
	known                    map[string]bool
	lastAppliedEventSequence uint64
}

func newTenantPoisonQuarantine(st *store.Store) *tenantPoisonQuarantine {
	return &tenantPoisonQuarantine{store: st, known: make(map[string]bool)}
}

func (q *tenantPoisonQuarantine) skip(ctx context.Context, e events.Event) (bool, error) {
	return q.skipWithReplayTx(ctx, e, nil)
}

func (q *tenantPoisonQuarantine) skipForExtensions(ctx context.Context, e events.Event) (bool, error) {
	skip, err := q.skip(ctx, e)
	if err == nil && q.lastAppliedEventSequence == e.Sequence && e.Sequence != 0 {
		return false, nil
	}
	return skip, err
}

func (q *tenantPoisonQuarantine) skipWithReplayTx(ctx context.Context, e events.Event, tx pgx.Tx) (bool, error) {
	q.lastAppliedEventSequence = 0
	// Historical Provider audit has a textual pre-UUID partition. It is not a
	// customer tenant and must keep its existing replay path. There is no
	// tenant-scoped quarantine row to write for this legacy scope.
	if events.IsLegacyProviderGlobalAudit(e) {
		return false, events.ValidateEventText(e)
	}
	quarantined, seen := q.known[e.TenantID]
	if !seen {
		var err error
		if tx == nil {
			quarantined, err = q.store.ProjectionTenantQuarantined(ctx, e.TenantID)
		} else {
			quarantined, err = q.store.ProjectionTenantQuarantinedTx(ctx, tx, e.TenantID)
		}
		if err != nil {
			return false, err
		}
		if quarantined {
			q.known[e.TenantID] = true
		}
	}
	if quarantined {
		// A tenant's served read model is unavailable, but erasure, key
		// destruction, and other custody changes still need replay. If one
		// cannot be projected safely, stop instead of pretending it ran.
		if isKeyStateMutationEventType(e.Type) {
			if err := events.ValidateEventText(e); err != nil {
				return false, err
			}
			if e.Type == EventTenantOffboarded {
				// OffboardTenant deletes the durable marker. A later registration
				// of the same UUID must query it again rather than inherit this
				// replay worker's positive cache from the prior lifecycle.
				delete(q.known, e.TenantID)
			}
			return false, nil
		}
		return true, nil
	}
	textErr := events.ValidateEventText(e)
	if textErr == nil {
		if e.SchemaVersion == 1 && (e.Type == EventWindowsLocalAccountScanFailed ||
			e.Type == EventServiceDependentScanFailed) &&
			ValidateNativeAgentReceipt(e.Type, e.Data) != nil {
			if err := q.record(ctx, tx, e.TenantID, e.Sequence, "native_failure_receipt_invalid"); err != nil {
				return false, err
			}
			q.known[e.TenantID] = true
			return true, nil
		}
		if e.Type == EventAgentHeartbeat && schemaVersionOf(e) <= AgentHeartbeatRelayEgressSchemaVersion {
			var heartbeat AgentHeartbeat
			if err := json.Unmarshal(e.Data, &heartbeat); err == nil &&
				ValidateAgentHeartbeat(schemaVersionOf(e), e.TenantID, heartbeat) != nil {
				if err := q.record(ctx, tx, e.TenantID, e.Sequence, "agent_heartbeat_invalid"); err != nil {
					return false, err
				}
				q.known[e.TenantID] = true
				return true, nil
			}
		}
		if e.Type == EventDiscoveryFindingRecorded && schemaVersionOf(e) <= DiscoveryAttackPathFindingSchemaVersion {
			var finding DiscoveryAttackPathFindingRecorded
			if err := json.Unmarshal(e.Data, &finding); err == nil {
				metadata := bytes.TrimSpace(finding.Metadata)
				// This is a replay-only guard for an old natural key that cannot
				// fit PostgreSQL's btree entry. Admission uses tighter per-field
				// limits. Do not quarantine already accepted historical metadata
				// merely because it exceeds today's admission policy.
				if len(finding.Kind)+len(finding.Ref)+len(finding.Fingerprint) > 2300 ||
					(len(metadata) > 0 && metadata[0] != '{' && string(metadata) != "null" &&
						(risk.DiscoveryUrgency(finding.RiskScore) != "" ||
							(finding.Kind == "ssh_key" && finding.Fingerprint != ""))) {
					if err := q.record(ctx, tx, e.TenantID, e.Sequence, "discovery_finding_unprojectable"); err != nil {
						return false, err
					}
					q.known[e.TenantID] = true
					return true, nil
				}
			}
		}
		if tx == nil && e.Type != EventTenantOffboarded && uuid.Validate(e.TenantID) == nil {
			// A protected offboard can commit inline ahead of this replay. Its
			// exact pending destruction row proves all earlier tenant rows and
			// effects were erased in that commit. Reapplying them would create
			// residue that the offboard's strict retry must refuse. The offboard
			// itself still runs and verifies the sole pending row and no residue.
			skip, err := q.store.PendingEventKeyDestructionAfter(ctx, e.TenantID, e.Sequence)
			if err != nil || skip {
				return skip, err
			}
		}
		if e.Type == succession.TypeDelegationApplied {
			if e.SchemaVersion > succession.DelegationAppliedSchemaV1 {
				return false, nil // a future envelope belongs to its versioned projector
			}
			var payload succession.DelegationAppliedV1
			if err := json.Unmarshal(e.Data, &payload); err == nil && payload.TenantID == e.TenantID {
				var receipt delegation.Receipt
				if json.Unmarshal(payload.ReceiptJSON, &receipt) == nil && receipt.TenantID == e.TenantID &&
					receipt.OperationID != "" && receipt.ScopeID != "" && receipt.ScopeID != receipt.ParentScopeID &&
					(receipt.Kind == "scope" || receipt.Kind == "floor") &&
					receipt.AppliedFloor == receipt.EpochFloor && receipt.AppliedFloor > delegation.MaxEpochFloor && receipt.Verify() == nil {
					if err := q.record(ctx, tx, e.TenantID, e.Sequence, "pcas_delegation_floor_out_of_range"); err != nil {
						return false, err
					}
					q.known[e.TenantID] = true
					return true, nil
				}
			}
			return false, nil
		}
		if e.Type != EventSecretSyncWorkloadIdentityUpserted {
			return false, nil
		}
		var source SecretSyncWorkloadIdentitySourceUpserted
		if err := json.Unmarshal(e.Data, &source); err != nil || source.ID == "" || source.Provider == "" || source.TargetID == "" {
			// Leave malformed payloads to the normal schema projector. Only an
			// exact occupied target is a known, tenant-confined failure.
			return false, nil
		}
		var owner string
		var err error
		if tx == nil {
			owner, err = q.store.SecretSyncWorkloadIdentitySourceTargetOwner(ctx, e.TenantID, source.Provider, source.TargetID)
		} else {
			owner, err = q.store.SecretSyncWorkloadIdentitySourceTargetOwnerTx(ctx, tx, e.TenantID, source.Provider, source.TargetID)
		}
		if err != nil || owner == "" || owner == source.ID {
			return false, err
		}
		var applied bool
		if tx == nil {
			applied, err = q.store.ProjectionAppliedEventReceipt(ctx, e.TenantID, e.ID, e.Sequence)
		} else {
			applied, err = q.store.ProjectionAppliedEventReceiptTx(ctx, tx, e.TenantID, e.ID, e.Sequence)
		}
		if err != nil {
			return false, err
		}
		if applied {
			// This exact core event committed before the target changed. Its
			// extension projections still receive the replayed envelope.
			q.lastAppliedEventSequence = e.Sequence
			return true, nil
		}
		if err := q.record(ctx, tx, e.TenantID, e.Sequence, "workload_source_target_conflict"); err != nil {
			return false, err
		}
		q.known[e.TenantID] = true
		return true, nil
	}
	if isKeyStateMutationEventType(e.Type) {
		return false, fmt.Errorf("projections: key-state event %d cannot be quarantined: %w", e.Sequence, textErr)
	}
	reasonCode := ""
	switch {
	case errors.Is(textErr, inputtext.ErrNUL):
		reasonCode = "nul_text"
	case errors.Is(textErr, inputtext.ErrInvalidUTF8):
		reasonCode = "invalid_utf8"
	case errors.Is(textErr, inputtext.ErrInvalidUnicodeEscape):
		reasonCode = "json_unicode_escape"
	case errors.Is(textErr, inputtext.ErrJSONNumberRange):
		reasonCode = "json_number_range"
	default:
		return false, textErr
	}
	if err := q.record(ctx, tx, e.TenantID, e.Sequence, reasonCode); err != nil {
		return false, err
	}
	q.known[e.TenantID] = true
	return true, nil
}

func (q *tenantPoisonQuarantine) record(ctx context.Context, tx pgx.Tx, tenantID string, seq uint64, reasonCode string) error {
	if tx != nil {
		return q.store.RecordProjectionTenantQuarantineTx(ctx, tx, tenantID, seq, reasonCode)
	}
	return q.store.RecordProjectionTenantQuarantine(ctx, tenantID, seq, reasonCode)
}

// confineApplyFailure records a deterministic read-model rejection under the
// event's tenant. Transport, datastore availability, and key-custody failures
// still stop replay so they cannot be mistaken for tenant data errors.
func (q *tenantPoisonQuarantine) confineApplyFailure(ctx context.Context, tx pgx.Tx, e events.Event, applyErr error) (bool, error) {
	var networkErr net.Error
	if isKeyStateMutationEventType(e.Type) || events.IsLegacyProviderGlobalAudit(e) ||
		uuid.Validate(e.TenantID) != nil || e.Sequence == 0 ||
		errors.Is(applyErr, context.Canceled) || errors.Is(applyErr, context.DeadlineExceeded) ||
		errors.Is(applyErr, io.EOF) || errors.Is(applyErr, io.ErrUnexpectedEOF) ||
		errors.Is(applyErr, pgx.ErrTxClosed) || errors.As(applyErr, &networkErr) ||
		errors.Is(applyErr, store.ErrDatastoreBusy) ||
		errors.Is(applyErr, store.ErrRestoreInProgress) ||
		errors.Is(applyErr, store.ErrRestoreActivityUnresolved) ||
		errors.Is(applyErr, store.ErrRestoreAdmissionLost) ||
		errors.Is(applyErr, store.ErrKeyStateOwnerUnavailable) ||
		errors.Is(applyErr, ErrCanonicalEventRequired) {
		return false, nil
	}
	var pgErr *pgconn.PgError
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	projectableDataError := errors.As(applyErr, &typeErr) || errors.As(applyErr, &syntaxErr) ||
		errors.Is(applyErr, store.ErrNotificationRoutingIdentityConflict)
	if errors.As(applyErr, &pgErr) {
		// Data exceptions and integrity constraints are stable for the same
		// event and read-model state. Connection, resource, and transaction
		// failures remain retryable and must stop the ordered replay.
		projectableDataError = len(pgErr.Code) >= 2 && (pgErr.Code[:2] == "22" || pgErr.Code[:2] == "23")
	}
	if !projectableDataError {
		return false, nil
	}
	if err := q.record(ctx, tx, e.TenantID, e.Sequence, "projection_rejected"); err != nil {
		return false, err
	}
	q.known[e.TenantID] = true
	return true, nil
}

func (q *tenantPoisonQuarantine) apply(ctx context.Context, e events.Event, step func() error) error {
	return q.finishApply(ctx, e, step())
}

func (q *tenantPoisonQuarantine) finishApply(ctx context.Context, e events.Event, applyErr error) error {
	if applyErr == nil {
		return nil
	}
	confined, err := q.confineApplyFailure(ctx, nil, e, applyErr)
	if err != nil {
		return errors.Join(applyErr, err)
	}
	if confined {
		return nil
	}
	return applyErr
}
