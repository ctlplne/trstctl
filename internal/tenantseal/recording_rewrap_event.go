// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var recordingRewrapEventNamespace = uuid.MustParse("0e1662df-3904-4c21-af55-d547bb2ae7b1")

// appendRecordingRewrap gives the PostgreSQL header an immutable source in
// JetStream. A retry projects the original event with the same ID, including
// after an append succeeded but its SQL projection was interrupted.
func appendRecordingRewrap(ctx context.Context, st *store.Store, log *events.Log, projector *projections.Projector,
	operationID, grantID string, c store.PAMRecordingChunk, header []byte) error {
	if _, err := uuid.Parse(operationID); err != nil || st == nil || log == nil || projector == nil {
		return errors.New("tenantseal: recording rewrap operation is not configured")
	}
	if _, err := uuid.Parse(grantID); err != nil {
		return errors.New("tenantseal: recording rewrap grant is not configured")
	}
	id := uuid.NewSHA1(recordingRewrapEventNamespace,
		[]byte(operationID+"\x00"+c.TenantID+"\x00"+c.SessionID+"\x00"+strconv.Itoa(c.Ord))).String()
	pl := projections.PAMRecordingChunkRewrapped{ID: c.SessionID, Ord: c.Ord,
		ObjectSHA256: c.SealedSHA256, HeaderHex: hex.EncodeToString(header), OperationID: operationID}
	data, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	if previous, found, err := log.EventByID(ctx, id); err != nil {
		return err
	} else if found {
		if previous.Type != projections.EventPAMRecordingChunkRewrapped || previous.TenantID != c.TenantID {
			return errors.New("tenantseal: recording rewrap event ID conflicts")
		}
		var original projections.PAMRecordingChunkRewrapped
		if json.Unmarshal(previous.Data, &original) != nil || original.ID != c.SessionID ||
			original.Ord != c.Ord || original.ObjectSHA256 != c.SealedSHA256 || original.OperationID != operationID {
			return errors.New("tenantseal: recording rewrap event binding conflicts")
		}
		data = previous.Data
	}
	return st.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive, func(admitted context.Context) error {
		return log.WithHistoryRead(admitted, func(history context.Context) error {
			return st.WithTenantEvent(history, c.TenantID, func(history context.Context, tx pgx.Tx) error {
				owned, err := st.BindKeyStateOwnerTx(history, tx, c.TenantID, store.KeyStateExclusive)
				if err != nil {
					return err
				}
				if err := st.LockTenantKeyDomainExclusiveTx(owned, tx, c.TenantID); err != nil {
					return err
				}
				return st.WithRewrapCoordinatorEvent(owned, tx, c.TenantID, grantID,
					projections.EventPAMRecordingChunkRewrapped, func(granted context.Context) error {
						e, err := log.Append(granted, events.Event{ID: id, Type: projections.EventPAMRecordingChunkRewrapped,
							TenantID: c.TenantID, SchemaVersion: 1, Data: data})
						if err != nil {
							return err
						}
						return projector.ApplyTx(granted, tx, e)
					})
			})
		})
	})
}
