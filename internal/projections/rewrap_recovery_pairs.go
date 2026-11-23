// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func receiptVerifierFromPair(pair func(context.Context, string, []byte, []byte, []byte) (bool, error)) func(context.Context, string, ApplicationSecretMutation) error {
	return func(ctx context.Context, tenantID string, mutation ApplicationSecretMutation) error {
		check := func(sealed, aad []byte) error {
			if len(sealed) == 0 {
				return nil
			}
			if same, err := pair(ctx, tenantID, sealed, sealed, aad); err != nil || !same {
				return fmt.Errorf("%w: recovery receipt container did not authenticate", store.ErrIdempotencyConflict)
			}
			return nil
		}
		if err := check(mutation.Sealed, []byte(tenantID+"/secret-store/"+mutation.Name)); err != nil {
			return err
		}
		if mutation.Sync != nil {
			sync := mutation.Sync
			if sync.ID == "" || sync.Target == "" || sync.RemoteKey == "" || len(sync.Sealed) == 0 {
				return store.ErrIdempotencyConflict
			}
			return check(sync.Sealed, []byte(tenantID+"/secret-sync/"+sync.Target+"/"+sync.ID+"/"+sync.RemoteKey))
		}
		return nil
	}
}

// preverifyRewrappedSyncOutbox proves every differing event/outbox container
// while the pretruncate owner transaction can still read the old authority.
// The replay consumes only exact hashes of the event, row and staged key state.
func (p *Projector) preverifyRewrappedSyncOutbox(ctx context.Context, tx pgx.Tx, log *events.Log,
	head uint64, operationID string,
	pair func(context.Context, string, []byte, []byte, []byte) (bool, error),
) error {
	return replayProjectionThrough(ctx, log, 1, head, func(event events.Event) error {
		var sync *SecretSyncQueued
		switch event.Type {
		case EventSecretSyncQueued:
			var command SecretSyncQueued
			if err := decode(event, &command); err != nil {
				return err
			}
			sync = &command
		case EventApplicationSecretCreated, EventApplicationSecretRotated,
			EventApplicationSecretRecovered, EventApplicationSecretDeleted,
			EventApplicationSecretUndeleted:
			mutation, err := retainedApplicationSecretMutationForProof(event)
			if err != nil {
				return err
			}
			sync = mutation.Sync
		default:
			return nil
		}
		if sync == nil || sync.ID == "" || sync.Target == "" || sync.RemoteKey == "" || sync.IdempotencyKey == "" {
			return nil
		}
		var id int64
		var rowImage string
		var payload []byte
		err := tx.QueryRow(ctx, `SELECT id,to_jsonb(o)::text,payload FROM outbox AS o
			WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3`,
			event.TenantID, sync.IdempotencyKey, "secret.sync."+sync.Target).
			Scan(&id, &rowImage, &payload)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		var binding struct {
			ID             string `json:"id"`
			Key            string `json:"key"`
			Target         string `json:"target"`
			RequestBinding string `json:"request_binding,omitempty"`
			Sealed         []byte `json:"sealed"`
		}
		if err := json.Unmarshal(payload, &binding); err != nil ||
			binding.ID != sync.ID || binding.Key != sync.RemoteKey ||
			binding.Target != sync.Target || binding.RequestBinding != sync.RequestBinding {
			return fmt.Errorf("%w: recovery outbox payload differs from event", store.ErrIdempotencyConflict)
		}
		if bytes.Equal(binding.Sealed, sync.Sealed) {
			return nil
		}
		if pair == nil {
			return fmt.Errorf("%w: recovery outbox custody is unavailable", store.ErrIdempotencyConflict)
		}
		aad := []byte(event.TenantID + "/secret-sync/" + sync.Target + "/" + sync.ID + "/" + sync.RemoteKey)
		same, err := pair(ctx, event.TenantID, binding.Sealed, sync.Sealed, aad)
		if err != nil || !same {
			return fmt.Errorf("%w: recovery outbox ciphertext did not authenticate", store.ErrIdempotencyConflict)
		}
		eventHash, err := recoveryEventSHA256(event)
		if err != nil {
			return err
		}
		keyHash, err := p.store.RecoveryKeyStateDigestTx(ctx, tx, event.TenantID, operationID)
		if err != nil {
			return err
		}
		return p.store.InsertRecoveryPairProofTx(ctx, tx, store.RecoveryPairProof{
			TenantID: event.TenantID, OperationID: operationID, EventID: event.ID,
			PairKind: "sync_outbox", RowID: strconv.FormatInt(id, 10),
			EventSHA256: eventHash, RowSHA256: crypto.SHA256Hex([]byte(rowImage)),
			KeyStateSHA256: keyHash,
		})
	})
}

// preverifyRewrappedSourcePairs covers recover and undelete events that were
// appended before rewrap but had no receipt yet. Their source rows are retained
// across rebuild, so replay can consume an exact one-use proof without opening
// ciphertext after the key-domain read model has been truncated.
func (p *Projector) preverifyRewrappedSourcePairs(ctx context.Context, tx pgx.Tx, log *events.Log,
	head uint64, operationID string,
	pair func(context.Context, string, []byte, []byte, []byte) (bool, error),
) error {
	return replayProjectionThrough(ctx, log, 1, head, func(event events.Event) error {
		if event.Type != EventApplicationSecretRecovered && event.Type != EventApplicationSecretUndeleted {
			return nil
		}
		mutation, err := retainedApplicationSecretMutationForProof(event)
		if err != nil {
			return err
		}
		if mutation.SourceVersion <= 0 || mutation.SourceWrittenAt.IsZero() || len(mutation.Sealed) == 0 {
			return fmt.Errorf("%w: recovery source event is incomplete", store.ErrIdempotencyConflict)
		}
		var receiptExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_secret_mutation_receipts
			WHERE tenant_id=$1 AND event_id=$2)`, event.TenantID, event.ID).Scan(&receiptExists); err != nil {
			return err
		}
		if receiptExists {
			return nil
		}
		var rowImage string
		var sourceSealed []byte
		var sourceTime time.Time
		pairKind := "recover_source"
		if event.Type == EventApplicationSecretRecovered {
			err = tx.QueryRow(ctx, `SELECT to_jsonb(v)::text,v.sealed,v.written_at FROM secret_store_versions AS v
				WHERE v.tenant_id=$1 AND v.name=$2 AND v.version=$3`,
				event.TenantID, mutation.Name, mutation.SourceVersion).Scan(&rowImage, &sourceSealed, &sourceTime)
		} else {
			pairKind = "undelete_tombstone"
			err = tx.QueryRow(ctx, `SELECT jsonb_build_object('version',to_jsonb(v),'tombstone',to_jsonb(t))::text,
				v.sealed,t.deleted_at FROM secret_store_tombstone_versions AS v
				JOIN secret_store_tombstones AS t ON t.tenant_id=v.tenant_id AND t.name=v.name
				WHERE v.tenant_id=$1 AND v.name=$2 AND v.version=$3 AND t.version=$3`,
				event.TenantID, mutation.Name, mutation.SourceVersion).Scan(&rowImage, &sourceSealed, &sourceTime)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			// On a fresh restore target the source row can be produced by an
			// earlier replay event. Re-read that exact pinned prefix without
			// retaining an unbounded map of every secret in history.
			sourceSealed, err = sourceCopyFromHistory(ctx, log, event, mutation)
			if err != nil {
				return err
			}
			if len(sourceSealed) == 0 {
				return nil // an offboarded historical lifecycle has no retained source
			}
			sourceTime = mutation.SourceWrittenAt
			rowImage = "history:"
			err = nil
		}
		if err != nil {
			return err
		}
		if !sourceTime.Equal(mutation.SourceWrittenAt) {
			return fmt.Errorf("%w: recovery source timestamp differs", store.ErrIdempotencyConflict)
		}
		if bytes.Equal(sourceSealed, mutation.Sealed) {
			return nil
		}
		if pair == nil {
			return fmt.Errorf("%w: recovery source custody is unavailable", store.ErrIdempotencyConflict)
		}
		same, err := pair(ctx, event.TenantID, sourceSealed, mutation.Sealed,
			[]byte(event.TenantID+"/secret-store/"+mutation.Name))
		if err != nil || !same {
			return fmt.Errorf("%w: recovery source ciphertext did not authenticate", store.ErrIdempotencyConflict)
		}
		eventHash, err := recoveryEventSHA256(event)
		if err != nil {
			return err
		}
		keyHash, err := p.store.RecoveryKeyStateDigestTx(ctx, tx, event.TenantID, operationID)
		if err != nil {
			return err
		}
		rowID := fmt.Sprintf("%s:%d", mutation.Name, mutation.SourceVersion)
		rowHash := crypto.SHA256Hex([]byte(rowImage))
		if rowImage == "history:" {
			rowID = "history:" + rowID
			rowHash = crypto.SHA256Hex(sourceSealed)
		}
		return p.store.InsertRecoveryPairProofTx(ctx, tx, store.RecoveryPairProof{
			TenantID: event.TenantID, OperationID: operationID, EventID: event.ID,
			PairKind: pairKind, RowID: rowID,
			EventSHA256: eventHash, RowSHA256: rowHash,
			KeyStateSHA256: keyHash,
		})
	})
}

// sourceCopyFromHistory keeps only one name/version candidate while scanning
// the pinned prefix. A delete retains the current version as a tombstone;
// registration/offboard boundaries reset that lifecycle's source authority.
func sourceCopyFromHistory(ctx context.Context, log *events.Log, target events.Event,
	mutation ApplicationSecretMutation,
) ([]byte, error) {
	if target.Sequence <= 1 {
		return nil, nil
	}
	var candidate, current, tombstone, tombstoneVersionCopy []byte
	var candidateTime, tombstoneTime, tombstoneVersionTime time.Time
	var currentVersion int
	active := false
	err := replayProjectionThrough(ctx, log, 1, target.Sequence-1, func(event events.Event) error {
		if event.TenantID != target.TenantID {
			return nil
		}
		switch event.Type {
		case EventTenantRegistered, EventTenantOffboarded:
			candidate, current, tombstone, tombstoneVersionCopy = nil, nil, nil, nil
			candidateTime, tombstoneTime, tombstoneVersionTime = time.Time{}, time.Time{}, time.Time{}
			currentVersion = 0
			active = event.Type == EventTenantRegistered
			return nil
		case EventApplicationSecretCreated, EventApplicationSecretRotated,
			EventApplicationSecretRecovered, EventApplicationSecretDeleted,
			EventApplicationSecretUndeleted:
		default:
			return nil
		}
		if !active {
			return nil
		}
		prior, err := retainedApplicationSecretMutationForProof(event)
		if err != nil {
			return err
		}
		if prior.Name != mutation.Name {
			return nil
		}
		switch prior.Action {
		case "create", "rotate", "recover":
			current, currentVersion = prior.Sealed, prior.ResultVersion
			if prior.ResultVersion == mutation.SourceVersion {
				// PostgreSQL timestamptz stores microseconds. The source event
				// retains nanoseconds, while SourceWrittenAt was read back from
				// the projected version row before the rewrap. Compare the exact
				// database representation, not the lost sub-microsecond tail.
				candidate, candidateTime = prior.Sealed, time.UnixMicro(event.Time.UnixMicro())
			}
		case "delete":
			if currentVersion == prior.ExpectedVersion {
				tombstone, tombstoneTime = current, time.UnixMicro(event.Time.UnixMicro())
				tombstoneVersionCopy, tombstoneVersionTime = candidate, candidateTime
			}
			candidate, current = nil, nil
			candidateTime = time.Time{}
			currentVersion = 0
		case "undelete":
			if !tombstoneTime.Equal(prior.SourceWrittenAt) || prior.ResultVersion != prior.SourceVersion {
				return fmt.Errorf("%w: history undelete source is not the exact tombstone", store.ErrIdempotencyConflict)
			}
			current, currentVersion = tombstone, prior.ResultVersion
			candidate, candidateTime = tombstoneVersionCopy, tombstoneVersionTime
			tombstone, tombstoneVersionCopy = nil, nil
			tombstoneTime, tombstoneVersionTime = time.Time{}, time.Time{}
		}
		return nil
	})
	if err != nil || !active {
		return nil, err
	}
	if mutation.Action == "undelete" {
		if tombstoneTime.Equal(mutation.SourceWrittenAt) && currentVersion == 0 && len(tombstone) > 0 {
			return tombstone, nil
		}
		return nil, fmt.Errorf("%w: no exact history tombstone source", store.ErrIdempotencyConflict)
	}
	if !candidateTime.Equal(mutation.SourceWrittenAt) || len(candidate) == 0 {
		return nil, fmt.Errorf("%w: no exact history version source", store.ErrIdempotencyConflict)
	}
	return candidate, nil
}
