// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A stored event may project before the uploader deletes its staged row. The
// next chunk must see one accepted predecessor during that overlap.
func TestRecordingPlacementCountsInFlightStoredChunkOnce(t *testing.T) {
	db := newServerTestStore(t)
	ctx := context.Background()
	tenantID, sessionID, agentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	sum := strings.Repeat("a", 64)
	chain := strings.Repeat("b", 64)
	now := time.Now().UTC()
	if err := db.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := db.ApplyPAMRecordingChunkStoredTx(ctx, tx, store.PAMRecordingChunk{
			TenantID: tenantID, SessionID: sessionID, Ord: 0, Attempt: 1, Seq: 0,
			ObjectRef: "recordings/first", SHA256: sum, SealedSHA256: sum,
			Chain: chain, Size: 5, StoredAt: now,
		}, agentID, false); err != nil {
			return err
		}
		return db.InsertPAMRecordingUploadTx(ctx, tx, store.PAMRecordingUpload{
			TenantID: tenantID, SessionID: sessionID, GatewayAgentID: agentID,
			Ord: 0, Attempt: 1, Seq: 0, SHA256: sum, SealedSHA256: sum,
			Chain: chain, Size: 5, Sealed: []byte("ready"), StagedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	service := &pamService{store: db}
	var place recordingPlace
	if err := db.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		place, err = service.placeRecordingChunk(ctx, tx, tenantID, sessionID, 1, 1, strings.Repeat("c", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if place.ord != 1 || place.chainHead != chain {
		t.Fatalf("next chunk after stored/staged overlap got place %+v, want ordinal 1 and the predecessor chain", place)
	}
}
