// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A278 part 3: recording uploads go through the outbox with backpressure. A
// gateway's chunk is sealed and staged, with an outbox entry, in one
// transaction, and the upload RPC returns at once — a slow object store never
// holds the agent channel the gateway also heartbeats and claims on. A bounded
// in-process uploader stores the session's staged chunks in order right away;
// the outbox entry is the durable guarantee that they are stored even if this
// process stops. Staged bytes are bounded per session and per tenant: past
// the bound the upload is refused as retryable, the gateway keeps the chunk in
// its spool and retries, and only that session's traffic waits — nothing is
// dropped, and nothing is given up: a chunk's delivery defers rather than
// dead-letters.

const (
	pamRecordingStoreDestination = "pam.recording.store"
	// defaultPAMRecordingStagingBytes bounds one session's staged chunks; a
	// tenant may stage sixteen sessions' worth.
	defaultPAMRecordingStagingBytes = 16 << 20
	pamRecordingTenantStagingFactor = 16
	// pamRecordingUploaders bounds the sessions stored eagerly at once; the
	// outbox worker covers any session this process does not reach.
	pamRecordingUploaders = 8
	// pamRecordingStoreTimeout bounds one object write by the eager uploader.
	pamRecordingStoreTimeout = 30 * time.Second
)

var (
	// errRecordingBackpressure refuses a chunk while the session (or its
	// tenant) has too much waiting for the object store; the gateway retries.
	errRecordingBackpressure = errors.New("server: the session's recording uploads are waiting for the object store; retry")
	errRecordingChunkKnown   = errors.New("server: the recording chunk was already accepted")
	errRecordingPlaceMoved   = errors.New("server: the session's recording place moved")
)

// pamRecordingUploadRef is a staged chunk's outbox payload: its place by
// attempt and sequence. The sealed bytes stay in the staged row.
type pamRecordingUploadRef struct {
	SessionID string `json:"session_id"`
	Attempt   int    `json:"attempt"`
	Seq       int    `json:"seq"`
}

func pamRecordingUploadKey(sessionID string, attempt, seq int) string {
	return "pam-recording:" + sessionID + ":" + strconv.Itoa(attempt) + ":" + strconv.Itoa(seq)
}

func recordingStagingBytesOrDefault(n int64) int64 {
	if n <= 0 {
		return defaultPAMRecordingStagingBytes
	}
	return n
}

// pamRecordingUploader is the eager, bounded, per-process uploader.
type pamRecordingUploader struct {
	slots    chan struct{}
	sessions sync.Map // tenant\x00session -> *sync.Mutex
}

func newPAMRecordingUploader() *pamRecordingUploader {
	return &pamRecordingUploader{slots: make(chan struct{}, pamRecordingUploaders)}
}

func (u *pamRecordingUploader) lock(tenantID, sessionID string) *sync.Mutex {
	m, _ := u.sessions.LoadOrStore(tenantID+"\x00"+sessionID, &sync.Mutex{})
	return m.(*sync.Mutex)
}

type recordingPlace struct {
	ord       int
	chainHead string
}

// placeRecordingChunk finds where a chunk goes: after every stored and
// staged chunk of the session. A retry of an accepted chunk is
// errRecordingChunkKnown; a different chunk in an accepted place, or one out
// of order, is refused.
func (s *pamService) placeRecordingChunk(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, attempt, seq int, sumHex string) (recordingPlace, error) {
	stored, err := s.store.ListPAMRecordingChunksTx(ctx, tx, tenantID, sessionID)
	if err != nil {
		return recordingPlace{}, err
	}
	staged, err := s.store.ListPAMRecordingUploadsTx(ctx, tx, tenantID, sessionID)
	if err != nil {
		return recordingPlace{}, err
	}
	type accepted struct {
		attempt, seq int
		sum, chain   string
	}
	all := make([]accepted, 0, len(stored)+len(staged))
	for _, c := range stored {
		all = append(all, accepted{c.Attempt, c.Seq, c.SHA256, c.Chain})
	}
	for _, u := range staged {
		all = append(all, accepted{u.Attempt, u.Seq, u.SHA256, u.Chain})
	}
	next := 0
	for _, c := range all {
		if c.attempt != attempt {
			continue
		}
		if c.seq == seq {
			if c.sum != sumHex {
				return recordingPlace{}, fmt.Errorf("chunk %d of attempt %d was already accepted with other content", seq, attempt)
			}
			return recordingPlace{}, errRecordingChunkKnown
		}
		if c.seq >= next {
			next = c.seq + 1
		}
	}
	if seq != next {
		return recordingPlace{}, fmt.Errorf("chunk %d of attempt %d is out of order (expected %d)", seq, attempt, next)
	}
	place := recordingPlace{ord: len(all)}
	if len(all) > 0 {
		place.chainHead = all[len(all)-1].chain
	}
	return place, nil
}

// stageRecordingChunk records one sealed chunk and its outbox entry at the
// place it was sealed for, refusing it as retryable past the staging bound.
func (s *pamService) stageRecordingChunk(ctx context.Context, u store.PAMRecordingUpload, place recordingPlace) error {
	limit := recordingStagingBytesOrDefault(s.recordingStagingBytes)
	return s.store.WithTenant(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := store.LockPAMRecordingSessionTx(ctx, tx, u.TenantID, u.SessionID); err != nil {
			return err
		}
		now, err := s.placeRecordingChunk(ctx, tx, u.TenantID, u.SessionID, u.Attempt, u.Seq, u.SHA256)
		if err != nil {
			return err
		}
		if now != place {
			return errRecordingPlaceMoved
		}
		session, tenant, err := s.store.PAMRecordingStagedBytesTx(ctx, tx, u.TenantID, u.SessionID)
		if err != nil {
			return err
		}
		// One chunk always fits, so a single large chunk cannot wait forever.
		if (session > 0 && session+int64(len(u.Sealed)) > limit) || tenant+int64(len(u.Sealed)) > limit*pamRecordingTenantStagingFactor {
			return errRecordingBackpressure
		}
		if err := s.store.InsertPAMRecordingUploadTx(ctx, tx, u); err != nil {
			return err
		}
		ref, err := json.Marshal(pamRecordingUploadRef{SessionID: u.SessionID, Attempt: u.Attempt, Seq: u.Seq})
		if err != nil {
			return err
		}
		_, err = s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: u.TenantID, Destination: pamRecordingStoreDestination,
			IdempotencyKey: pamRecordingUploadKey(u.SessionID, u.Attempt, u.Seq), Payload: ref})
		return err
	})
}

// acceptRecordingChunk seals a chunk for its place and stages it, then has
// the eager uploader store the session's staged chunks.
func (s *pamService) acceptRecordingChunk(ctx context.Context, tenantID, sessionID, agentID string, attempt, seq int, chunk []byte, final bool) error {
	sum := crypto.SHA256Sum(chunk)
	sumHex := hex.EncodeToString(sum)
	for range 3 {
		var place recordingPlace
		err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if err := store.LockPAMRecordingSessionTx(ctx, tx, tenantID, sessionID); err != nil {
				return err
			}
			var err error
			place, err = s.placeRecordingChunk(ctx, tx, tenantID, sessionID, attempt, seq, sumHex)
			return err
		})
		if errors.Is(err, errRecordingChunkKnown) {
			s.kickRecordingUploads(tenantID, sessionID)
			return nil
		}
		if err != nil {
			return err
		}
		chain, err := recordingChain(place.chainHead, sum)
		if err != nil {
			return err
		}
		sealed, err := sealTenantValue(ctx, s.recordings.access, s.recordings.legacy, tenantID, chunk, recordingAAD(tenantID, sessionID, place.ord, sumHex))
		if err != nil {
			return err
		}
		err = s.stageRecordingChunk(ctx, store.PAMRecordingUpload{TenantID: tenantID, SessionID: sessionID, Attempt: attempt, Seq: seq,
			Ord: place.ord, GatewayAgentID: agentID, SHA256: sumHex, SealedSHA256: hex.EncodeToString(crypto.SHA256Sum(sealed)),
			Chain: chain, Size: len(chunk), Final: final, Sealed: sealed, StagedAt: s.clock().UTC()}, place)
		switch {
		case errors.Is(err, errRecordingPlaceMoved):
			continue
		case errors.Is(err, errRecordingChunkKnown):
			s.kickRecordingUploads(tenantID, sessionID)
			return nil
		case err != nil:
			if errors.Is(err, errRecordingBackpressure) {
				s.kickRecordingUploads(tenantID, sessionID)
			}
			return err
		}
		if s.wakeOutbox != nil {
			s.wakeOutbox()
		}
		s.kickRecordingUploads(tenantID, sessionID)
		return nil
	}
	return fmt.Errorf("server: the session's recording place kept moving; retry")
}

// kickRecordingUploads stores a session's staged chunks now, in order, when
// an uploader slot is free; otherwise the outbox worker stores them.
func (s *pamService) kickRecordingUploads(tenantID, sessionID string) {
	if s.uploader == nil {
		return
	}
	select {
	case s.uploader.slots <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-s.uploader.slots }()
		m := s.uploader.lock(tenantID, sessionID)
		m.Lock()
		defer m.Unlock()
		ctx := context.Background()
		for {
			ord, found, err := s.store.LowestPAMRecordingUploadOrd(ctx, tenantID, sessionID)
			if err != nil || !found {
				return
			}
			up, err := s.lowestRecordingUpload(ctx, tenantID, sessionID, ord)
			if err != nil {
				return
			}
			storeCtx, cancel := context.WithTimeout(ctx, pamRecordingStoreTimeout)
			err = s.storeStagedRecordingChunk(storeCtx, up)
			cancel()
			if err != nil {
				return
			}
		}
	}()
}

// lowestRecordingUpload loads the staged chunk at ord.
func (s *pamService) lowestRecordingUpload(ctx context.Context, tenantID, sessionID string, ord int) (store.PAMRecordingUpload, error) {
	var meta []store.PAMRecordingUpload
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		meta, err = s.store.ListPAMRecordingUploadsTx(ctx, tx, tenantID, sessionID)
		return err
	})
	if err != nil {
		return store.PAMRecordingUpload{}, err
	}
	for _, m := range meta {
		if m.Ord == ord {
			return s.store.GetPAMRecordingUpload(ctx, tenantID, sessionID, m.Attempt, m.Seq)
		}
	}
	return store.PAMRecordingUpload{}, store.ErrPAMRecordingUploadNotFound
}

// storeStagedRecordingChunk writes one staged chunk's sealed object, records
// it as stored, removes the staged row and, after the final chunk, seals the
// recording. Every step repeats safely: the object is written only if absent
// (an existing one must carry this chunk's sealed digest), the stored event's
// ID and payload derive from the staged row, and the delete is idempotent.
func (s *pamService) storeStagedRecordingChunk(ctx context.Context, up store.PAMRecordingUpload) error {
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, up.TenantID)
	if err != nil {
		return err
	}
	rel := "recordings/" + up.SessionID + "/" + strconv.Itoa(up.Ord) + "-" + strconv.Itoa(up.Attempt) + "-" + strconv.Itoa(up.Seq)
	name, err := view.Name(rel)
	if err != nil {
		return err
	}
	obj, headErr := view.Head(ctx, rel)
	switch {
	case headErr == nil:
		if obj.SHA256 != "" && obj.SHA256 != up.SealedSHA256 {
			return fmt.Errorf("server: recording object %s holds other content", rel)
		}
	case errors.Is(headErr, objectstore.ErrNotFound):
		sealedSum, err := hex.DecodeString(up.SealedSHA256)
		if err != nil {
			return err
		}
		if _, err := view.Create(ctx, rel, bytes.NewReader(up.Sealed), int64(len(up.Sealed)), sealedSum); err != nil && !errors.Is(err, objectstore.ErrExists) {
			return err
		}
	default:
		// The store did not answer a read: nothing was written, so the
		// delivery defers without spending an attempt.
		return orchestrator.DeferDeliveryUntil(fmt.Errorf("server: the recording object store did not answer: %w", headErr), s.clock().Add(5*time.Second))
	}
	stored := projections.PAMRecordingChunkStored{ID: up.SessionID, GatewayAgentID: up.GatewayAgentID, Ord: up.Ord, Attempt: up.Attempt, Seq: up.Seq,
		ObjectRef: name, SHA256: up.SHA256, SealedSHA256: up.SealedSHA256, Chain: up.Chain,
		Size: up.Size, Final: up.Final, StoredAt: up.StagedAt.UTC()}
	if err := s.appendDeterministic(ctx, up.TenantID, recordingChunkEventID(up.TenantID, up.SessionID, up.Attempt, up.Seq), projections.EventPAMRecordingChunkStored, stored); err != nil {
		return err
	}
	if err := s.store.DeletePAMRecordingUpload(ctx, up.TenantID, up.SessionID, up.Attempt, up.Seq); err != nil {
		return err
	}
	if up.Final {
		return s.sealRecording(ctx, up.TenantID, up.SessionID)
	}
	return nil
}

// deliverRecordingUpload is the outbox worker for pam.recording.store: it
// stores the session's staged chunks in order up to this one. A chunk whose
// earlier neighbor is still staged defers without spending an attempt.
func (s *pamService) deliverRecordingUpload(ctx context.Context, m orchestrator.Message) error {
	if s.recordings == nil {
		return errors.New("server: session recordings are not stored by this control plane")
	}
	var ref pamRecordingUploadRef
	if json.Unmarshal(m.Payload, &ref) != nil || ref.SessionID == "" || m.IdempotencyKey != pamRecordingUploadKey(ref.SessionID, ref.Attempt, ref.Seq) {
		return orchestrator.DefiniteNoEffect(errors.New("server: malformed recording upload"))
	}
	up, err := s.store.GetPAMRecordingUpload(ctx, m.TenantID, ref.SessionID, ref.Attempt, ref.Seq)
	if errors.Is(err, store.ErrPAMRecordingUploadNotFound) {
		return nil // stored already
	}
	if err != nil {
		return err
	}
	lock := s.uploader.lock(m.TenantID, ref.SessionID)
	lock.Lock()
	defer lock.Unlock()
	lowest, found, err := s.store.LowestPAMRecordingUploadOrd(ctx, m.TenantID, ref.SessionID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if lowest < up.Ord {
		return orchestrator.DeferDeliveryUntil(errors.New("server: an earlier recording chunk is not stored yet"), s.clock().Add(time.Second))
	}
	// The staged row may have been stored and removed between the reads.
	if up, err = s.store.GetPAMRecordingUpload(ctx, m.TenantID, ref.SessionID, ref.Attempt, ref.Seq); errors.Is(err, store.ErrPAMRecordingUploadNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	return s.storeStagedRecordingChunk(ctx, up)
}

// failRecordingUpload keeps a recording chunk whose delivery exhausted its
// attempts: it is never given up while it is staged, so its delivery defers
// again instead of dead-lettering.
func (s *pamService) failRecordingUpload(ctx context.Context, m orchestrator.Message) error {
	return orchestrator.DeferDeliveryUntil(errors.New("server: a staged recording chunk is retried until it is stored"), s.clock().Add(time.Minute))
}

// recordingChunkEventID is a stored chunk's deterministic event ID.
func recordingChunkEventID(tenantID, sessionID string, attempt, seq int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-recording-chunk\x00"+tenantID+"\x00"+sessionID+"\x00"+strconv.Itoa(attempt)+"\x00"+strconv.Itoa(seq))).String()
}
