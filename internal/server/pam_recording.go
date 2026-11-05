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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	// recordingMaxChunk bounds one uploaded recording chunk.
	recordingMaxChunk = 1 << 20
	// recordingManifestArtifact is the signed manifest's artifact kind.
	recordingManifestArtifact = "pam-session-recording-manifest"
	// recordingIdleSeal is how long a recording of an ended session may wait
	// for its gateway's final chunk before the control plane seals it.
	recordingIdleSeal = 2 * time.Minute
)

// pamRecordings stores gateway session recordings (A255): each chunk sealed
// for the tenant into the object store and chained, and a manifest signed by
// the deployment's audit key when the recording closes. It is nil — and
// sessions are not recorded — without an object store, tenant sealing and an
// audit signing key.
type pamRecordings struct {
	objects objectstore.Store
	access  tenantseal.Access
	legacy  seal.KeyWrapper
	signer  *jose.SigningKey
}

// recordingManifest is what a sealed recording's signature covers.
type recordingManifest struct {
	Kind           string                   `json:"kind"`
	TenantID       string                   `json:"tenant_id"`
	SessionID      string                   `json:"session_id"`
	GatewayAgentID string                   `json:"gateway_agent_id"`
	StartedAt      time.Time                `json:"started_at"`
	LastChunkAt    time.Time                `json:"last_chunk_at"`
	FinalReceived  bool                     `json:"final_received"`
	Chunks         []recordingManifestChunk `json:"chunks"`
	Bytes          int64                    `json:"bytes"`
	ChainHead      string                   `json:"chain_head"`
	SealedAt       time.Time                `json:"sealed_at"`
}

type recordingManifestChunk struct {
	Ord          int    `json:"ord"`
	Attempt      int    `json:"attempt"`
	Seq          int    `json:"seq"`
	ObjectRef    string `json:"object_ref"`
	SHA256       string `json:"sha256"`
	SealedSHA256 string `json:"sealed_sha256"`
	Size         int    `json:"size"`
}

var zeroChain = make([]byte, 32)

// recordingChain extends a recording's chain by one chunk's digest.
func recordingChain(prev string, sum []byte) (string, error) {
	p := zeroChain
	if prev != "" {
		var err error
		if p, err = hex.DecodeString(prev); err != nil || len(p) != 32 {
			return "", errors.New("recording chain head is malformed")
		}
	}
	return hex.EncodeToString(crypto.SHA256Sum(append(append([]byte(nil), p...), sum...))), nil
}

// recordingAAD binds a sealed chunk to its tenant, session, place and
// plaintext digest: a chunk moved, swapped or replaced does not open.
func recordingAAD(tenantID, sessionID string, ord int, sum string) []byte {
	return []byte("trstctl/pam-recording/v1\x00" + tenantID + "\x00" + sessionID + "\x00" + strconv.Itoa(ord) + "\x00" + sum)
}

// UploadSessionRecording takes one chunk of a held session's recording
// (A255) from the gateway holding its job at that attempt.
func (a *agentService) UploadSessionRecording(ctx context.Context, req *transport.UploadSessionRecordingRequest) (*transport.UploadSessionRecordingResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if a.store == nil || a.storeRecordingChunk == nil {
		return nil, status.Error(codes.FailedPrecondition, "session recordings are not stored by this control plane")
	}
	if !agentHasRole(info.Roles, "gateway") {
		return nil, status.Error(codes.PermissionDenied, "session recordings come only from gateway-role agents")
	}
	if req == nil || req.JobID <= 0 || req.Attempt <= 0 || req.Seq < 0 || len(req.Chunk) > recordingMaxChunk {
		return nil, status.Error(codes.InvalidArgument, "job_id, attempt, seq and a chunk of at most 1 MiB are required")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	job, held, err := a.store.GetGatewayJobForRecording(ctx, info.TenantID, agentID, req.JobID, req.Attempt, relay.KindAccessGatewaySession, relay.KindAccessGatewayRulesSession, relay.KindAccessGatewaySSHRulesSession)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load job: %v", err)
	}
	if !held || job.RequiredAgentID != agentID {
		return &transport.UploadSessionRecordingResponse{Stopped: true}, nil
	}
	stopped, err := a.storeRecordingChunk(ctx, info.TenantID, agentID, job.Payload, req.Attempt, req.Seq, req.Chunk, req.Final)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "store the recording chunk: %v", err)
	}
	return &transport.UploadSessionRecordingResponse{Accepted: !stopped, Stopped: stopped}, nil
}

// UploadSessionRecording on the bulkhead wrapper dispatches into the
// agent-channel pool.
func (b *bulkheadedAgentService) UploadSessionRecording(ctx context.Context, req *transport.UploadSessionRecordingRequest) (*transport.UploadSessionRecordingResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "upload_session_recording", b.metrics, func(ctx context.Context) (*transport.UploadSessionRecordingResponse, error) {
		return b.next.UploadSessionRecording(ctx, req)
	})
}

// storeRecordingChunk seals and stores one chunk and records it. Chunks of an
// attempt arrive in order from seq 0; a retried chunk is accepted again
// unchanged, a different one in its place is refused. It reports stopped once
// the recording is sealed.
func (s *pamService) storeRecordingChunk(ctx context.Context, tenantID, agentID string, payload []byte, attempt, seq int, chunk []byte, final bool) (bool, error) {
	if s.recordings == nil {
		return true, nil
	}
	var intent accessgateway.SessionIntent
	if err := json.Unmarshal(payload, &intent); err != nil || accessgateway.ValidateSessionIntent(intent) != nil ||
		intent.RequiredAgentID != agentID || !intent.Record {
		return false, errors.New("the job is not a recorded gateway session of this agent's")
	}
	sessionID := intent.SessionID
	rec, err := s.store.GetPAMRecording(ctx, tenantID, sessionID)
	switch {
	case errors.Is(err, store.ErrPAMRecordingNotFound):
		rec = store.PAMRecording{}
	case err != nil:
		return false, err
	case rec.Status == "sealed":
		return true, nil
	}
	chunks, err := s.store.ListPAMRecordingChunks(ctx, tenantID, sessionID, 0, 0)
	if err != nil {
		return false, err
	}
	sum := crypto.SHA256Sum(chunk)
	sumHex := hex.EncodeToString(sum)
	next := 0
	for _, c := range chunks {
		if c.Attempt != attempt {
			continue
		}
		if c.Seq == seq {
			if c.SHA256 != sumHex {
				return false, fmt.Errorf("chunk %d of attempt %d was already stored with other content", seq, attempt)
			}
			return false, nil // a retry of a stored chunk
		}
		if c.Seq >= next {
			next = c.Seq + 1
		}
	}
	if seq != next {
		return false, fmt.Errorf("chunk %d of attempt %d is out of order (expected %d)", seq, attempt, next)
	}
	ord := len(chunks)
	chain, err := recordingChain(rec.ChainHead, sum)
	if err != nil {
		return false, err
	}
	sealed, err := sealTenantValue(ctx, s.recordings.access, s.recordings.legacy, tenantID, chunk, recordingAAD(tenantID, sessionID, ord, sumHex))
	if err != nil {
		return false, err
	}
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, tenantID)
	if err != nil {
		return false, err
	}
	rel := "recordings/" + sessionID + "/" + strconv.Itoa(ord) + "-" + strconv.Itoa(attempt) + "-" + strconv.Itoa(seq)
	ref, err := view.Create(ctx, rel, bytes.NewReader(sealed), int64(len(sealed)), crypto.SHA256Sum(sealed))
	if err != nil {
		return false, err
	}
	stored := projections.PAMRecordingChunkStored{ID: sessionID, GatewayAgentID: agentID, Ord: ord, Attempt: attempt, Seq: seq,
		ObjectRef: ref, SHA256: sumHex, SealedSHA256: hex.EncodeToString(crypto.SHA256Sum(sealed)), Chain: chain,
		Size: len(chunk), Final: final, StoredAt: s.clock().UTC()}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-recording-chunk\x00"+tenantID+"\x00"+sessionID+"\x00"+
		strconv.Itoa(attempt)+"\x00"+strconv.Itoa(seq))).String()
	if err := s.appendDeterministic(ctx, tenantID, eventID, projections.EventPAMRecordingChunkStored, stored); err != nil {
		return false, err
	}
	if final {
		if err := s.sealRecording(ctx, tenantID, sessionID); err != nil {
			return false, err
		}
	}
	return false, nil
}

// sealRecording closes a recording with a manifest signed by the audit key:
// every chunk's place, digests and object, and the chain head.
func (s *pamService) sealRecording(ctx context.Context, tenantID, sessionID string) error {
	if s.recordings == nil {
		return nil
	}
	rec, err := s.store.GetPAMRecording(ctx, tenantID, sessionID)
	if err != nil || rec.Status == "sealed" {
		return err
	}
	chunks, err := s.store.ListPAMRecordingChunks(ctx, tenantID, sessionID, 0, 0)
	if err != nil {
		return err
	}
	manifest := recordingManifest{Kind: "trstctl.pam.session.recording.v1", TenantID: tenantID, SessionID: sessionID,
		GatewayAgentID: rec.GatewayAgentID, StartedAt: rec.StartedAt.UTC(), LastChunkAt: rec.LastChunkAt.UTC(),
		FinalReceived: rec.FinalReceived, Bytes: rec.Bytes, ChainHead: rec.ChainHead, SealedAt: s.clock().UTC().Truncate(time.Second)}
	for _, c := range chunks {
		manifest.Chunks = append(manifest.Chunks, recordingManifestChunk{Ord: c.Ord, Attempt: c.Attempt, Seq: c.Seq,
			ObjectRef: c.ObjectRef, SHA256: c.SHA256, SealedSHA256: c.SealedSHA256, Size: c.Size})
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	signature, err := s.recordings.signer.SignArtifact(recordingManifestArtifact, body)
	if err != nil {
		return fmt.Errorf("sign the recording manifest: %w", err)
	}
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, tenantID)
	if err != nil {
		return err
	}
	ref, err := view.Create(ctx, "recordings/"+sessionID+"/manifest.json", bytes.NewReader(body), int64(len(body)), crypto.SHA256Sum(body))
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-recording-sealed\x00"+tenantID+"\x00"+sessionID)).String()
	return s.appendDeterministic(ctx, tenantID, eventID, projections.EventPAMRecordingSealed, projections.PAMRecordingSealed{
		ID: sessionID, ManifestRef: ref, ManifestSHA256: hex.EncodeToString(crypto.SHA256Sum(body)),
		ManifestSignature: signature, SealedAt: manifest.SealedAt})
}

// sealIdleRecordings seals the recordings of ended sessions whose gateway
// sent no final chunk (it lost the control plane or the session was cut off),
// once nothing has arrived for recordingIdleSeal.
func (s *pamService) sealIdleRecordings(ctx context.Context) {
	if s.recordings == nil {
		return
	}
	open, err := s.store.ListOpenPAMRecordings(ctx, s.clock().UTC().Add(-recordingIdleSeal), 100)
	if err != nil {
		return
	}
	for _, rec := range open {
		session, err := s.store.GetPAMSession(ctx, rec.TenantID, rec.SessionID)
		if err != nil || session.Status == "active" && s.clock().UTC().Before(session.ExpiresAt) {
			continue
		}
		_ = s.sealRecording(ctx, rec.TenantID, rec.SessionID)
	}
}

// RecordingVerification is what verifying a sealed recording found.
type RecordingVerification struct {
	Verified bool     `json:"verified"`
	Chunks   int      `json:"chunks"`
	Problems []string `json:"problems,omitempty"`
}

// verifyRecording checks a sealed recording end to end: the manifest is the
// one the audit key signed, every chunk object is there, unmodified and in
// its place (its seal opens only there), its plaintext matches its digest,
// and the chain over the digests reaches the manifest's head.
func (s *pamService) verifyRecording(ctx context.Context, tenantID, sessionID string) (RecordingVerification, error) {
	if s.recordings == nil {
		return RecordingVerification{}, errors.New("session recordings are not stored by this control plane")
	}
	rec, err := s.store.GetPAMRecording(ctx, tenantID, sessionID)
	if err != nil {
		return RecordingVerification{}, err
	}
	out := RecordingVerification{}
	problem := func(format string, args ...any) { out.Problems = append(out.Problems, fmt.Sprintf(format, args...)) }
	if rec.Status != "sealed" {
		problem("the recording is not sealed yet")
		return out, nil
	}
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, tenantID)
	if err != nil {
		return RecordingVerification{}, err
	}
	var body bytes.Buffer
	if _, err := view.Get(ctx, recordingRel(view, rec.ManifestRef), &body, 64<<20); errors.Is(err, objectstore.ErrDigest) {
		problem("the manifest object differs from the one recorded")
		return out, nil
	} else if err != nil {
		problem("the manifest object cannot be read")
		return out, nil
	}
	if hex.EncodeToString(crypto.SHA256Sum(body.Bytes())) != rec.ManifestSHA256 {
		problem("the manifest object differs from the one recorded")
	}
	signed, err := s.recordings.signer.JWKS().VerifyArtifact(rec.ManifestSignature, recordingManifestArtifact)
	if err != nil || !bytes.Equal(signed, body.Bytes()) {
		problem("the manifest signature does not verify")
	}
	var manifest recordingManifest
	if err := json.Unmarshal(signed, &manifest); err != nil || manifest.SessionID != sessionID || manifest.TenantID != tenantID {
		problem("the signed manifest is not this session's")
		return out, nil
	}
	chain := ""
	for i, c := range manifest.Chunks {
		if c.Ord != i {
			problem("chunk %d is out of place in the manifest", i)
			continue
		}
		var sealed bytes.Buffer
		if _, err := view.Get(ctx, recordingRel(view, c.ObjectRef), &sealed, recordingMaxChunk*2); errors.Is(err, objectstore.ErrDigest) {
			// The store's own digest check refuses an altered object.
			problem("chunk %d was modified", i)
			continue
		} else if err != nil {
			problem("chunk %d is missing", i)
			continue
		}
		if hex.EncodeToString(crypto.SHA256Sum(sealed.Bytes())) != c.SealedSHA256 {
			problem("chunk %d was modified", i)
			continue
		}
		plain, err := openTenantValue(ctx, s.recordings.access, s.recordings.legacy, tenantID, sealed.Bytes(), recordingAAD(tenantID, sessionID, c.Ord, c.SHA256))
		if err != nil || hex.EncodeToString(crypto.SHA256Sum(plain)) != c.SHA256 {
			problem("chunk %d does not open in its place", i)
			continue
		}
		raw, _ := hex.DecodeString(c.SHA256)
		if chain, err = recordingChain(chain, raw); err != nil {
			problem("chunk %d breaks the chain", i)
		}
		out.Chunks++
	}
	if chain != manifest.ChainHead {
		problem("the chain over the chunks does not reach the manifest's head")
	}
	out.Verified = len(out.Problems) == 0
	return out, nil
}

// recordingRel turns a stored object reference back into its path under the
// tenant's prefix.
func recordingRel(view objectstore.Tenant, ref string) string {
	if p := view.Prefix(); len(ref) > len(p) && ref[:len(p)] == p {
		return ref[len(p):]
	}
	return ref
}

// appendDeterministic appends an event with a derived ID and projects it; a
// retry finds the same event, and a different payload under the ID conflicts.
func (s *pamService) appendDeterministic(ctx context.Context, tenantID, id, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e, err := s.log.Append(ctx, events.Event{ID: id, Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if e.Type != eventType || e.TenantID != tenantID || !bytes.Equal(e.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, e)
}

// pamStoreRecordingChunk is the agent channel's hook into PAM, nil when PAM
// is not served.
func (s *Server) pamStoreRecordingChunk() func(ctx context.Context, tenantID, agentID string, payload []byte, attempt, seq int, chunk []byte, final bool) (bool, error) {
	if s.pam == nil {
		return nil
	}
	return s.pam.storeRecordingChunk
}

// GetPAMRecording serves a session's recording index (A255).
func (s *Server) GetPAMRecording(ctx context.Context, tenantID, sessionID string) (api.PAMRecording, error) {
	if s.pam == nil || s.pam.recordings == nil {
		return api.PAMRecording{}, api.ErrPAMUnavailable
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return api.PAMRecording{}, pgx.ErrNoRows
	}
	rec, err := s.store.GetPAMRecording(ctx, tenantID, sessionID)
	if errors.Is(err, store.ErrPAMRecordingNotFound) {
		return api.PAMRecording{}, pgx.ErrNoRows
	}
	if err != nil {
		return api.PAMRecording{}, err
	}
	return api.PAMRecording{SessionID: rec.SessionID, Status: rec.Status, Chunks: rec.Chunks, Bytes: rec.Bytes,
		StartedAt: rec.StartedAt, LastChunkAt: rec.LastChunkAt, SealedAt: rec.SealedAt, FinalReceived: rec.FinalReceived,
		ChainHead: rec.ChainHead, ManifestSHA256: rec.ManifestSHA256,
		LegalHold: rec.LegalHold, LegalHoldReason: rec.LegalHoldReason, DeletedAt: rec.DeletedAt}, nil
}

// VerifyPAMRecording checks a sealed recording against its signed manifest.
func (s *Server) VerifyPAMRecording(ctx context.Context, tenantID, sessionID string) (api.PAMRecordingVerification, error) {
	if s.pam == nil || s.pam.recordings == nil {
		return api.PAMRecordingVerification{}, api.ErrPAMUnavailable
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return api.PAMRecordingVerification{}, pgx.ErrNoRows
	}
	v, err := s.pam.verifyRecording(ctx, tenantID, sessionID)
	if errors.Is(err, store.ErrPAMRecordingNotFound) {
		return api.PAMRecordingVerification{}, pgx.ErrNoRows
	}
	if err != nil {
		return api.PAMRecordingVerification{}, err
	}
	return api.PAMRecordingVerification{Verified: v.Verified, Chunks: v.Chunks, Problems: v.Problems}, nil
}

// recordGatewaySessionEnded records the gateway's own report that it ended a
// session (A255) — at its deadline, or recalled by a revocation or
// termination — and seals the session's recording if its final chunk never
// arrived.
func (s *pamService) recordGatewaySessionEnded(ctx context.Context, tenantID string, payload []byte, detail string, attempt int) error {
	var intent accessgateway.SessionIntent
	var report accessgateway.SessionReport
	if json.Unmarshal(payload, &intent) != nil || json.Unmarshal([]byte(detail), &report) != nil || report.SessionID != intent.SessionID {
		return errors.New("gateway session report does not match its job")
	}
	if report.Ended != "deadline" && report.Ended != "recalled" {
		return nil
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-gateway-ended\x00"+tenantID+"\x00"+intent.SessionID+"\x00"+strconv.Itoa(attempt))).String()
	if err := s.appendOnce(ctx, tenantID, eventID, projections.EventPAMSessionGatewayEnded, projections.PAMSessionGatewayEnded{
		ID: intent.SessionID, Ended: report.Ended, Connections: report.Connections, Attempt: attempt,
		EndedAt: s.clock().UTC().Truncate(time.Millisecond)}); err != nil {
		return err
	}
	if s.recordings != nil {
		if rec, err := s.store.GetPAMRecording(ctx, tenantID, intent.SessionID); err == nil && rec.Status == "recording" {
			return s.sealRecording(ctx, tenantID, intent.SessionID)
		}
	}
	return nil
}

// pamRecordGatewaySessionEnded is the agent channel's hook into PAM, nil when
// PAM is not served.
func (s *Server) pamRecordGatewaySessionEnded() func(ctx context.Context, tenantID string, payload []byte, detail string, attempt int) error {
	if s.pam == nil {
		return nil
	}
	return s.pam.recordGatewaySessionEnded
}

// appendOnce records a fact once under a derived ID: a retry whose payload
// carries a later time finds the first record and keeps it.
func (s *pamService) appendOnce(ctx context.Context, tenantID, id, eventType string, payload any) error {
	if existing, found, err := s.log.EventByID(ctx, id); err != nil {
		return err
	} else if found {
		if existing.Type != eventType || existing.TenantID != tenantID {
			return orchestrator.ErrIdempotencyConflict
		}
		return s.projector.Apply(ctx, existing)
	}
	return s.appendDeterministic(ctx, tenantID, id, eventType, payload)
}

// recordingReadLimit bounds the frames one read returns; recordingExportLimit
// the plaintext one export returns (read a longer recording by pages).
const (
	recordingReadLimit   = 8 << 20
	recordingExportLimit = 64 << 20
	recordingMaxWait     = 25 * time.Second
)

// recordingFrames opens chunks from fromOrd, at most limit, and returns
// their frames (each a JSON line as the gateway wrote it) and the next place.
func (s *pamService) recordingFrames(ctx context.Context, tenantID, sessionID string, fromOrd, limit, maxBytes int) ([]json.RawMessage, int, error) {
	chunks, err := s.store.ListPAMRecordingChunks(ctx, tenantID, sessionID, fromOrd, limit)
	if err != nil {
		return nil, fromOrd, err
	}
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, tenantID)
	if err != nil {
		return nil, fromOrd, err
	}
	var frames []json.RawMessage
	next, total := fromOrd, 0
	for _, c := range chunks {
		if total+c.Size > maxBytes && len(frames) > 0 {
			break
		}
		var sealed bytes.Buffer
		if _, err := view.Get(ctx, recordingRel(view, c.ObjectRef), &sealed, recordingMaxChunk*2); err != nil {
			return nil, next, fmt.Errorf("recording chunk %d cannot be read: %w", c.Ord, err)
		}
		plain, err := openTenantValue(ctx, s.recordings.access, s.recordings.legacy, tenantID, sealed.Bytes(), recordingAAD(tenantID, sessionID, c.Ord, c.SHA256))
		if err != nil || hex.EncodeToString(crypto.SHA256Sum(plain)) != c.SHA256 {
			return nil, next, fmt.Errorf("recording chunk %d does not open in its place", c.Ord)
		}
		for _, line := range bytes.Split(plain, []byte("\n")) {
			if len(line) > 0 {
				frames = append(frames, json.RawMessage(append([]byte(nil), line...)))
			}
		}
		total += c.Size
		next = c.Ord + 1
	}
	return frames, next, nil
}

// recordRead records who read which recording, and how (A255).
func (s *pamService) recordRead(ctx context.Context, tenantID, sessionID, actor, mode string) error {
	return s.appendDeterministic(ctx, tenantID, uuid.NewString(), projections.EventPAMRecordingRead,
		projections.PAMRecordingRead{ID: sessionID, Actor: actor, Mode: mode, At: s.clock().UTC().Truncate(time.Millisecond)})
}

func (s *Server) pamRecordingFor(ctx context.Context, tenantID, sessionID string) (store.PAMRecording, error) {
	if s.pam == nil || s.pam.recordings == nil {
		return store.PAMRecording{}, api.ErrPAMUnavailable
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return store.PAMRecording{}, pgx.ErrNoRows
	}
	rec, err := s.store.GetPAMRecording(ctx, tenantID, sessionID)
	if errors.Is(err, store.ErrPAMRecordingNotFound) {
		return store.PAMRecording{}, pgx.ErrNoRows
	}
	return rec, err
}

// pamRecordingOrPending is a session's recording, or — for a gateway session
// whose first chunk has not arrived — an empty recording still being made, so
// a watch can start with the session.
func (s *Server) pamRecordingOrPending(ctx context.Context, tenantID, sessionID string) (store.PAMRecording, error) {
	rec, err := s.pamRecordingFor(ctx, tenantID, sessionID)
	if !errors.Is(err, pgx.ErrNoRows) {
		return rec, err
	}
	session, serr := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if serr != nil || session.Delivery != "gateway" {
		return store.PAMRecording{}, err
	}
	return store.PAMRecording{TenantID: tenantID, SessionID: sessionID, Status: "recording"}, nil
}

// ReadPAMRecordingFrames plays back a recording from chunk from (A255). With
// wait, a read that would return nothing waits up to that long for the next
// chunk of a recording still being made, which is how a session is watched
// live. Every read is recorded.
func (s *Server) ReadPAMRecordingFrames(ctx context.Context, tenantID, sessionID, actor string, from, limit int, wait time.Duration) (api.PAMRecordingFrames, error) {
	rec, err := s.pamRecordingOrPending(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMRecordingFrames{}, err
	}
	if rec.Status == "deleted" {
		return api.PAMRecordingFrames{}, fmt.Errorf("%w: the recording was deleted by retention", api.ErrPAMTerminal)
	}
	if from < 0 {
		from = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if err := s.pam.recordRead(ctx, tenantID, sessionID, actor, "frames"); err != nil {
		return api.PAMRecordingFrames{}, err
	}
	wait = min(max(wait, 0), recordingMaxWait)
	deadline := time.Now().Add(wait)
	for {
		frames, next, err := s.pam.recordingFrames(ctx, tenantID, sessionID, from, limit, recordingReadLimit)
		if err != nil {
			return api.PAMRecordingFrames{}, err
		}
		if len(frames) > 0 || rec.Status != "recording" || !time.Now().Before(deadline) {
			return api.PAMRecordingFrames{SessionID: sessionID, Status: rec.Status, Next: next, Frames: frames}, nil
		}
		select {
		case <-ctx.Done():
			return api.PAMRecordingFrames{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		if rec, err = s.pamRecordingOrPending(ctx, tenantID, sessionID); err != nil {
			return api.PAMRecordingFrames{}, err
		}
	}
}

// ExportPAMRecording returns a sealed recording whole: its manifest, the
// audit key's signature over it, and every frame (A255). The read is
// recorded.
func (s *Server) ExportPAMRecording(ctx context.Context, tenantID, sessionID, actor string) (api.PAMRecordingExport, error) {
	rec, err := s.pamRecordingFor(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMRecordingExport{}, err
	}
	if rec.Status != "sealed" {
		return api.PAMRecordingExport{}, fmt.Errorf("%w: only a sealed recording is exported", api.ErrPAMTerminal)
	}
	view, err := objectstore.ForTenant(ctx, s.pam.recordings.objects, tenantID)
	if err != nil {
		return api.PAMRecordingExport{}, err
	}
	var manifest bytes.Buffer
	if _, err := view.Get(ctx, recordingRel(view, rec.ManifestRef), &manifest, 64<<20); err != nil {
		return api.PAMRecordingExport{}, fmt.Errorf("the recording manifest cannot be read: %w", err)
	}
	frames, next, err := s.pam.recordingFrames(ctx, tenantID, sessionID, 0, 0, recordingExportLimit)
	if err != nil {
		return api.PAMRecordingExport{}, err
	}
	if next < rec.Chunks {
		return api.PAMRecordingExport{}, fmt.Errorf("%w: the recording is larger than one export; read it by pages", api.ErrPAMInvalid)
	}
	if err := s.pam.recordRead(ctx, tenantID, sessionID, actor, "export"); err != nil {
		return api.PAMRecordingExport{}, err
	}
	return api.PAMRecordingExport{SessionID: sessionID, Manifest: json.RawMessage(manifest.Bytes()),
		ManifestSignature: rec.ManifestSignature, Frames: frames}, nil
}

// SetPAMRecordingLegalHold places (hold) or releases a legal hold on a
// recording; a held recording outlives its retention (A255).
func (s *Server) SetPAMRecordingLegalHold(ctx context.Context, tenantID, sessionID, actor string, hold bool, reason string) (api.PAMRecording, error) {
	rec, err := s.pamRecordingFor(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMRecording{}, err
	}
	reason = strings.TrimSpace(reason)
	switch {
	case rec.Status == "deleted":
		return api.PAMRecording{}, fmt.Errorf("%w: the recording was deleted by retention", api.ErrPAMTerminal)
	case hold && (reason == "" || len(reason) > 1000):
		return api.PAMRecording{}, fmt.Errorf("%w: a legal hold needs a reason", api.ErrPAMInvalid)
	case rec.LegalHold == hold:
		return s.GetPAMRecording(ctx, tenantID, sessionID)
	}
	if !hold {
		reason = ""
	}
	if err := s.pam.appendDeterministic(ctx, tenantID, uuid.NewString(), projections.EventPAMRecordingLegalHold,
		projections.PAMRecordingLegalHold{ID: sessionID, Hold: hold, Reason: reason, Actor: actor, At: s.pam.clock().UTC().Truncate(time.Millisecond)}); err != nil {
		return api.PAMRecording{}, err
	}
	return s.GetPAMRecording(ctx, tenantID, sessionID)
}

// TerminatePAMSession ends another principal's live gateway session (A255):
// the session's job is recalled (the gateway closes its connections at its
// next lease extension) and its credential is revoked, as for a revocation.
// Until the gateway reports the end, the session reads as uncertain until its
// native deadline.
func (s *Server) TerminatePAMSession(ctx context.Context, tenantID, id, actor, reason, idempotencyKey string) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	if _, err := uuid.Parse(id); err != nil {
		return api.PAMSession{}, pgx.ErrNoRows
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	if rec.Delivery != "gateway" {
		return api.PAMSession{}, fmt.Errorf("%w: only a session through a gateway is terminated; revoke a direct session", api.ErrPAMInvalid)
	}
	return s.pam.RevokePAMSession(ctx, tenantID, id, actor, strings.TrimSpace(reason), idempotencyKey)
}

// deleteExpiredRecordings removes the objects of sealed recordings past the
// deployment's retention that no legal hold keeps (A255); the index and its
// manifest digest stay, marked deleted.
func (s *pamService) deleteExpiredRecordings(ctx context.Context) {
	if s.recordings == nil || s.recordingRetention <= 0 {
		return
	}
	expired, err := s.store.ListExpiredPAMRecordings(ctx, s.clock().UTC().Add(-s.recordingRetention), 50)
	if err != nil {
		return
	}
	for _, rec := range expired {
		_ = s.deleteRecording(ctx, rec)
	}
}

func (s *pamService) deleteRecording(ctx context.Context, rec store.PAMRecording) error {
	view, err := objectstore.ForTenant(ctx, s.recordings.objects, rec.TenantID)
	if err != nil {
		return err
	}
	chunks, err := s.store.ListPAMRecordingChunks(ctx, rec.TenantID, rec.SessionID, 0, 0)
	if err != nil {
		return err
	}
	removed := 0
	for _, ref := range append(chunkRefs(chunks), rec.ManifestRef) {
		if err := view.Delete(ctx, recordingRel(view, ref)); err != nil && !errors.Is(err, objectstore.ErrNotFound) {
			return err
		}
		removed++
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-recording-deleted\x00"+rec.TenantID+"\x00"+rec.SessionID)).String()
	return s.appendOnce(ctx, rec.TenantID, eventID, projections.EventPAMRecordingDeleted, projections.PAMRecordingDeleted{
		ID: rec.SessionID, Objects: removed, DeletedAt: s.clock().UTC().Truncate(time.Millisecond)})
}

func chunkRefs(chunks []store.PAMRecordingChunk) []string {
	out := make([]string, 0, len(chunks))
	for _, c := range chunks {
		out = append(out, c.ObjectRef)
	}
	return out
}
