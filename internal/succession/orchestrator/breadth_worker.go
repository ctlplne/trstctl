// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	eepqc "trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/federation"
	pcaskem "trstctl.com/trstctl/internal/succession/kem"
	"trstctl.com/trstctl/internal/succession/recovery"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
	"trstctl.com/trstctl/internal/translog"
)

type BreadthWorker struct {
	core *corestore.Store
	repo *pcasstore.Repo
	kem  editionseam.KEMCustody
	log  *events.Log
}

func NewBreadthWorker(core *corestore.Store, kem editionseam.KEMCustody, log *events.Log) *BreadthWorker {
	var repo *pcasstore.Repo
	if core != nil {
		repo = pcasstore.New(core)
	}
	return &BreadthWorker{core: core, repo: repo, kem: kem, log: log}
}

func (w *BreadthWorker) Deliver(ctx context.Context, m coreorch.Message) error {
	switch m.Destination {
	case KEMRewrapDestination:
		return w.handleKEMRewrap(ctx, m.TenantID, m.Payload)
	case RecoverySuccessorPrepareDestination:
		return w.handleRecoverySuccessorPrepare(ctx, m.TenantID, m.Payload)
	case RecoveryRequestDestination:
		return w.handleRecovery(ctx, m.TenantID, m.Payload)
	case FederationImportDestination:
		return w.handleFederationImport(ctx, m.TenantID, m.Payload)
	default:
		return fmt.Errorf("pcas breadth worker: unexpected destination %q", m.Destination)
	}
}

// breadthKind names one breadth family independent of the (configurable)
// destination string, so an operator-repointed pcas.*.outbox_topic still routes
// to the right handler (AUD-7).
type breadthKind string

const (
	breadthKEM             breadthKind = "kem"
	breadthRecovery        breadthKind = "recovery"
	breadthRecoveryPrepare breadthKind = "recovery_prepare"
	breadthFederation      breadthKind = "federation"
)

// DeliverKind routes by resolved family rather than by destination literal; the
// licensed handler resolves the family from the operator's configured topics.
func (w *BreadthWorker) DeliverKind(ctx context.Context, kind breadthKind, m coreorch.Message) error {
	switch kind {
	case breadthKEM:
		return w.handleKEMRewrap(ctx, m.TenantID, m.Payload)
	case breadthRecovery:
		return w.handleRecovery(ctx, m.TenantID, m.Payload)
	case breadthRecoveryPrepare:
		return w.handleRecoverySuccessorPrepare(ctx, m.TenantID, m.Payload)
	case breadthFederation:
		return w.handleFederationImport(ctx, m.TenantID, m.Payload)
	default:
		return fmt.Errorf("pcas breadth worker: unexpected kind %q (destination %q)", kind, m.Destination)
	}
}

type requestEnvelope[T any] struct {
	RequestID string `json:"request_id"`
	Request   T      `json:"request"`
}

type kemRewrapPayload struct {
	IdentityID          string   `json:"identity_id"`
	PredecessorHandle   string   `json:"predecessor_handle"`
	PredecessorEpoch    uint64   `json:"predecessor_epoch"`
	SuccessorSignHandle string   `json:"successor_sign_handle"`
	SuccessorKEMHandle  string   `json:"successor_kem_handle"`
	SigningAlgorithm    string   `json:"signing_algorithm"`
	KEMAlgorithm        string   `json:"kem_algorithm"`
	Stages              []string `json:"stages,omitempty"`
}

type recoveryPayload struct {
	IdentityID           string          `json:"identity_id"`
	DeploymentScope      string          `json:"deployment_scope,omitempty"`
	TargetAlgorithm      string          `json:"target_algorithm"`
	SuccessorHandle      string          `json:"successor_handle"`
	PredecessorEpoch     uint64          `json:"predecessor_epoch"`
	Epoch                uint64          `json:"epoch"`
	PredecessorAlgorithm string          `json:"predecessor_algorithm"`
	PredecessorPublicDER []byte          `json:"predecessor_public_der"`
	TrustRootDER         []byte          `json:"trust_root_der"`
	Authorization        json.RawMessage `json:"authorization"`
}

type recoveryPreparePayload struct {
	IdentityID      string `json:"identity_id"`
	Epoch           uint64 `json:"epoch"`
	Algorithm       string `json:"algorithm"`
	DeploymentScope string `json:"deployment_scope"`
}

// handleRecoverySuccessorPrepare creates one signer-held key under a deterministic
// tenant identity epoch handle, then appends a signed public receipt. The event
// ID is a first-writer fence; a lost reply reuses the same key and event.
func (w *BreadthWorker) handleRecoverySuccessorPrepare(ctx context.Context, tenantID string, payload []byte) error {
	var env requestEnvelope[recoveryPreparePayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas recovery prepare: decode payload: %w", err)
	}
	p := env.Request
	if env.RequestID == "" || p.IdentityID == "" || p.Epoch == 0 || p.Algorithm == "" || p.DeploymentScope == "" {
		return errors.New("pcas recovery prepare: incomplete request")
	}
	if w.log == nil || w.repo == nil || w.kem == nil {
		return errors.New("pcas recovery prepare: event log, policy store and signer are required")
	}
	anchor, found, err := w.repo.GetGenesis(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	if !found || anchor.Genesis.DeploymentScope != p.DeploymentScope {
		return errors.New("pcas recovery prepare: tenant identity genesis or scope mismatch")
	}
	highWater, err := w.highWater(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	if p.Epoch != highWater+1 {
		return errors.New("pcas recovery prepare: epoch is not next after current high-water")
	}
	handle := succession.TenantKeyHandle(tenantID, p.IdentityID, p.Epoch)
	eventID := succession.RecoverySuccessorEventID(tenantID, p.IdentityID, p.Epoch)
	if prior, exists, err := w.log.EventByID(ctx, eventID); err != nil {
		return err
	} else if exists {
		return w.verifyPreparedSuccessorReadback(ctx, prior, tenantID, p.IdentityID,
			p.Epoch, p.Algorithm, p.DeploymentScope, handle)
	}
	remote, err := w.kem.SignerForHandle(ctx, handle)
	if status.Code(err) == codes.NotFound {
		remote, err = w.kem.GenerateKeyHandle(ctx, crypto.Algorithm(p.Algorithm), handle)
		if status.Code(err) == codes.AlreadyExists {
			remote, err = w.kem.SignerForHandle(ctx, handle)
		}
	}
	if err != nil {
		return fmt.Errorf("pcas recovery prepare: signer key: %w", err)
	}
	if string(remote.Algorithm()) != p.Algorithm {
		return errors.New("pcas recovery prepare: existing signer key uses a different algorithm")
	}
	receipt := succession.RecoverySuccessorPreparedV1{
		TenantID: tenantID, IdentityID: p.IdentityID, Epoch: p.Epoch,
		Algorithm: p.Algorithm, Handle: handle, PublicKeyDER: remote.Public().DER,
		DeploymentScope: p.DeploymentScope, RequestID: env.RequestID,
	}
	message, err := succession.RecoverySuccessorSigningMessage(receipt)
	if err != nil {
		return err
	}
	digest, err := crypto.Digest(crypto.SHA256, message)
	if err != nil {
		return err
	}
	receipt.SignerSignature, err = remote.SignDigestForOperation(
		"pcas-recovery-prepare:"+eventID, digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return fmt.Errorf("pcas recovery prepare: signer receipt: %w", err)
	}
	if err := succession.VerifyRecoverySuccessorPrepared(receipt); err != nil {
		return err
	}
	ev, err := succession.Encode(receipt)
	if err != nil {
		return err
	}
	ev.ID = eventID
	recorded, err := w.log.Append(ctx, ev)
	if err != nil {
		return fmt.Errorf("pcas recovery prepare: append public receipt: %w", err)
	}
	return w.verifyPreparedSuccessorReadback(ctx, recorded, tenantID, p.IdentityID,
		p.Epoch, p.Algorithm, p.DeploymentScope, handle)
}

func (w *BreadthWorker) verifyPreparedSuccessorReadback(ctx context.Context, ev events.Event,
	tenantID, identityID string, epoch uint64, algorithm, deploymentScope, handle string) error {
	if ev.TenantID != tenantID || ev.Type != succession.TypeRecoverySuccessorPrepared {
		return errors.New("pcas recovery prepare: event ID belongs to another tenant or command")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	receipt, ok := decoded.(succession.RecoverySuccessorPreparedV1)
	if !ok || receipt.TenantID != tenantID || receipt.IdentityID != identityID ||
		receipt.Epoch != epoch || receipt.Algorithm != algorithm ||
		receipt.DeploymentScope != deploymentScope || receipt.Handle != handle {
		return errors.New("pcas recovery prepare: existing receipt binds different key or scope")
	}
	if err := succession.VerifyRecoverySuccessorPrepared(receipt); err != nil {
		return err
	}
	remote, err := w.kem.SignerForHandle(ctx, handle)
	if err != nil {
		return fmt.Errorf("pcas recovery prepare: signer readback: %w", err)
	}
	if string(remote.Algorithm()) != algorithm || !bytes.Equal(remote.Public().DER, receipt.PublicKeyDER) {
		return errors.New("pcas recovery prepare: signer key differs from immutable receipt")
	}
	return nil
}

type federationImportPayload struct {
	ForeignDeploymentID  string            `json:"foreign_deployment_id"`
	LocalDeploymentID    string            `json:"local_deployment_id"`
	LocalAuthorityHandle string            `json:"local_authority_handle"`
	IdentityID           string            `json:"identity_id"`
	ForeignTrustRootDER  []byte            `json:"foreign_trust_root_der"`
	LocalBaseEpoch       uint64            `json:"local_base_epoch"`
	ForeignGenesis       json.RawMessage   `json:"foreign_genesis"`
	ForeignChain         []json.RawMessage `json:"foreign_chain,omitempty"`
}

func (w *BreadthWorker) handleKEMRewrap(ctx context.Context, tenantID string, payload []byte) error {
	if w.kem == nil {
		return errors.New("pcas KEM rewrap: no signer KEM custody configured")
	}
	var env requestEnvelope[kemRewrapPayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas KEM rewrap: decode payload: %w", err)
	}
	p := env.Request
	if len(p.Stages) == 0 {
		p.Stages = []string{"default"}
	}
	if err := succession.ValidateKEMRewrapStages(p.Stages); err != nil {
		return err
	}
	if p.IdentityID == "" || p.PredecessorHandle == "" || p.SuccessorSignHandle == "" || p.SuccessorKEMHandle == "" {
		return errors.New("pcas KEM rewrap: missing identity or signer handles")
	}
	if p.PredecessorEpoch >= math.MaxInt64 {
		return errors.New("pcas KEM rewrap: predecessor epoch exceeds signed storage range")
	}
	if p.PredecessorHandle != succession.TenantKeyHandle(tenantID, p.IdentityID, p.PredecessorEpoch) ||
		p.SuccessorSignHandle != succession.TenantKeyHandle(tenantID, p.IdentityID, p.PredecessorEpoch+1) ||
		p.SuccessorKEMHandle != succession.TenantKEMKeyHandle(tenantID, p.IdentityID, p.PredecessorEpoch+1) {
		return errors.New("pcas KEM rewrap: signer handles are not bound to tenant identity and epoch")
	}
	if env.RequestID == "" || w.log == nil || w.repo == nil {
		return errors.New("pcas KEM rewrap: request ID, event log and projection store are required")
	}
	requestBytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	requestDigest := crypto.SHA256Sum(requestBytes)
	if err := w.recordKEMRewrapRequest(ctx, tenantID, p.IdentityID, p.PredecessorEpoch,
		env.RequestID, requestDigest, p.Stages); err != nil {
		return err
	}
	recordEventID := succession.KEMRewrapRecordEventID(tenantID, p.IdentityID, p.PredecessorEpoch+1)
	if prior, found, err := w.log.EventByID(ctx, recordEventID); err != nil {
		return err
	} else if found {
		if err := w.applyExistingKEMRewrap(ctx, prior, tenantID, p.IdentityID,
			p.PredecessorEpoch+1, env.RequestID, requestDigest, p.Stages); err != nil {
			return err
		}
		return nil
	}
	predRemote, err := w.kem.SignerForHandle(ctx, p.PredecessorHandle)
	if err != nil {
		return fmt.Errorf("pcas KEM rewrap: bind predecessor handle: %w", err)
	}
	predecessor := crypto.SignerFromDigestSigner(predRemote)
	now := time.Now().UTC()
	fields := succession.CommitmentFields{
		DeploymentScope:   "pcas-kem-rewrap",
		IdentityID:        p.IdentityID,
		TenantID:          tenantID,
		PredecessorEpoch:  p.PredecessorEpoch,
		Epoch:             p.PredecessorEpoch + 1,
		PredecessorAlg:    predecessor.Algorithm(),
		PredecessorPub:    predecessor.Public().DER,
		PolicyRef:         "pcas:kem-rewrap:" + env.RequestID,
		HashAlg:           succession.HashAlgSHA256,
		NotBefore:         now.Unix(),
		NotAfter:          now.Add(365 * 24 * time.Hour).Unix(),
		CommitmentVersion: 2,
	}
	rec, err := pcaskem.MintPairedThroughSigner(fields, predecessor, signerKEMAdapter{ctx: ctx, custody: w.kem, signingAlg: crypto.Algorithm(p.SigningAlgorithm)}, p.SuccessorSignHandle, p.SuccessorKEMHandle, p.KEMAlgorithm)
	if err != nil {
		return fmt.Errorf("pcas KEM rewrap: mint paired successor: %w", err)
	}
	if err := pcaskem.VerifyPaired(rec); err != nil {
		return fmt.Errorf("pcas KEM rewrap: verify paired record: %w", err)
	}
	if err := w.proveSignerDecapsulation(ctx, p.SuccessorKEMHandle, p.KEMAlgorithm, rec.KEMPub); err != nil {
		return err
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := w.recordKEMRewrap(ctx, tenantID, rec.Base.Fields, encoded, env.RequestID, requestDigest, p.Stages); err != nil {
		return err
	}
	return nil
}

type signerKEMAdapter struct {
	ctx        context.Context
	custody    editionseam.KEMCustody
	signingAlg crypto.Algorithm
}

func (a signerKEMAdapter) GeneratePairedSigningKey(handle string) (crypto.Signer, error) {
	rs, err := a.custody.SignerForHandle(a.ctx, handle)
	if status.Code(err) == codes.NotFound {
		rs, err = a.custody.GenerateKeyHandle(a.ctx, a.signingAlg, handle)
		if status.Code(err) == codes.AlreadyExists {
			rs, err = a.custody.SignerForHandle(a.ctx, handle)
		}
	}
	if err != nil {
		return nil, err
	}
	if rs.Algorithm() != a.signingAlg {
		return nil, fmt.Errorf("pcas KEM rewrap: paired signer handle uses %s, want %s", rs.Algorithm(), a.signingAlg)
	}
	return crypto.SignerFromDigestSigner(rs), nil
}

func (a signerKEMAdapter) GenerateKEMSuccessor(handle, kemAlg string) ([]byte, error) {
	protoAlg := eepqc.KEMAlgorithmToProto(crypto.Algorithm(kemAlg))
	if protoAlg == signing.KEMAlgorithm(0) {
		return nil, fmt.Errorf("pcas KEM rewrap: unsupported KEM algorithm %q", kemAlg)
	}
	pub, err := a.custody.GenerateSuccessorKEM(a.ctx, handle, protoAlg)
	if err != nil {
		return nil, err
	}
	return pub.PublicDER, nil
}

func (w *BreadthWorker) proveSignerDecapsulation(ctx context.Context, handle, kemAlg string, pubDER []byte) error {
	ct, want, err := eepqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm(kemAlg), DER: pubDER})
	if err != nil {
		return fmt.Errorf("pcas KEM rewrap: encapsulate proof challenge: %w", err)
	}
	defer secret.Wipe(want)
	got, err := w.kem.Decapsulate(ctx, handle, ct)
	if err != nil {
		return fmt.Errorf("pcas KEM rewrap: signer decapsulation proof: %w", err)
	}
	defer secret.Wipe(got)
	if !bytes.Equal(got, want) {
		return errors.New("pcas KEM rewrap: signer decapsulation proof mismatch")
	}
	return nil
}

func (w *BreadthWorker) handleRecovery(ctx context.Context, tenantID string, payload []byte) error {
	var env requestEnvelope[recoveryPayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas recovery: decode payload: %w", err)
	}
	p := env.Request
	if p.SuccessorHandle != succession.TenantKeyHandle(tenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas recovery: successor handle is not bound to tenant, identity and epoch")
	}
	if env.RequestID == "" || w.log == nil {
		return errors.New("pcas recovery: request id and event log are required")
	}
	requestBytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	requestDigest := crypto.SHA256Sum(requestBytes)
	recordEventID := succession.RecoveryRecordEventID(tenantID, p.IdentityID, p.Epoch)
	if prior, found, err := w.log.EventByID(ctx, recordEventID); err != nil {
		return err
	} else if found {
		return w.applyExistingRecovery(ctx, prior, tenantID, p.IdentityID, p.Epoch, env.RequestID, requestDigest)
	}
	if w.repo == nil {
		return errors.New("pcas recovery: recovery policy store unavailable")
	}
	policy, found, err := w.repo.GetRecoveryPolicy(ctx, tenantID, p.IdentityID)
	if err != nil {
		return fmt.Errorf("pcas recovery: read recovery policy: %w", err)
	}
	if !found {
		return errors.New("pcas recovery: recovery policy not configured for this tenant identity")
	}
	var configured []recovery.Approver
	if err := json.Unmarshal(policy.RosterJSON, &configured); err != nil {
		return fmt.Errorf("pcas recovery: decode configured roster: %w", err)
	}
	var auth recovery.RecoveryAuthorization
	if err := json.Unmarshal(p.Authorization, &auth); err != nil {
		return fmt.Errorf("pcas recovery: decode authorization: %w", err)
	}
	expected := recovery.Expected{IdentityID: p.IdentityID, TenantID: tenantID,
		Epoch: p.Epoch, SuccessorAlg: p.TargetAlgorithm, SuccessorPub: auth.Statement.SuccessorPub}
	if err := recovery.VerifyConfiguredPolicy(recovery.Policy{
		TrustRootDER: policy.TrustRootDER, Threshold: policy.Threshold, Roster: configured,
	}, p.TrustRootDER, auth, expected, p.DeploymentScope); err != nil {
		return fmt.Errorf("pcas recovery: configured policy refusal: %w", err)
	}
	preparedID := succession.RecoverySuccessorEventID(tenantID, p.IdentityID, p.Epoch)
	preparedEvent, preparedFound, err := w.log.EventByID(ctx, preparedID)
	if err != nil {
		return err
	}
	if !preparedFound {
		return errors.New("pcas recovery: successor has no immutable preparation receipt")
	}
	if err := w.verifyPreparedSuccessorReadback(ctx, preparedEvent, tenantID, p.IdentityID,
		p.Epoch, p.TargetAlgorithm, p.DeploymentScope, p.SuccessorHandle); err != nil {
		return err
	}
	anchor, found, err := w.repo.GetGenesis(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	if !found || anchor.Genesis.DeploymentScope != p.DeploymentScope {
		return errors.New("pcas recovery: genesis or deployment scope mismatch")
	}
	highWater, err := w.highWater(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	if p.PredecessorEpoch != highWater || p.Epoch != highWater+1 {
		return errors.New("pcas recovery: predecessor and successor epochs do not follow the current chain")
	}
	predecessorAlg, predecessorPub := string(anchor.Genesis.Algorithm), anchor.Genesis.PublicKey
	if highWater > 0 {
		rows, err := w.repo.FetchChain(ctx, tenantID, p.IdentityID)
		if err != nil {
			return err
		}
		if len(rows) == 0 || rows[len(rows)-1].Epoch != highWater {
			return errors.New("pcas recovery: current predecessor record is missing")
		}
		predecessorAlg, predecessorPub = rows[len(rows)-1].SuccessorAlg, rows[len(rows)-1].SuccessorPub
	}
	if p.PredecessorAlgorithm != predecessorAlg || !bytes.Equal(p.PredecessorPublicDER, predecessorPub) {
		return errors.New("pcas recovery: claimed predecessor differs from current tenant chain")
	}
	if w.kem == nil {
		return errors.New("pcas recovery: no signer custody configured")
	}
	successorRemote, err := w.kem.SignerForHandle(ctx, p.SuccessorHandle)
	if err != nil {
		return fmt.Errorf("pcas recovery: prepared successor absent from signer: %w", err)
	}
	if string(successorRemote.Algorithm()) != p.TargetAlgorithm ||
		!bytes.Equal(successorRemote.Public().DER, auth.Statement.SuccessorPub) {
		return errors.New("pcas recovery: prepared signer key differs from signed approval")
	}
	successor := crypto.SignerFromDigestSigner(successorRemote)
	now := time.Now().UTC()
	fields := succession.CommitmentFields{
		DeploymentScope:   p.DeploymentScope,
		IdentityID:        p.IdentityID,
		TenantID:          tenantID,
		PredecessorEpoch:  p.PredecessorEpoch,
		Epoch:             p.Epoch,
		PredecessorAlg:    crypto.Algorithm(p.PredecessorAlgorithm),
		PredecessorPub:    p.PredecessorPublicDER,
		PolicyRef:         "pcas:recovery:" + env.RequestID,
		HashAlg:           succession.HashAlgSHA256,
		NotBefore:         now.Unix(),
		NotAfter:          now.Add(365 * 24 * time.Hour).Unix(),
		CommitmentVersion: 2,
		RecordType:        succession.RecordType("recovery"),
	}
	rec, err := recovery.Mint(fields, auth, p.TrustRootDER, successor, highWater)
	if err != nil {
		return fmt.Errorf("pcas recovery: mint: %w", err)
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	source, err := succession.Encode(succession.RecoveryRecordedV1{
		TenantID: tenantID, IdentityID: p.IdentityID, Epoch: p.Epoch,
		RequestID: env.RequestID, RequestDigest: requestDigest,
		TrustRootDER: p.TrustRootDER, RecordJSON: encoded,
	})
	if err != nil {
		return err
	}
	source.ID = recordEventID
	recorded, err := w.log.Append(ctx, source)
	if err != nil {
		return fmt.Errorf("pcas recovery: append immutable record: %w", err)
	}
	return w.applyExistingRecovery(ctx, recorded, tenantID, p.IdentityID, p.Epoch, env.RequestID, requestDigest)
}

func (w *BreadthWorker) applyExistingRecovery(ctx context.Context, ev events.Event,
	tenantID, identityID string, epoch uint64, requestID string, requestDigest []byte) error {
	if ev.TenantID != tenantID || ev.Type != succession.TypeRecoveryRecorded ||
		ev.ID != succession.RecoveryRecordEventID(tenantID, identityID, epoch) {
		return errors.New("pcas recovery: first-writer event is not the requested tenant identity epoch")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	prior, ok := decoded.(succession.RecoveryRecordedV1)
	if !ok || prior.TenantID != tenantID || prior.IdentityID != identityID ||
		prior.Epoch != epoch || prior.RequestID != requestID ||
		!bytes.Equal(prior.RequestDigest, requestDigest) {
		return errors.New("pcas recovery: immutable record belongs to a different request")
	}
	if w.repo == nil {
		return errors.New("pcas recovery: projection store unavailable")
	}
	if err := w.repo.ApplyRecoveryRecordEvent(ctx, ev); err != nil {
		return err
	}
	return w.ensureRecoveryProof(ctx, tenantID, identityID, epoch, requestID)
}

// ensureRecoveryProof signs an RFC-6962 head over the indexed, per-identity
// recovery leaf projection. The leaf order is epoch order, so new recoveries
// extend rather than reorder the tree. The proof is a second immutable event;
// a crash after either append is recovered by the same outbox retry.
func (w *BreadthWorker) ensureRecoveryProof(ctx context.Context, tenantID, identityID string,
	epoch uint64, requestID string) error {
	if w.repo == nil || w.log == nil || w.kem == nil {
		return errors.New("pcas recovery proof: event log, store and signer are required")
	}
	proofID := succession.RecoveryProofEventID(tenantID, identityID, epoch)
	if prior, found, err := w.log.EventByID(ctx, proofID); err != nil {
		return err
	} else if found {
		return w.applyExistingRecoveryProof(ctx, prior, tenantID, identityID, epoch, requestID)
	}
	anchor, found, err := w.repo.GetGenesis(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("pcas recovery proof: tenant genesis is absent")
	}
	root, err := w.kem.SignerForHandle(ctx, succession.TenantRootHandle(tenantID))
	if err != nil {
		return fmt.Errorf("pcas recovery proof: isolated log signer: %w", err)
	}
	if !bytes.Equal(root.Public().DER, anchor.TrustRootPublicDER) {
		return errors.New("pcas recovery proof: isolated log signer differs from tenant genesis")
	}
	leaves, index, err := w.repo.RecoveryLogLeaves(ctx, tenantID, identityID, epoch)
	if err != nil {
		return err
	}
	log := translog.New(crypto.SignerFromDigestSigner(root))
	for _, leaf := range leaves {
		if _, _, err := log.Append(leaf); err != nil {
			return err
		}
	}
	proof, err := log.Prove(index)
	if err != nil {
		return err
	}
	encoded := translog.EncodeProof(proof)
	if err := translog.VerifyEncodedInclusion(leaves[index], encoded, root.Public().DER); err != nil {
		return fmt.Errorf("pcas recovery proof: signer head readback: %w", err)
	}
	source, err := succession.Encode(succession.RecoveryProofIssuedV1{
		TenantID: tenantID, IdentityID: identityID, Epoch: epoch, RequestID: requestID,
		RecordEventID:   succession.RecoveryRecordEventID(tenantID, identityID, epoch),
		LogPublicKeyDER: root.Public().DER, ProofBytes: encoded,
	})
	if err != nil {
		return err
	}
	source.ID = proofID
	recorded, err := w.log.Append(ctx, source)
	if err != nil {
		return fmt.Errorf("pcas recovery proof: append signed proof: %w", err)
	}
	return w.applyExistingRecoveryProof(ctx, recorded, tenantID, identityID, epoch, requestID)
}

func (w *BreadthWorker) applyExistingRecoveryProof(ctx context.Context, ev events.Event,
	tenantID, identityID string, epoch uint64, requestID string) error {
	if ev.TenantID != tenantID || ev.Type != succession.TypeRecoveryProofIssued ||
		ev.ID != succession.RecoveryProofEventID(tenantID, identityID, epoch) {
		return errors.New("pcas recovery proof: first-writer event is not this recovery")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	p, ok := decoded.(succession.RecoveryProofIssuedV1)
	if !ok || p.TenantID != tenantID || p.IdentityID != identityID ||
		p.Epoch != epoch || p.RequestID != requestID ||
		p.RecordEventID != succession.RecoveryRecordEventID(tenantID, identityID, epoch) {
		return errors.New("pcas recovery proof: immutable proof belongs to another request")
	}
	return w.repo.ApplyRecoveryProofEvent(ctx, ev)
}

func (w *BreadthWorker) handleFederationImport(ctx context.Context, tenantID string, payload []byte) error {
	if w.kem == nil || w.log == nil || w.repo == nil {
		return errors.New("pcas federation: signer custody, event log and store are required")
	}
	var env requestEnvelope[federationImportPayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas federation: decode payload: %w", err)
	}
	p := env.Request
	if env.RequestID == "" {
		return errors.New("pcas federation: request id is required")
	}
	if p.LocalAuthorityHandle != succession.TenantKeyHandle(tenantID, p.LocalDeploymentID, 0) {
		return errors.New("pcas federation: local authority handle is not tenant-bound")
	}
	localGenesis, found, err := w.repo.GetGenesis(ctx, tenantID, p.LocalDeploymentID)
	if err != nil {
		return err
	}
	if !found || localGenesis.Genesis.TenantID != tenantID ||
		localGenesis.Genesis.IdentityID != p.LocalDeploymentID {
		return errors.New("pcas federation: local authority has no tenant-bound genesis")
	}
	if err := succession.VerifyGenesis(localGenesis.TrustRootPublicDER, localGenesis.Genesis); err != nil {
		return fmt.Errorf("pcas federation: local authority genesis: %w", err)
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return err
	}
	requestDigest := crypto.SHA256Sum(canonical)
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pcas.federation.bridge.v1\x00"+tenantID+"\x00"+env.RequestID)).String()
	applyPrior := func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != succession.TypeFederationBridgeImported {
			return errors.New("pcas federation: request id belongs to another event")
		}
		decoded, err := succession.Decode(ev)
		if err != nil {
			return err
		}
		prior, ok := decoded.(succession.FederationBridgeImportedV1)
		if !ok || prior.RequestID != env.RequestID ||
			!bytes.Equal(prior.RequestDigest, requestDigest) {
			return errors.New("pcas federation: request id belongs to another import")
		}
		return w.repo.ApplyFederationBridgeEvent(ctx, ev)
	}
	if prior, found, err := w.log.EventByID(ctx, eventID); err != nil {
		return err
	} else if found {
		return applyPrior(prior)
	}
	localRemote, err := w.kem.SignerForHandle(ctx, p.LocalAuthorityHandle)
	if err != nil {
		return fmt.Errorf("pcas federation: bind local authority handle: %w", err)
	}
	if !bytes.Equal(localRemote.Public().DER, localGenesis.Genesis.PublicKey) {
		return errors.New("pcas federation: isolated local authority key differs from tenant genesis")
	}
	localAuthority := crypto.SignerFromDigestSigner(localRemote)
	var genesis succession.GenesisRecord
	if err := json.Unmarshal(p.ForeignGenesis, &genesis); err != nil {
		return fmt.Errorf("pcas federation: decode foreign genesis: %w", err)
	}
	chain := make([]succession.SuccessionRecord, 0, len(p.ForeignChain))
	for _, raw := range p.ForeignChain {
		var rec succession.SuccessionRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("pcas federation: decode foreign chain: %w", err)
		}
		chain = append(chain, rec)
	}
	result, err := federation.Import(localAuthority, p.LocalDeploymentID, p.ForeignTrustRootDER, genesis, chain, p.LocalBaseEpoch)
	if err != nil && !errors.Is(err, federation.ErrImportVerification) {
		return fmt.Errorf("pcas federation: import: %w", err)
	}
	if result.Bridge != nil {
		if result.Bridge.ForeignDeployment != p.ForeignDeploymentID ||
			result.Bridge.LocalDeployment != p.LocalDeploymentID ||
			result.Bridge.IdentityID != p.IdentityID ||
			result.Bridge.LocalBaseEpoch != p.LocalBaseEpoch {
			return errors.New("pcas federation: signed bridge does not match requested deployments or identity")
		}
		if err := federation.VerifyBridge(localRemote.Public().DER, nil, *result.Bridge, false); err != nil {
			return fmt.Errorf("pcas federation: signed bridge verification: %w", err)
		}
		bridgeJSON, err := json.Marshal(result.Bridge)
		if err != nil {
			return err
		}
		ev, err := succession.Encode(succession.FederationBridgeImportedV1{
			TenantID: tenantID, RequestID: env.RequestID, RequestDigest: requestDigest,
			ForeignDeploymentID: p.ForeignDeploymentID, LocalDeploymentID: p.LocalDeploymentID,
			IdentityID: p.IdentityID, ForeignTrustRootDER: p.ForeignTrustRootDER,
			LocalAuthorityPublicDER: localRemote.Public().DER,
			LocalBaseEpoch:          p.LocalBaseEpoch, Bridge: bridgeJSON,
		})
		if err != nil {
			return err
		}
		ev.ID = eventID
		recorded, err := w.log.Append(ctx, ev)
		if err != nil {
			return err
		}
		return applyPrior(recorded)
	}
	if result.Quarantine != nil {
		proofJSON, _ := json.Marshal(result.Quarantine)
		return w.repo.SaveFederationQuarantine(ctx, tenantID, pcasstore.FederationQuarantine{
			ForeignDeploymentID: p.ForeignDeploymentID,
			IdentityID:          p.IdentityID,
			Reason:              result.Quarantine.Reason,
			ProofJSON:           proofJSON,
		})
	}
	return err
}

func (w *BreadthWorker) recordKEMRewrapRequest(ctx context.Context, tenantID, identityID string,
	predecessorEpoch uint64, requestID string, requestDigest []byte, stages []string) error {
	source, err := succession.Encode(succession.KEMRewrapRequestedV1{
		TenantID: tenantID, IdentityID: identityID, PredecessorEpoch: predecessorEpoch,
		RequestID: requestID, RequestDigest: requestDigest, Stages: stages,
	})
	if err != nil {
		return err
	}
	source.ID = succession.KEMRewrapRequestEventID(tenantID, requestID)
	if prior, found, err := w.log.EventByID(ctx, source.ID); err != nil {
		return err
	} else if found {
		if prior.TenantID != tenantID || prior.Type != source.Type ||
			prior.SchemaVersion != source.SchemaVersion || !bytes.Equal(prior.Data, source.Data) {
			return errors.New("pcas KEM rewrap: request ID belongs to another immutable request")
		}
		return w.repo.ApplyKEMRewrapRequestedEvent(ctx, prior)
	}
	recorded, err := w.log.Append(ctx, source)
	if err != nil {
		return err
	}
	if recorded.TenantID != tenantID || recorded.Type != source.Type ||
		recorded.SchemaVersion != source.SchemaVersion || !bytes.Equal(recorded.Data, source.Data) {
		return errors.New("pcas KEM rewrap: request ID append collided with another immutable request")
	}
	return w.repo.ApplyKEMRewrapRequestedEvent(ctx, recorded)
}

func (w *BreadthWorker) recordKEMRewrap(ctx context.Context, tenantID string,
	fields succession.CommitmentFields, encoded []byte, requestID string, requestDigest []byte, stages []string) error {
	source, err := succession.Encode(succession.KEMRewrapRecordedV1{
		TenantID: tenantID, IdentityID: fields.IdentityID, Epoch: fields.Epoch,
		RequestID: requestID, RequestDigest: requestDigest, RecordJSON: encoded, Stages: stages,
	})
	if err != nil {
		return err
	}
	source.ID = succession.KEMRewrapRecordEventID(tenantID, fields.IdentityID, fields.Epoch)
	recorded, err := w.log.Append(ctx, source)
	if err != nil {
		return fmt.Errorf("pcas KEM rewrap: append immutable paired record: %w", err)
	}
	return w.applyExistingKEMRewrap(ctx, recorded, tenantID, fields.IdentityID, fields.Epoch, requestID, requestDigest, stages)
}

func (w *BreadthWorker) applyExistingKEMRewrap(ctx context.Context, ev events.Event,
	tenantID, identityID string, epoch uint64, requestID string, requestDigest []byte, stages []string) error {
	if ev.TenantID != tenantID || ev.Type != succession.TypeKEMRewrapRecorded ||
		ev.ID != succession.KEMRewrapRecordEventID(tenantID, identityID, epoch) {
		return errors.New("pcas KEM rewrap: first-writer event differs from tenant identity epoch")
	}
	decoded, err := succession.Decode(ev)
	if err != nil {
		return err
	}
	prior, ok := decoded.(succession.KEMRewrapRecordedV1)
	if !ok || prior.TenantID != tenantID || prior.IdentityID != identityID ||
		prior.Epoch != epoch || prior.RequestID != requestID ||
		!bytes.Equal(prior.RequestDigest, requestDigest) || len(prior.Stages) != len(stages) {
		return errors.New("pcas KEM rewrap: immutable paired record belongs to another request")
	}
	for i := range stages {
		if prior.Stages[i] != stages[i] {
			return errors.New("pcas KEM rewrap: immutable paired record has a different stage set")
		}
	}
	return w.repo.ApplyKEMRewrapRecordEvent(ctx, ev)
}

func (w *BreadthWorker) highWater(ctx context.Context, tenantID, identityID string) (uint64, error) {
	var epoch uint64
	if w.core == nil {
		return 0, nil
	}
	err := w.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT epoch FROM identity_algorithm_epoch
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`, identityID).Scan(&epoch)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		return e
	})
	return epoch, err
}
