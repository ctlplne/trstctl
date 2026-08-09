// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/succession"
	pcasdelegation "trstctl.com/trstctl/ee/succession/delegation"
	pcasissuer "trstctl.com/trstctl/ee/succession/issuer"
	pcasstaple "trstctl.com/trstctl/ee/succession/staple"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

// SuccessionRequestDestination is the outbox destination for an accepted succession
// request. The signer-side orchestrator (PCAS-08) consumes it and mints the
// successor; the IdempotencyKey renders redeliveries exactly-once (AN-5 ↔ AN-6).
const (
	SuccessionRequestDestination = "pcas.succession-request"
	RecoveryRequestDestination   = "pcas.recovery-request"
	FederationImportDestination  = "pcas.federation-import"
	KEMRewrapDestination         = "pcas.kem-rewrap"
)

// service is the store/log/outbox-backed PCAS API Service. Request-succession
// enqueues an idempotent job through the core outbox; chain-fetch reads the
// RLS-scoped succession store; ack-record appends a signed nhi.rp.ack to the AN-2
// ledger. HTTP-level idempotency (api.Mutate) makes a replayed Idempotency-Key
// return the original result without re-invoking these methods (PCAS-claim-6).
type service struct {
	store          *corestore.Store
	repo           *pcasstore.Repo
	log            *events.Log
	outbox         *orchestrator.Outbox
	signerStoreDir string
	kem            editionseam.KEMCustody
	// Breadth outbox topics, resolved from pcas.{recovery,federation,kem}.
	// outbox_topic (AUD-7: the config was validated and never read — an operator
	// who re-pointed a topic still enqueued to the hardcoded constant). Empty
	// falls back to the canonical constants; the dispatch side resolves the SAME
	// configuration, so both ends of the outbox always agree.
	recoveryTopic   string
	federationTopic string
	kemTopic        string
}

type ServiceOption func(*service)

func WithSignerStoreDir(dir string) ServiceOption {
	return func(s *service) { s.signerStoreDir = dir }
}

func WithKEMCustody(kem editionseam.KEMCustody) ServiceOption {
	return func(s *service) { s.kem = kem }
}

// WithOutboxTopics resolves the breadth destinations from operator
// configuration (pcas.recovery/federation/kem.outbox_topic). Blank values keep
// the canonical defaults, so an unset config changes nothing.
func WithOutboxTopics(recovery, federation, kem string) ServiceOption {
	return func(s *service) {
		s.recoveryTopic = strings.TrimSpace(recovery)
		s.federationTopic = strings.TrimSpace(federation)
		s.kemTopic = strings.TrimSpace(kem)
	}
}

// topicOr returns configured when non-empty, else the canonical fallback.
func topicOr(configured, fallback string) string {
	if configured != "" {
		return configured
	}
	return fallback
}

var (
	ErrIssuerNotFound     = errors.New("pcas api: issuer authority not found")
	ErrSignerUnavailable  = errors.New("pcas api: signer custody unavailable")
	ErrCheckpointNotFound = errors.New("pcas api: checkpoint not found")
)

const defaultReporterHandle = "pcas-checkpoint-signer"

// NewService builds the store/log/outbox-backed PCAS API Service. It is exported so
// the attach seam and integration tests construct the concrete service directly.
func NewService(store *corestore.Store, log *events.Log, outbox *orchestrator.Outbox, opts ...ServiceOption) Service {
	s := &service{store: store, log: log, outbox: outbox}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if store != nil {
		s.repo = pcasstore.New(store)
	}
	return s
}

var _ Service = (*service)(nil)

// RequestSuccession records an accepted succession request as an idempotent outbox
// job for the signer to mint (AN-4/AN-5/AN-6). It returns a request acknowledgement;
// the actual dual-signed record is produced asynchronously by the signer-side
// orchestrator.
func (s *service) RequestSuccession(ctx context.Context, tenantID string, req RequestSuccessionRequest) (RequestSuccessionResponse, error) {
	requestID := events.NewID()
	payload, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		RequestSuccessionRequest
	}{RequestID: requestID, RequestSuccessionRequest: req})
	if err != nil {
		return RequestSuccessionResponse{}, err
	}
	if s.store != nil && s.outbox != nil {
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: SuccessionRequestDestination,
				IdempotencyKey: requestID, Payload: payload,
			})
			return err
		}); err != nil {
			return RequestSuccessionResponse{}, fmt.Errorf("pcas api: enqueue succession request: %w", err)
		}
	}
	return RequestSuccessionResponse{
		RequestID:       requestID,
		IdentityID:      req.IdentityID,
		CredentialType:  req.CredentialType,
		TargetAlgorithm: req.TargetAlgorithm,
		Status:          "queued",
		QueuedAt:        time.Now().UTC(),
	}, nil
}

func (s *service) ConfigureDelegationScope(ctx context.Context, tenantID string, req DelegationScopeRequest) (DelegationScopeResponse, error) {
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.UpsertDelegationScope(ctx, tenantID, pcasstore.DelegationScope{
			ScopeID: req.ScopeID, ParentScopeID: req.ParentScopeID, EpochFloor: req.EpochFloor,
		}); err != nil {
			return DelegationScopeResponse{}, err
		}
	}
	if s.signerStoreDir != "" {
		ds := pcasdelegation.NewDurableScopeStore(s.signerStoreDir)
		if err := ds.UpsertScope(pcasdelegation.Scope{
			ID: req.ScopeID, Parent: req.ParentScopeID,
			Constraint: pcasdelegation.Constraint{EpochFloor: req.EpochFloor},
		}); err != nil {
			return DelegationScopeResponse{}, fmt.Errorf("pcas api: provision signer delegation scope: %w", err)
		}
	}
	return DelegationScopeResponse{
		ScopeID: req.ScopeID, ParentScopeID: req.ParentScopeID, EpochFloor: req.EpochFloor,
		Status: "configured", UpdatedAt: updated,
	}, nil
}

func (s *service) RaiseDelegationFloor(ctx context.Context, tenantID string, req DelegationFloorRequest) (DelegationScopeResponse, error) {
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.RaiseDelegationFloor(ctx, tenantID, req.ScopeID, req.EpochFloor); err != nil {
			return DelegationScopeResponse{}, err
		}
	}
	if s.signerStoreDir != "" {
		ds := pcasdelegation.NewDurableScopeStore(s.signerStoreDir)
		if err := ds.RaiseFloor(req.ScopeID, req.EpochFloor); err != nil {
			return DelegationScopeResponse{}, fmt.Errorf("pcas api: provision signer delegation floor: %w", err)
		}
	}
	return DelegationScopeResponse{ScopeID: req.ScopeID, EpochFloor: req.EpochFloor, Status: "raised", UpdatedAt: updated}, nil
}

func (s *service) ConfigureRecoveryPolicy(ctx context.Context, tenantID string, req RecoveryPolicyRequest) (RecoveryPolicyResponse, error) {
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.UpsertRecoveryPolicy(ctx, tenantID, pcasstore.RecoveryPolicy{
			IdentityID: req.IdentityID, Threshold: req.Threshold, RosterJSON: req.Roster, TrustRootDER: req.TrustRootDER,
		}); err != nil {
			return RecoveryPolicyResponse{}, err
		}
	}
	return RecoveryPolicyResponse{IdentityID: req.IdentityID, Status: "configured", UpdatedAt: updated}, nil
}

func (s *service) RequestRecovery(ctx context.Context, tenantID string, req RecoveryRequest) (AsyncRequestResponse, error) {
	return s.enqueue(ctx, tenantID, topicOr(s.recoveryTopic, RecoveryRequestDestination), req.IdentityID, req)
}

func (s *service) RequestFederationImport(ctx context.Context, tenantID string, req FederationImportRequest) (AsyncRequestResponse, error) {
	if s.repo != nil {
		if err := s.repo.UpsertFederationBridge(ctx, tenantID, pcasstore.FederationBridge{
			ForeignDeploymentID: req.ForeignDeploymentID,
			IdentityID:          req.IdentityID,
			ForeignTrustRootDER: req.ForeignTrustRootDER,
			LocalBaseEpoch:      req.LocalBaseEpoch,
		}); err != nil {
			return AsyncRequestResponse{}, err
		}
	}
	return s.enqueue(ctx, tenantID, topicOr(s.federationTopic, FederationImportDestination), req.ForeignDeploymentID, req)
}

func (s *service) RequestKEMRewrap(ctx context.Context, tenantID string, req KEMRewrapRequest) (AsyncRequestResponse, error) {
	if len(req.Stages) == 0 {
		req.Stages = []string{"default"}
	}
	resp, err := s.enqueue(ctx, tenantID, topicOr(s.kemTopic, KEMRewrapDestination), req.IdentityID, req)
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if s.repo != nil {
		total := len(req.Stages)
		for _, stage := range req.Stages {
			if err := s.repo.UpsertRewrapJob(ctx, tenantID, pcasstore.RewrapJob{
				JobID: resp.RequestID, IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch,
				Stage: stage, TotalStages: total, Status: "queued",
			}); err != nil {
				return AsyncRequestResponse{}, err
			}
		}
	}
	return resp, nil
}

func (s *service) RegisterIssuerAuthority(ctx context.Context, tenantID string, req IssuerAuthorityRequest) (IssuerAuthorityResponse, error) {
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.UpsertIssuerAuthority(ctx, tenantID, pcasstore.IssuerAuthority{
			IssuerID: req.IssuerID, IdentityID: req.IdentityID, CurrentEpoch: req.CurrentEpoch, CAKeyHandle: req.CAKeyHandle, CACertDER: req.CACertDER,
		}); err != nil {
			return IssuerAuthorityResponse{}, err
		}
	}
	return IssuerAuthorityResponse{
		IssuerID: req.IssuerID, IdentityID: req.IdentityID, CurrentEpoch: req.CurrentEpoch,
		CAKeyHandle: req.CAKeyHandle, Status: "registered", UpdatedAt: updated,
	}, nil
}

func (s *service) IssueIssuerLeaf(ctx context.Context, tenantID string, req IssueLeafRequest) (IssueLeafResponse, error) {
	authority, err := s.issuerAuthority(ctx, tenantID, req.IssuerID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	ca, err := s.caSigner(ctx, authority.CAKeyHandle)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	ttl := leafTTL(req.TTLSeconds)
	rotation := req.RotationVersion
	if rotation == 0 {
		rotation = 1
	}
	certDER, err := pcasissuer.IssueLeafCertificate(authority.CACertDER, ca, req.CSRDER, pcasissuer.IssuerPosture{
		IssuerID:  authority.IssuerID,
		Epoch:     authority.CurrentEpoch,
		Algorithm: string(ca.Algorithm()),
		PublicDER: ca.Public().DER,
	}, rotation, ttl)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	return IssueLeafResponse{
		IssuerID: authority.IssuerID, IdentityID: authority.IdentityID, Epoch: authority.CurrentEpoch,
		RotationVersion: rotation, CertDER: certDER, IssuedAt: time.Now().UTC(),
	}, nil
}

func (s *service) IssueStapledLeaf(ctx context.Context, tenantID string, req IssueStapledLeafRequest) (IssueLeafResponse, error) {
	authority, err := s.issuerAuthority(ctx, tenantID, req.IssuerID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	identityID := req.CheckpointIdentityID
	if identityID == "" {
		identityID = authority.IdentityID
	}
	cp, found, err := s.LatestCheckpoint(ctx, tenantID, identityID)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	if !found {
		return IssueLeafResponse{}, ErrCheckpointNotFound
	}
	var signed succession.SignedEpochCheckpoint
	if len(cp.CheckpointJSON) > 0 {
		if err := json.Unmarshal(cp.CheckpointJSON, &signed); err != nil {
			return IssueLeafResponse{}, err
		}
	} else {
		signed = succession.SignedEpochCheckpoint{
			IdentityID: cp.IdentityID, TenantID: tenantID, Epoch: cp.Epoch, LogTreeSize: cp.LogTreeSize,
			LogRootHash: cp.LogRoot, Signature: cp.Signature,
		}
	}
	ca, err := s.caSigner(ctx, authority.CAKeyHandle)
	if err != nil {
		return IssueLeafResponse{}, err
	}
	certDER, err := pcasstaple.IssueStapledLeaf(authority.CACertDER, ca, req.CSRDER, pcasstaple.Attachment{Checkpoint: &signed}, leafTTL(req.TTLSeconds))
	if err != nil {
		return IssueLeafResponse{}, err
	}
	return IssueLeafResponse{
		IssuerID: authority.IssuerID, IdentityID: authority.IdentityID, Epoch: authority.CurrentEpoch,
		CertDER: certDER, IssuedAt: time.Now().UTC(),
	}, nil
}

func (s *service) RewrapStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RewrapStatusResponse, error) {
	resp := RewrapStatusResponse{IdentityID: identityID, PredecessorEpoch: predecessorEpoch, Jobs: []RewrapJobState{}, CheckedAt: time.Now().UTC()}
	if s.repo == nil {
		return resp, nil
	}
	jobs, err := s.repo.ListRewrapJobs(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil {
		return RewrapStatusResponse{}, err
	}
	for _, job := range jobs {
		resp.Jobs = append(resp.Jobs, RewrapJobState{
			JobID: job.JobID, Stage: job.Stage, TotalStages: job.TotalStages,
			CompletedStages: job.CompletedStages, Status: job.Status, UpdatedAt: job.UpdatedAt,
		})
	}
	if predecessorEpoch != 0 {
		resp.Complete, err = s.repo.RewrapComplete(ctx, tenantID, identityID, predecessorEpoch)
		if err != nil {
			return RewrapStatusResponse{}, err
		}
	} else {
		resp.Complete = len(resp.Jobs) > 0
		for _, job := range resp.Jobs {
			resp.Complete = resp.Complete && job.Status == "complete"
		}
	}
	return resp, nil
}

func (s *service) ConfigureRetirementPolicy(ctx context.Context, tenantID string, req RetirementPolicyRequest) (RetirementPolicyResponse, error) {
	updated := time.Now().UTC()
	if s.repo != nil {
		if err := s.repo.UpsertRetirementPolicy(ctx, tenantID, pcasstore.RetirementPolicy{
			IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch, Threshold: req.Threshold,
			RosterJSON: req.Roster, ValidityWindowSeconds: req.ValidityWindowSeconds,
			PredecessorHandle: req.PredecessorHandle, Status: "active",
		}); err != nil {
			return RetirementPolicyResponse{}, err
		}
	}
	complete := false
	if s.repo != nil {
		var err error
		complete, err = s.repo.RewrapComplete(ctx, tenantID, req.IdentityID, req.PredecessorEpoch)
		if err != nil {
			return RetirementPolicyResponse{}, err
		}
	}
	return RetirementPolicyResponse{
		IdentityID: req.IdentityID, PredecessorEpoch: req.PredecessorEpoch, Threshold: req.Threshold,
		Roster: req.Roster, ValidityWindowSeconds: req.ValidityWindowSeconds,
		PredecessorHandle: req.PredecessorHandle, Status: "active", UpdatedAt: updated, RewrapComplete: complete,
	}, nil
}

func (s *service) RetirementStatus(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RetirementPolicyResponse, bool, error) {
	if s.repo == nil {
		return RetirementPolicyResponse{}, false, nil
	}
	policy, found, err := s.repo.GetRetirementPolicy(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil || !found {
		return RetirementPolicyResponse{}, found, err
	}
	complete, err := s.repo.RewrapComplete(ctx, tenantID, identityID, predecessorEpoch)
	if err != nil {
		return RetirementPolicyResponse{}, false, err
	}
	return retirementPolicyResponse(policy, complete), true, nil
}

func (s *service) LatestCheckpoint(ctx context.Context, tenantID, identityID string) (CheckpointResponse, bool, error) {
	if s.repo == nil {
		return CheckpointResponse{}, false, nil
	}
	cp, found, err := s.repo.LatestCheckpoint(ctx, tenantID, identityID)
	if err != nil || !found {
		return CheckpointResponse{}, found, err
	}
	return CheckpointResponse{
		IdentityID: cp.IdentityID, Epoch: cp.Epoch, LogTreeSize: cp.LogTreeSize, LogRoot: cp.LogRoot,
		Signature: cp.Signature, CheckpointJSON: cp.CheckpointJSON, IssuedAt: cp.IssuedAt,
	}, true, nil
}

func (s *service) PostureReport(ctx context.Context, tenantID, identityID string) (PostureReportResponse, bool, error) {
	if s.repo == nil {
		return PostureReportResponse{}, false, nil
	}
	rec, found, err := s.repo.LatestRecord(ctx, tenantID, identityID)
	if err != nil || !found {
		return PostureReportResponse{}, found, err
	}
	reporter, err := s.reporterSigner(ctx)
	if err != nil {
		return PostureReportResponse{}, false, err
	}
	digest := crypto.SHA256Sum(rec.Encoded)
	report := succession.BuildPostureReport(succession.IdentityPosture{
		IdentityID:       rec.IdentityID,
		TenantID:         tenantID,
		CurrentEpoch:     rec.Epoch,
		CurrentAlgorithm: rec.SuccessorAlg,
		CurrentPublicDER: rec.SuccessorPub,
		State:            succession.StateActive,
	}, digest)
	signed, err := succession.SignPostureReport(crypto.SignerFromDigestSigner(reporter), report)
	if err != nil {
		return PostureReportResponse{}, false, err
	}
	return PostureReportResponse{
		IdentityID: signed.IdentityID, TenantID: signed.TenantID, Algorithm: string(signed.Algorithm),
		Epoch: signed.Epoch, IntroducingRecordDigest: signed.IntroducingRecordDigest,
		Signature: signed.Signature, ReporterPublicDER: reporter.Public().DER, IssuedAt: time.Now().UTC(),
	}, true, nil
}

func (s *service) ListMisissuance(ctx context.Context, tenantID string) (MisissuanceListResponse, error) {
	resp := MisissuanceListResponse{Findings: []MisissuanceResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	findings, err := s.repo.ListMisissuance(ctx, tenantID)
	if err != nil {
		return MisissuanceListResponse{}, err
	}
	for _, m := range findings {
		resp.Findings = append(resp.Findings, MisissuanceResponse{
			IdentityID: m.IdentityID, Epoch: m.Epoch, RecordADigest: m.RecordADigest, RecordBDigest: m.RecordBDigest,
			SignerA: m.SignerA, SignerB: m.SignerB, ProofJSON: m.ProofJSON, DetectedAt: m.DetectedAt,
		})
	}
	resp.Count = len(resp.Findings)
	return resp, nil
}

// ListFederationBridges serves the imported bridges with trust-root digests
// (AUD-9's missing read path). No repo means no bridges — an empty truthful
// answer, not an error.
func (s *service) ListFederationBridges(ctx context.Context, tenantID string) (FederationBridgeListResponse, error) {
	resp := FederationBridgeListResponse{Bridges: []FederationBridgeResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	bridges, err := s.repo.ListFederationBridges(ctx, tenantID)
	if err != nil {
		return FederationBridgeListResponse{}, err
	}
	for _, b := range bridges {
		digest := ""
		if len(b.ForeignTrustRootDER) > 0 {
			digest = hex.EncodeToString(crypto.SHA256Sum(b.ForeignTrustRootDER))
		}
		resp.Bridges = append(resp.Bridges, FederationBridgeResponse{
			ForeignDeploymentID: b.ForeignDeploymentID,
			IdentityID:          b.IdentityID,
			LocalBaseEpoch:      b.LocalBaseEpoch,
			TrustRootSHA256:     digest,
			UpdatedAt:           b.UpdatedAt,
		})
	}
	resp.Count = len(resp.Bridges)
	return resp, nil
}

func (s *service) enqueue(ctx context.Context, tenantID, destination, target string, req any) (AsyncRequestResponse, error) {
	requestID := events.NewID()
	payload, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		Request   any    `json:"request"`
	}{RequestID: requestID, Request: req})
	if err != nil {
		return AsyncRequestResponse{}, err
	}
	if s.store != nil && s.outbox != nil {
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: destination, IdempotencyKey: requestID, Payload: payload,
			})
			return err
		}); err != nil {
			return AsyncRequestResponse{}, fmt.Errorf("pcas api: enqueue %s: %w", destination, err)
		}
	}
	return AsyncRequestResponse{RequestID: requestID, Status: "queued", QueuedAt: time.Now().UTC(), Target: target}, nil
}

func (s *service) issuerAuthority(ctx context.Context, tenantID, issuerID string) (pcasstore.IssuerAuthority, error) {
	if s.repo == nil {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	authority, found, err := s.repo.GetIssuerAuthority(ctx, tenantID, issuerID)
	if err != nil {
		return pcasstore.IssuerAuthority{}, err
	}
	if !found {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	if authority.CAKeyHandle == "" || len(authority.CACertDER) == 0 {
		return pcasstore.IssuerAuthority{}, ErrIssuerNotFound
	}
	return authority, nil
}

func (s *service) caSigner(ctx context.Context, handle string) (*signing.RemoteSigner, error) {
	if s.kem == nil {
		return nil, ErrSignerUnavailable
	}
	return s.kem.SignerForHandleWithPurpose(ctx, handle, signing.PurposeCASign)
}

func (s *service) reporterSigner(ctx context.Context) (*signing.RemoteSigner, error) {
	if s.kem == nil {
		return nil, ErrSignerUnavailable
	}
	rs, err := s.kem.SignerForHandleWithPurpose(ctx, defaultReporterHandle, signing.PurposeGeneric)
	if err == nil {
		return rs, nil
	}
	rs, err = s.kem.GenerateKeyHandle(ctx, crypto.ECDSAP256, defaultReporterHandle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
	}
	return rs, nil
}

func leafTTL(seconds int64) time.Duration {
	if seconds <= 0 {
		return time.Hour
	}
	return time.Duration(seconds) * time.Second
}

func retirementPolicyResponse(policy pcasstore.RetirementPolicy, rewrapComplete bool) RetirementPolicyResponse {
	return RetirementPolicyResponse{
		IdentityID: policy.IdentityID, PredecessorEpoch: policy.PredecessorEpoch,
		Threshold: policy.Threshold, Roster: policy.RosterJSON,
		ValidityWindowSeconds: policy.ValidityWindowSeconds,
		PredecessorHandle:     policy.PredecessorHandle, Status: policy.Status,
		UpdatedAt: policy.UpdatedAt, RewrapComplete: rewrapComplete,
	}
}

// FetchChain returns identityID's ordered, gapless succession records (opaque
// encoded, PCAS-04), RLS-scoped to tenantID. The response verifies offline with
// PCAS-07.
func (s *service) FetchChain(ctx context.Context, tenantID, identityID string) (ChainResponse, error) {
	resp := ChainResponse{IdentityID: identityID, Records: [][]byte{}}
	if s.repo == nil {
		return resp, nil
	}
	recs, err := s.repo.FetchChain(ctx, tenantID, identityID)
	if err != nil {
		return ChainResponse{}, err
	}
	for _, r := range recs {
		resp.Records = append(resp.Records, r.Encoded)
	}
	resp.Count = len(resp.Records)
	return resp, nil
}

// RecordAck appends the relying party's signed acknowledgement as an nhi.rp.ack
// event on the AN-2 ledger, preserving the signature and identity/epoch binding so
// the PCAS-10 quorum can count it. The ledger stamps the recorded time (the quorum
// validity-window anchor).
func (s *service) RecordAck(ctx context.Context, tenantID string, req AckRequest) (AckResponse, error) {
	ev, err := succession.Encode(succession.RPAckV1{
		IdentityID:   req.IdentityID,
		TenantID:     tenantID,
		Epoch:        req.Epoch,
		RelyingParty: req.RelyingParty,
		AckSignature: req.Signature,
	})
	if err != nil {
		return AckResponse{}, err
	}
	recorded := ev
	if s.log != nil {
		recorded, err = s.log.Append(ctx, ev)
		if err != nil {
			return AckResponse{}, fmt.Errorf("pcas api: record ack: %w", err)
		}
	} else {
		recorded.ID = events.NewID()
		recorded.Time = time.Now().UTC()
	}
	return AckResponse{
		AckID:        recorded.ID,
		IdentityID:   req.IdentityID,
		Epoch:        req.Epoch,
		RelyingParty: req.RelyingParty,
		RecordedAt:   recorded.Time,
	}, nil
}
