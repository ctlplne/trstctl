// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// Outbox destinations for the AGID user journeys. These are plain destination strings
// on the feature-neutral AN-6 outbox — the orchestrator drains them and drives the
// mechanisms. They are duplicated as constants in internal/agentid/orchestrator (the
// consumer) with the SAME string value, exactly as PCAS duplicates
// SuccessionRequestDestination / RequestDestination, so the API package need not import
// the orchestrator (which imports the reach engine + broker + cascade) into the request
// path.
const (
	// IssuanceRequestDestination carries a staged chain-bound issuance request. The
	// orchestrator's issuance worker drains it, computes the reachability verdict
	// (reach.NewEngine), and drives broker.IssueChainBound.
	IssuanceRequestDestination = "agentid.issue-chain-bound"
	// RevocationDirectiveDestination carries a staged revocation directive. The
	// orchestrator's cascade drains it and drives revoke.NewCascade.
	RevocationDirectiveDestination = "agentid.revoke-directive"
)

// RootAnchorProvisioner mirrors the signer's durable local root-anchor floor. The
// delegation.DurableAnchorStore satisfies it. It is an interface so tests can prove the
// API writes the signer's provisioning path without linking the API to process control.
type RootAnchorProvisioner interface {
	PutRootAnchor(ctx context.Context, tenantID, keyID string, anchor delegation.RootAnchor) error
}

// service is the store/log/outbox-backed AGID API Service. IssueChainBound and Revoke
// enqueue an idempotent outbox job through the core outbox (the AGID mechanisms run
// asynchronously in the orchestrator worker); the read routes read the RLS-scoped AGID-02
// store. HTTP-level idempotency (api.Mutate) makes a replayed Idempotency-Key return the
// original result without re-invoking these methods (AN-5). This mirrors the PCAS API
// service exactly.
type service struct {
	store  *corestore.Store
	repo   *agidstore.Repo
	log    *events.Log
	outbox *orchestrator.Outbox

	anchorProvisioner RootAnchorProvisioner
}

// NewService builds the store/log/outbox-backed AGID API Service. It is exported so the
// attach seam and integration tests construct the concrete service directly (the PCAS
// pattern).
func NewService(store *corestore.Store, log *events.Log, outbox *orchestrator.Outbox) Service {
	s := &service{store: store, log: log, outbox: outbox}
	if store != nil {
		s.repo = agidstore.New(store)
	}
	return s
}

// NewServiceWithRootAnchorProvisioner builds the AGID API service with an optional signer
// root-anchor provisioner. Production supplies a DurableAnchorStore rooted at the signer
// keystore/floor directory, so a root anchor registered in the control plane is also
// visible to the out-of-process signer after restart.
func NewServiceWithRootAnchorProvisioner(store *corestore.Store, log *events.Log, outbox *orchestrator.Outbox, provisioner RootAnchorProvisioner) Service {
	svc := NewService(store, log, outbox)
	if s, ok := svc.(*service); ok {
		s.anchorProvisioner = provisioner
	}
	return svc
}

var _ Service = (*service)(nil)

// RegisterRootAnchor persists one tenant root anchor in the RLS store and mirrors it into
// the signer's durable local anchor floor when that floor is configured. Both writes are
// idempotent upserts, so replaying the API idempotency key returns the same public result
// and retrying after a transient provisioning error is safe.
func (s *service) RegisterRootAnchor(ctx context.Context, tenantID string, req RootAnchorRequest) (RootAnchorResponse, error) {
	if len(req.PublicDER) != 0 && req.PublicPEM != "" {
		return RootAnchorResponse{}, errors.New("agentid api: provide only one of public_der or public_pem")
	}
	publicDER := append([]byte(nil), req.PublicDER...)
	if req.PublicPEM != "" {
		decoded, err := delegation.DecodeRootAnchorPEM([]byte(req.PublicPEM))
		if err != nil {
			return RootAnchorResponse{}, err
		}
		publicDER = decoded
	}
	if req.KeyID == "" {
		return RootAnchorResponse{}, errors.New("agentid api: key_id is required")
	}
	if len(publicDER) == 0 {
		return RootAnchorResponse{}, errors.New("agentid api: root-anchor public key is required")
	}
	if req.AuthRef == "" {
		return RootAnchorResponse{}, errors.New("agentid api: auth_ref is required")
	}
	row := agidstore.RootAnchor{
		KeyID:     req.KeyID,
		PublicDER: publicDER,
		AuthRef:   req.AuthRef,
	}
	if s.repo != nil {
		if err := s.repo.RegisterRootAnchor(ctx, tenantID, row); err != nil {
			return RootAnchorResponse{}, err
		}
	}
	provisioned := false
	if s.anchorProvisioner != nil {
		if err := s.anchorProvisioner.PutRootAnchor(ctx, tenantID, req.KeyID, delegation.RootAnchor{
			PublicDER: publicDER,
			AuthRef:   req.AuthRef,
		}); err != nil {
			return RootAnchorResponse{}, err
		}
		provisioned = true
	}
	return RootAnchorResponse{
		KeyID:       req.KeyID,
		PublicDER:   publicDER,
		AuthRef:     req.AuthRef,
		Provisioned: provisioned,
	}, nil
}

// ListRootAnchors returns the tenant's registered root anchors. When no store is wired
// (for example an unlicensed/core-only shape in tests), it fails soft with an empty list.
func (s *service) ListRootAnchors(ctx context.Context, tenantID string) (RootAnchorsResponse, error) {
	resp := RootAnchorsResponse{Anchors: []RootAnchorResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	anchors, err := s.repo.ListRootAnchors(ctx, tenantID)
	if err != nil {
		return RootAnchorsResponse{}, err
	}
	for _, a := range anchors {
		resp.Anchors = append(resp.Anchors, RootAnchorResponse{
			KeyID:       a.KeyID,
			PublicDER:   append([]byte(nil), a.PublicDER...),
			AuthRef:     a.AuthRef,
			CreatedAt:   a.CreatedAt,
			Provisioned: s.anchorProvisioner != nil,
		})
	}
	resp.Count = len(resp.Anchors)
	return resp, nil
}

// issuanceJob is the durable outbox payload the orchestrator's issuance worker drains. It
// carries the issuance id plus the opaque bodies the mechanisms re-verify; no key material
// crosses the outbox.
type issuanceJob struct {
	IssuanceID string `json:"issuance_id"`
	IssueChainBoundRequest
}

// IssueChainBound records an accepted chain-bound issuance as an idempotent outbox job
// (agentid.issue-chain-bound) for the orchestrator to drive (AN-5/AN-6). It returns an
// issuance acknowledgement; the actual verify-before-keygen + broker mint happen
// asynchronously in the worker, exactly as PCAS RequestSuccession enqueues and the PCAS
// worker mints.
func (s *service) IssueChainBound(ctx context.Context, tenantID string, req IssueChainBoundRequest) (IssueChainBoundResponse, error) {
	issuanceID := events.NewID()
	payload, err := json.Marshal(issuanceJob{IssuanceID: issuanceID, IssueChainBoundRequest: req})
	if err != nil {
		return IssueChainBoundResponse{}, err
	}
	if s.store != nil && s.outbox != nil {
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: IssuanceRequestDestination,
				IdempotencyKey: issuanceID, Payload: payload,
			})
			return err
		}); err != nil {
			return IssueChainBoundResponse{}, fmt.Errorf("agentid api: enqueue issuance request: %w", err)
		}
	}
	return IssueChainBoundResponse{
		IssuanceID:     issuanceID,
		AgentID:        req.AgentID,
		TrustAnchorRef: req.TrustAnchorRef,
		Status:         "queued",
		QueuedAt:       time.Now().UTC(),
	}, nil
}

// revocationJob is the durable outbox payload the orchestrator's cascade drains. It carries
// the directive id plus the subject + reason so the cascade determines descendants and
// commits the transactional per-descendant jobs.
type revocationJob struct {
	DirectiveID string `json:"directive_id"`
	RevokeRequest
}

// Revoke records an accepted revocation directive as an idempotent outbox job
// (agentid.revoke-directive) for the orchestrator's cascade to drive (AN-5/AN-6). It
// returns a directive acknowledgement; the descendant determination + transactional
// per-descendant job enqueue + terminal transition happen asynchronously in the worker.
func (s *service) Revoke(ctx context.Context, tenantID string, req RevokeRequest) (RevokeResponse, error) {
	directiveID := events.NewID()
	payload, err := json.Marshal(revocationJob{DirectiveID: directiveID, RevokeRequest: req})
	if err != nil {
		return RevokeResponse{}, err
	}
	if s.store != nil && s.outbox != nil {
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: RevocationDirectiveDestination,
				IdempotencyKey: directiveID, Payload: payload,
			})
			return err
		}); err != nil {
			return RevokeResponse{}, fmt.Errorf("agentid api: enqueue revocation directive: %w", err)
		}
	}
	return RevokeResponse{
		DirectiveID: directiveID,
		Subject:     req.Subject,
		Reason:      req.Reason,
		Status:      "queued",
		QueuedAt:    time.Now().UTC(),
	}, nil
}

// FetchChain returns the ordered opaque delegation records for an issued credential,
// RLS-scoped to tenantID. The response verifies offline with the AGID-09 relying-party
// verifier. It reads the AGID-02 store's chain read (FetchChain), rendering each record's
// canonical bytes.
func (s *service) FetchChain(ctx context.Context, tenantID, credentialID string) (ChainResponse, error) {
	resp := ChainResponse{CredentialID: credentialID, Records: [][]byte{}}
	if s.repo == nil {
		return resp, nil
	}
	recs, found, err := s.repo.FetchChain(ctx, tenantID, credentialID)
	if err != nil {
		return ChainResponse{}, err
	}
	if !found {
		return resp, nil
	}
	for _, r := range recs {
		resp.Records = append(resp.Records, append([]byte(nil), r.Encoded...))
	}
	resp.Count = len(resp.Records)
	return resp, nil
}

// FetchCredential returns the signer-minted public credential bytes for an issued AGID
// credential. It is RLS-scoped and serves only public material; private key bytes never
// leave the isolated signer.
func (s *service) FetchCredential(ctx context.Context, tenantID, credentialID string) (CredentialResponse, error) {
	resp := CredentialResponse{CredentialID: credentialID}
	if s.store == nil {
		return resp, nil
	}
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var (
			subjectID        string
			credentialDER    []byte
			chainHeadDigest  []byte
			chainDigest      []byte
			agentStackDigest []byte
			notBefore        int64
			notAfter         int64
		)
		err := tx.QueryRow(ctx,
			`SELECT subject_id, credential_der, chain_head_digest, chain_digest,
			        agent_stack_digest, not_before, not_after
			   FROM agent_issuances
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND credential_id = $1`,
			credentialID).Scan(&subjectID, &credentialDER, &chainHeadDigest, &chainDigest, &agentStackDigest, &notBefore, &notAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("agentid api: fetch credential: %w", err)
		}
		resp.SubjectID = subjectID
		resp.CredentialDER = append([]byte(nil), credentialDER...)
		resp.ChainHeadDigest = append([]byte(nil), chainHeadDigest...)
		resp.ChainDigest = append([]byte(nil), chainDigest...)
		resp.AgentStackDigest = append([]byte(nil), agentStackDigest...)
		resp.NotBefore = notBefore
		resp.NotAfter = notAfter
		resp.Found = true
		return nil
	})
	return resp, err
}

// IncompleteJobs returns a directive's still-open descendant jobs (AGID-11
// IncompleteJobs), RLS-scoped to tenantID. It reads the AGID-02 store's incomplete-jobs
// query and projects it to the API DTO.
func (s *service) IncompleteJobs(ctx context.Context, tenantID, directiveID string) (IncompleteJobsResponse, error) {
	resp := IncompleteJobsResponse{DirectiveID: directiveID, Jobs: []IncompleteJob{}}
	if s.repo == nil {
		return resp, nil
	}
	jobs, err := s.repo.IncompleteJobs(ctx, tenantID, directiveID)
	if err != nil {
		return IncompleteJobsResponse{}, err
	}
	for _, j := range jobs {
		resp.Jobs = append(resp.Jobs, IncompleteJob{CredentialID: j.CredentialID, FollowOn: j.FollowOn})
	}
	resp.Count = len(resp.Jobs)
	return resp, nil
}
