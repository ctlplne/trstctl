// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/succession"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// SuccessionRequestDestination is the outbox destination for an accepted succession
// request. The signer-side orchestrator (PCAS-08) consumes it and mints the
// successor; the IdempotencyKey renders redeliveries exactly-once (AN-5 ↔ AN-6).
const SuccessionRequestDestination = "pcas.succession-request"

// service is the store/log/outbox-backed PCAS API Service. Request-succession
// enqueues an idempotent job through the core outbox; chain-fetch reads the
// RLS-scoped succession store; ack-record appends a signed nhi.rp.ack to the AN-2
// ledger. HTTP-level idempotency (api.Mutate) makes a replayed Idempotency-Key
// return the original result without re-invoking these methods (claim 6).
type service struct {
	store  *corestore.Store
	repo   *pcasstore.Repo
	log    *events.Log
	outbox *orchestrator.Outbox
}

// NewService builds the store/log/outbox-backed PCAS API Service. It is exported so
// the attach seam and integration tests construct the concrete service directly.
func NewService(store *corestore.Store, log *events.Log, outbox *orchestrator.Outbox) Service {
	s := &service{store: store, log: log, outbox: outbox}
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
