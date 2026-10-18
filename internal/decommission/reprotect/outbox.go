// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	DestinationJob             = "vdec.reprotect.job"
	TypeCredentialSupersession = "reprotection.credential_supersession_recorded"
)

var ErrExecutorUnavailable = errors.New("reprotect: executor substrate unavailable")

type factoryConfig struct {
	store *decstore.Repo
}

// Option customizes the production VDEC outbox factory.
type Option func(*factoryConfig)

// WithStore supplies the VDEC read-model repository built at the EE attach seam.
func WithStore(repo *decstore.Repo) Option {
	return func(cfg *factoryConfig) {
		cfg.store = repo
	}
}

type Handler struct {
	store                *decstore.Repo
	ciphertext           *CiphertextExecutor
	credential           *CredentialReissueExecutor
	lease                *LeaseRevocationExecutor
	staged               *StagedExecutor
	failClosed           *FailClosedKeyGuard
	revokeFirst          *RevokeFirstCoordinator
	revocationCompletion *RevocationCompletionRecorder
}

type Payload struct {
	Job                            Job                     `json:"job"`
	TransitKeyName                 string                  `json:"transit_key_name,omitempty"`
	Ciphertext                     string                  `json:"ciphertext,omitempty"`
	AAD                            []byte                  `json:"aad,omitempty"`
	SuccessorKeyID                 string                  `json:"successor_key_id,omitempty"`
	LeaseID                        string                  `json:"lease_id,omitempty"`
	RevocationDestinations         []RevocationDestination `json:"revocation_destinations,omitempty"`
	RevocationCompletedDestination string                  `json:"revocation_completed_destination,omitempty"`
}

func NewLicensedOutboxFactory(opts ...Option) editionseam.LicensedOutboxFactory {
	cfg := factoryConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		return newHandler(d, cfg)
	}
}

func newHandler(d editionseam.LicensedOutboxDeps, cfg factoryConfig) (Handler, error) {
	completions := NewCompletionRecorder(eventSink{log: d.Log, store: d.Store})
	revocations := NewRevocationCompletionRecorder(eventSink{log: d.Log, store: d.Store})
	rewrap := RewrapBoundary(unavailableRewrapBoundary{})
	if boundary, err := NewTransitBoundary(d.Transit); err == nil {
		rewrap = boundary
	}
	ciphertext, err := NewCiphertextExecutor(rewrap, completions)
	if err != nil {
		return Handler{}, err
	}
	credential, err := NewCredentialReissueExecutor(unavailableCredentialIssuer{}, eventCredentialSupersessionRecorder{log: d.Log, store: d.Store}, completions)
	if err != nil {
		return Handler{}, err
	}
	lease, err := NewLeaseRevocationExecutor(unavailableLeaseEngine{}, unavailableLeaseQueue{}, completions)
	if err != nil {
		return Handler{}, err
	}
	staged, err := NewStagedExecutor(unavailableStagedPhases{}, completions)
	if err != nil {
		return Handler{}, err
	}
	revocationTx := RevocationTransactor(unavailableRevocationTransactor{})
	if d.Store != nil {
		revocationTx = storeRevocationTransactor{store: d.Store, outbox: orchestrator.NewOutbox(d.Store)}
	}
	revokeFirst, err := NewRevokeFirstCoordinator(revocationTx)
	if err != nil {
		return Handler{}, err
	}
	return Handler{
		store:                cfg.store,
		ciphertext:           ciphertext,
		credential:           credential,
		lease:                lease,
		staged:               staged,
		failClosed:           NewFailClosedKeyGuard(),
		revokeFirst:          revokeFirst,
		revocationCompletion: revocations,
	}, nil
}

func (h Handler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	if m.Destination != DestinationJob {
		return false, nil
	}
	payload, err := decodePayload(m.Payload)
	if err != nil {
		return true, fmt.Errorf("reprotect: decode job payload: %w", err)
	}
	job := payload.Job
	if err := validateJob(job); err != nil {
		return true, err
	}
	if len(payload.RevocationDestinations) != 0 {
		result, err := h.revokeFirst.RevokeFirst(ctx, RevokeFirstRequest{
			TenantID:     job.TenantID,
			KeyID:        job.KeyID,
			JobID:        job.ID,
			Reason:       "vdec re-protection revokes protective use before replacement",
			Dependent:    job.Dependent,
			Destinations: payload.RevocationDestinations,
		})
		if err != nil {
			return true, err
		}
		if err := h.failClosed.MarkFailClosed(result.StateChange); err != nil {
			return true, err
		}
	}
	if payload.RevocationCompletedDestination != "" {
		_, err := h.revocationCompletion.RecordDestinationCompletion(ctx, RevokeFirstRequest{
			TenantID:     job.TenantID,
			KeyID:        job.KeyID,
			JobID:        job.ID,
			Dependent:    job.Dependent,
			Destinations: payload.RevocationDestinations,
		}, RevocationDestination{ID: payload.RevocationCompletedDestination})
		if err != nil {
			return true, err
		}
	}
	switch job.Kind {
	case JobKindReEncrypt, JobKindReWrap:
		_, err = h.ciphertext.Execute(ctx, CiphertextRequest{
			Job:            job,
			TransitKeyName: payload.TransitKeyName,
			Ciphertext:     payload.Ciphertext,
			AAD:            payload.AAD,
			SuccessorKeyID: payload.SuccessorKeyID,
		})
	case JobKindReIssue:
		_, err = h.credential.Execute(ctx, CredentialReissueRequest{Job: job, SuccessorKeyID: payload.SuccessorKeyID})
	case JobKindRevokeLease:
		_, err = h.lease.Execute(ctx, LeaseRevocationRequest{Job: job, LeaseID: payload.LeaseID})
	case JobKindReDerive:
		_, err = h.staged.Execute(ctx, StagedRequest{Job: job, SuccessorKeyID: payload.SuccessorKeyID})
	default:
		err = fmt.Errorf("%w: %s", ErrUnsupportedDependentType, job.Kind)
	}
	return true, err
}

func decodePayload(raw []byte) (Payload, error) {
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Payload{}, err
	}
	if payload.Job.ID != "" {
		return payload, nil
	}
	var job Job
	if err := json.Unmarshal(raw, &job); err != nil {
		return Payload{}, err
	}
	payload.Job = job
	return payload, nil
}

type eventSink struct {
	log   *events.Log
	store *corestore.Store
}

func (s eventSink) AppendReprotectionCompleted(ctx context.Context, ev depstate.ReprotectionCompletedV1) (bool, error) {
	encoded, err := depstate.Encode(ev)
	if err != nil {
		return false, err
	}
	identity := ev.TenantID + "\x1f" + ev.KeyID + "\x1f" + ev.JobID + "\x1f" +
		string(ev.Dependent.Class) + "\x1f" + ev.Dependent.ID
	return s.appendBoundEventOnce(ctx, "vdec-completion", identity, encoded)
}

func (s eventSink) AppendRevocationCompleted(ctx context.Context, ev depstate.RevocationCompletedV1) (bool, error) {
	encoded, err := depstate.Encode(ev)
	if err != nil {
		return false, err
	}
	identity := ev.TenantID + "\x1f" + ev.KeyID + "\x1f" + ev.JobID + "\x1f" +
		string(ev.Dependent.Class) + "\x1f" + ev.Dependent.ID + "\x1f" + ev.Destination
	return s.appendBoundEventOnce(ctx, "vdec-revocation-completion", identity, encoded)
}

func (s eventSink) appendBoundEventOnce(ctx context.Context, kind, identity string, encoded events.Event) (bool, error) {
	if s.log == nil || s.store == nil {
		return false, fmt.Errorf("%w: event log and tenant store are required", ErrExecutorUnavailable)
	}
	encoded.ID = kind + ":" + crypto.SHA256Hex([]byte(identity))
	var recorded bool
	err := s.store.WithTenant(ctx, encoded.TenantID, func(tx pgx.Tx) error {
		// A row lock cannot protect an event that has not yet been appended.
		// This transaction-scoped lock fences competing workers; the canonical
		// event ID is the durable answer after a crash or lost append response.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			kind+"/v1/"+identity); err != nil {
			return err
		}
		prior, found, err := s.log.EventByID(ctx, encoded.ID)
		if err != nil {
			return err
		}
		if found {
			if prior.TenantID != encoded.TenantID || prior.Type != encoded.Type ||
				prior.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(prior.Data, encoded.Data) {
				return ErrCompletionConflict
			}
			return nil
		}
		appended, err := s.log.Append(ctx, encoded)
		if err != nil {
			return err
		}
		if appended.ID != encoded.ID || !bytes.Equal(appended.Data, encoded.Data) {
			return ErrCompletionConflict
		}
		recorded = true
		return nil
	})
	return recorded, err
}

type unavailableRewrapBoundary struct{}

func (unavailableRewrapBoundary) Rewrap(context.Context, string, string, string, []byte) (string, error) {
	return "", fmt.Errorf("%w: transit service is required", ErrExecutorUnavailable)
}

type unavailableCredentialIssuer struct{}

func (unavailableCredentialIssuer) IssueReplacementCredential(context.Context, CredentialIssueRequest) (CredentialReplacement, error) {
	return CredentialReplacement{}, fmt.Errorf("%w: credential replacement issuer is not provisioned", ErrExecutorUnavailable)
}

type eventCredentialSupersessionRecorder struct {
	log   *events.Log
	store *corestore.Store
}

func (r eventCredentialSupersessionRecorder) RecordCredentialSupersession(ctx context.Context, s CredentialSupersession) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("reprotect: encode credential supersession: %w", err)
	}
	identity := s.TenantID + "\x1f" + s.JobID + "\x1f" + s.OldCredentialID
	_, err = eventSink(r).appendBoundEventOnce(ctx,
		"vdec-credential-supersession", identity, events.Event{
			Type:          TypeCredentialSupersession,
			TenantID:      s.TenantID,
			SchemaVersion: depstate.SchemaV1,
			Data:          raw,
		})
	return err
}

type unavailableLeaseEngine struct{}

func (unavailableLeaseEngine) Revoke(context.Context, string) error {
	return fmt.Errorf("%w: lease revocation engine is not provisioned", ErrExecutorUnavailable)
}

func (unavailableLeaseEngine) RunRevocations(context.Context) (int, error) {
	return 0, fmt.Errorf("%w: lease revocation engine is not provisioned", ErrExecutorUnavailable)
}

type unavailableLeaseQueue struct{}

func (unavailableLeaseQueue) Pending(context.Context) ([]dynsecret.RevokeItem, error) {
	return nil, fmt.Errorf("%w: lease revocation queue is not provisioned", ErrExecutorUnavailable)
}

type unavailableStagedPhases struct{}

func (unavailableStagedPhases) StageSuccessor(context.Context, StageRequest) (StagedForm, error) {
	return StagedForm{}, fmt.Errorf("%w: staged re-protection substrate is not provisioned", ErrExecutorUnavailable)
}

func (unavailableStagedPhases) Cutover(context.Context, CutoverRequest) (CutoverResult, error) {
	return CutoverResult{}, fmt.Errorf("%w: staged re-protection substrate is not provisioned", ErrExecutorUnavailable)
}

func (unavailableStagedPhases) VerifyHealth(context.Context, HealthRequest) (HealthResult, error) {
	return HealthResult{}, fmt.Errorf("%w: staged re-protection substrate is not provisioned", ErrExecutorUnavailable)
}

func (unavailableStagedPhases) RetireOriginal(context.Context, RetireRequest) error {
	return fmt.Errorf("%w: staged re-protection substrate is not provisioned", ErrExecutorUnavailable)
}

func (unavailableStagedPhases) Rollback(context.Context, RollbackRequest) error {
	return nil
}

type unavailableRevocationTransactor struct{}

func (unavailableRevocationTransactor) WithinRevocationTx(context.Context, string, func(context.Context, RevocationTransaction) error) error {
	return fmt.Errorf("%w: revocation transaction substrate is not provisioned", ErrExecutorUnavailable)
}

type storeRevocationTransactor struct {
	store  *corestore.Store
	outbox *orchestrator.Outbox
}

func (t storeRevocationTransactor) WithinRevocationTx(ctx context.Context, tenantID string, fn func(context.Context, RevocationTransaction) error) error {
	if t.store == nil || t.outbox == nil {
		return fmt.Errorf("%w: revocation transaction substrate is not provisioned", ErrExecutorUnavailable)
	}
	return t.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return fn(ctx, storeRevocationTx{tx: tx, outbox: t.outbox})
	})
}

type storeRevocationTx struct {
	tx     pgx.Tx
	outbox *orchestrator.Outbox
}

func (t storeRevocationTx) MarkKeyFailClosed(ctx context.Context, change FailClosedStateChange) error {
	_, err := t.tx.Exec(ctx,
		`INSERT INTO decommission_fail_closed_keys
		        (tenant_id, key_id, job_id, reason, state)
		 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4)
		 ON CONFLICT (tenant_id, key_id)
		 DO UPDATE SET job_id = EXCLUDED.job_id,
		               reason = EXCLUDED.reason,
		               state = EXCLUDED.state,
		               updated_at = now()`,
		change.KeyID, change.JobID, change.Reason, change.State)
	return err
}

func (t storeRevocationTx) EnqueueRevocationIntent(ctx context.Context, e orchestrator.Entry) error {
	_, err := t.outbox.Enqueue(ctx, t.tx, e)
	return err
}
