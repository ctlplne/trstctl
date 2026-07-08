// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/federation"
	pcaskem "trstctl.com/trstctl/ee/succession/kem"
	"trstctl.com/trstctl/ee/succession/recovery"
	pcasstore "trstctl.com/trstctl/ee/succession/store"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

type BreadthWorker struct {
	core *corestore.Store
	repo *pcasstore.Repo
	kem  editionseam.KEMCustody
}

func NewBreadthWorker(core *corestore.Store, kem editionseam.KEMCustody) *BreadthWorker {
	var repo *pcasstore.Repo
	if core != nil {
		repo = pcasstore.New(core)
	}
	return &BreadthWorker{core: core, repo: repo, kem: kem}
}

func (w *BreadthWorker) Deliver(ctx context.Context, m coreorch.Message) error {
	switch m.Destination {
	case KEMRewrapDestination:
		return w.handleKEMRewrap(ctx, m.TenantID, m.Payload)
	case RecoveryRequestDestination:
		return w.handleRecovery(ctx, m.TenantID, m.Payload)
	case FederationImportDestination:
		return w.handleFederationImport(ctx, m.TenantID, m.Payload)
	default:
		return fmt.Errorf("pcas breadth worker: unexpected destination %q", m.Destination)
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
	if p.IdentityID == "" || p.PredecessorHandle == "" || p.SuccessorSignHandle == "" || p.SuccessorKEMHandle == "" {
		return errors.New("pcas KEM rewrap: missing identity or signer handles")
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
	if err := w.recordOpaque(ctx, tenantID, rec.Base.Fields, encoded, env.RequestID); err != nil {
		return err
	}
	if w.core != nil {
		return w.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`UPDATE pcas_rewrap_job
				    SET completed_stages = total_stages, status = 'complete', updated_at = now()
				  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND job_id = $1`,
				env.RequestID)
			return err
		})
	}
	return nil
}

type signerKEMAdapter struct {
	ctx        context.Context
	custody    editionseam.KEMCustody
	signingAlg crypto.Algorithm
}

func (a signerKEMAdapter) GeneratePairedSigningKey(handle string) (crypto.Signer, error) {
	rs, err := a.custody.GenerateKeyHandle(a.ctx, a.signingAlg, handle)
	if err != nil {
		return nil, err
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
	if w.kem == nil {
		return errors.New("pcas recovery: no signer custody configured")
	}
	var env requestEnvelope[recoveryPayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas recovery: decode payload: %w", err)
	}
	p := env.Request
	var auth recovery.RecoveryAuthorization
	if err := json.Unmarshal(p.Authorization, &auth); err != nil {
		return fmt.Errorf("pcas recovery: decode authorization: %w", err)
	}
	successorRemote, err := w.kem.SignerForHandle(ctx, p.SuccessorHandle)
	if err != nil {
		successorRemote, err = w.kem.GenerateKeyHandle(ctx, crypto.Algorithm(p.TargetAlgorithm), p.SuccessorHandle)
		if err != nil {
			return fmt.Errorf("pcas recovery: bind successor in signer: %w", err)
		}
	}
	successor := crypto.SignerFromDigestSigner(successorRemote)
	highWater, err := w.highWater(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
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
	return w.recordOpaque(ctx, tenantID, rec.Fields, encoded, env.RequestID)
}

func (w *BreadthWorker) handleFederationImport(ctx context.Context, tenantID string, payload []byte) error {
	if w.kem == nil {
		return errors.New("pcas federation: no signer custody configured")
	}
	var env requestEnvelope[federationImportPayload]
	if err := json.Unmarshal(payload, &env); err != nil {
		return fmt.Errorf("pcas federation: decode payload: %w", err)
	}
	p := env.Request
	localRemote, err := w.kem.SignerForHandle(ctx, p.LocalAuthorityHandle)
	if err != nil {
		return fmt.Errorf("pcas federation: bind local authority handle: %w", err)
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
	if w.repo == nil {
		return err
	}
	if result.Bridge != nil {
		bridgeJSON, _ := json.Marshal(result.Bridge)
		return w.repo.UpsertFederationBridge(ctx, tenantID, pcasstore.FederationBridge{
			ForeignDeploymentID: p.ForeignDeploymentID,
			IdentityID:          p.IdentityID,
			ForeignTrustRootDER: p.ForeignTrustRootDER,
			LocalBaseEpoch:      p.LocalBaseEpoch,
			BridgeJSON:          bridgeJSON,
		})
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

func (w *BreadthWorker) recordOpaque(ctx context.Context, tenantID string, fields succession.CommitmentFields, encoded []byte, idempotencyKey string) error {
	if w.core == nil {
		return nil
	}
	return w.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO succession_records
			   (tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record, idempotency_key)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT DO NOTHING`,
			fields.IdentityID, fields.Epoch, fields.PredecessorEpoch, string(fields.PredecessorAlg),
			string(fields.SuccessorAlg), fields.SuccessorPub, encoded, idempotencyKey); err != nil {
			return fmt.Errorf("pcas breadth: append record: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
			 ON CONFLICT (tenant_id, identity_id)
			 DO UPDATE SET epoch = EXCLUDED.epoch, updated_at = now()
			 WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`,
			fields.IdentityID, fields.Epoch); err != nil {
			return fmt.Errorf("pcas breadth: advance high-water: %w", err)
		}
		return nil
	})
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
