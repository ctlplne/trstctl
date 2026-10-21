// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent"
	"trstctl.com/trstctl/internal/succession/minter"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
	"trstctl.com/trstctl/internal/translog"
)

// KeyCustody is the slice of the isolated signer the workload-held succession
// needs: the tenant trust root (to sign the inclusion log) and successor key
// generation under the deterministic per-epoch handle. editionseam.KEMCustody
// satisfies it through the adapter in serverfactory; tests use software keys.
type KeyCustody interface {
	SignerForHandle(ctx context.Context, handle string) (crypto.Signer, error)
	GenerateKeyHandle(ctx context.Context, algorithm crypto.Algorithm, handle string) (crypto.Signer, error)
}

// WithWorkloadCoSign equips a succession request worker with the custody and
// dialer the workload-held path needs. Without it, an identity anchored in
// workload custody fails closed.
func (w *SuccessionRequestWorker) WithWorkloadCoSign(custody KeyCustody, dialer WorkloadCoSignerDialer) *SuccessionRequestWorker {
	w.custody = custody
	w.cosigners = dialer
	return w
}

// handleWorkloadHeld is the FIG. 5 flow on the control-plane side (PCAS-claim-19):
// the control plane forms the commitment over the agent-held predecessor and a
// successor the isolated signer generated, obtains the predecessor co-signature
// from the agent over the co-sign RPC, verifies it against the commitment it
// supplied, has the successor sign inside the signer, and binds the record to a
// tenant-root transparency log inclusion proof (mandatory for this mode) before
// recording it with the same transaction every succession uses.
func (w *SuccessionRequestWorker) handleWorkloadHeld(ctx context.Context, tenantID string, p requestPayload,
	anchor pcasstore.GenesisAnchor, epoch uint64, idempotencyKey string) error {
	if w.custody == nil || w.cosigners == nil {
		return errors.New("pcas succession: workload custody needs the isolated signer and a configured workload co-signer")
	}
	if rec, _, ok, err := w.orch.fetchByKey(ctx, tenantID, idempotencyKey); err != nil {
		return err
	} else if ok && len(rec) > 0 {
		return nil // exactly-once: this request already minted
	}
	repo := pcasstore.New(w.orch.core)
	predecessorAlg, predecessorPub := anchor.Genesis.Algorithm, anchor.Genesis.PublicKey
	if epoch > 0 {
		latest, found, err := repo.LatestRecord(ctx, tenantID, p.IdentityID)
		if err != nil {
			return err
		}
		if !found || latest.Epoch != epoch {
			return fmt.Errorf("pcas succession: chain head %d does not match the serving epoch %d", latest.Epoch, epoch)
		}
		predecessorAlg, predecessorPub = crypto.Algorithm(latest.SuccessorAlg), latest.SuccessorPub
	}
	root, err := w.custody.SignerForHandle(ctx, succession.TenantRootHandle(tenantID))
	if err != nil {
		return fmt.Errorf("pcas succession: tenant trust root: %w", err)
	}
	if !bytes.Equal(root.Public().DER, anchor.TrustRootPublicDER) {
		return errors.New("pcas succession: isolated trust root differs from the genesis anchor")
	}
	successorHandle := succession.TenantKeyHandle(tenantID, p.IdentityID, epoch+1)
	successor, err := w.custody.GenerateKeyHandle(ctx, crypto.Algorithm(p.TargetAlgorithm), successorHandle)
	if status.Code(err) == codes.AlreadyExists {
		successor, err = w.custody.SignerForHandle(ctx, successorHandle)
	}
	if err != nil {
		return fmt.Errorf("pcas succession: successor key in the isolated signer: %w", err)
	}
	if successor.Algorithm() != crypto.Algorithm(p.TargetAlgorithm) {
		return fmt.Errorf("pcas succession: successor handle holds %s, want %s", successor.Algorithm(), p.TargetAlgorithm)
	}
	now := time.Now().UTC()
	fields := succession.CommitmentFields{
		DeploymentScope:   anchor.Genesis.DeploymentScope,
		IdentityID:        p.IdentityID,
		TenantID:          tenantID,
		PredecessorEpoch:  epoch,
		Epoch:             epoch + 1,
		PredecessorAlg:    predecessorAlg,
		PredecessorPub:    predecessorPub,
		PolicyRef:         p.PolicyRef,
		HashAlg:           succession.HashAlgSHA256,
		NotBefore:         now.Unix(),
		NotAfter:          now.Add(365 * 24 * time.Hour).Unix(),
		CommitmentVersion: 2,
	}
	cosigner, release, err := w.cosigners.CoSigner(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	defer release()
	rec, err := agent.MintWorkloadHeld(fields, cosigner, successor)
	if err != nil {
		return fmt.Errorf("pcas succession: workload-held mint: %w", err)
	}
	// Inclusion proof over the identity's succession commitments, signed by the
	// tenant trust root inside the isolated signer. Leaves are commitments, so
	// the proof never depends on the proof bytes themselves.
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	chain, err := repo.FetchChain(ctx, tenantID, p.IdentityID)
	if err != nil {
		return err
	}
	log := translog.New(root)
	for _, prior := range chain {
		decoded, err := minter.DecodeRecord(prior.Encoded)
		if err != nil {
			return fmt.Errorf("pcas succession: decode chain record %d: %w", prior.Epoch, err)
		}
		leaf, err := succession.Commit(decoded.Fields)
		if err != nil {
			return err
		}
		if _, _, err := log.Append(leaf); err != nil {
			return err
		}
	}
	index, _, err := log.Append(commitment)
	if err != nil {
		return err
	}
	proof, err := log.Prove(index)
	if err != nil {
		return err
	}
	rec.InclusionProof = translog.EncodeProof(proof)
	if err := agent.VerifyWorkloadHeld(rec, func(encoded []byte) error {
		return translog.VerifyEncodedInclusion(commitment, encoded, root.Public().DER)
	}); err != nil {
		return fmt.Errorf("pcas succession: workload-held record failed its own verification: %w", err)
	}
	encoded, err := minter.EncodeRecord(rec)
	if err != nil {
		return err
	}
	return w.orch.recordSuccession(ctx, tenantID, rec, encoded, idempotencyKey)
}
