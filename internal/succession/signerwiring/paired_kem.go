// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/kem"
)

// MintPairedKEM forms the entire Variant-B record inside the isolated signer.
// No caller-provided digest, key handle, commitment or KEM public key is signed.
// Existing paired keys are resolved in custody, so a lost worker response can
// resume without generating a different successor key.
func (p *ProductionMinter) MintPairedKEM(ctx context.Context, req signing.PairedKEMMintRequest) ([]byte, error) {
	p.pairedMu.Lock()
	defer p.pairedMu.Unlock()
	if p.custody == nil || p.kem == nil {
		return nil, signing.ErrNoKEMCustody
	}
	if !canonicalTenantUUID(req.TenantID) || strings.TrimSpace(req.IdentityID) != req.IdentityID ||
		req.IdentityID == "" || strings.TrimSpace(req.RequestID) != req.RequestID || req.RequestID == "" ||
		req.PredecessorEpoch >= math.MaxInt64 {
		return nil, errors.New("invalid paired KEM tenant, identity, request or epoch")
	}
	kemAlg, err := pqc.KEMAlgorithmFromProto(req.KEMAlgorithm)
	if err != nil {
		return nil, err
	}
	predecessorHandle := succession.TenantKeyHandle(req.TenantID, req.IdentityID, req.PredecessorEpoch)
	successorHandle := succession.TenantKeyHandle(req.TenantID, req.IdentityID, req.PredecessorEpoch+1)
	kemHandle := succession.TenantKEMKeyHandle(req.TenantID, req.IdentityID, req.PredecessorEpoch+1)
	predecessor, err := p.custody.ResolvePredecessor(predecessorHandle)
	if err != nil {
		return nil, fmt.Errorf("resolve paired KEM predecessor: %w", err)
	}
	if succession.IsStrengthDowngrade(predecessor.Algorithm(), req.SigningAlgorithm) {
		return nil, errors.New("paired KEM signing algorithm weakens its predecessor")
	}
	now := time.Now().UTC()
	fields := succession.CommitmentFields{
		DeploymentScope: "pcas-kem-rewrap", IdentityID: req.IdentityID, TenantID: req.TenantID,
		PredecessorEpoch: req.PredecessorEpoch, Epoch: req.PredecessorEpoch + 1,
		PredecessorAlg: predecessor.Algorithm(), PredecessorPub: predecessor.Public().DER,
		PolicyRef: "pcas:kem-rewrap:" + req.RequestID, HashAlg: succession.HashAlgSHA256,
		NotBefore: now.Unix(), NotAfter: now.Add(365 * 24 * time.Hour).Unix(), CommitmentVersion: 2,
	}
	record, err := kem.MintPairedThroughSigner(fields, predecessor, pairedKEMCustody{
		ctx: ctx, signer: p.custody, kem: p.kem, signingAlg: req.SigningAlgorithm,
		kemAlg: req.KEMAlgorithm,
	}, successorHandle, kemHandle, string(kemAlg))
	if err != nil {
		return nil, err
	}
	if err := kem.VerifyPaired(record); err != nil {
		return nil, fmt.Errorf("verify signer-local paired KEM record: %w", err)
	}
	return json.Marshal(record)
}

// canonicalTenantUUID validates the lowercase wire form without importing a
// UUID package whose database/sql/driver dependency would enter the AN-4 signer.
func canonicalTenantUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return false
			}
			continue
		}
		if (id[i] < '0' || id[i] > '9') && (id[i] < 'a' || id[i] > 'f') {
			return false
		}
	}
	return true
}

type pairedKEMCustody struct {
	ctx        context.Context
	signer     signing.SignerCustody
	kem        signing.KEMCustody
	signingAlg crypto.Algorithm
	kemAlg     signing.KEMAlgorithm
}

func (c pairedKEMCustody) GeneratePairedSigningKey(handle string) (crypto.Signer, error) {
	key, err := c.signer.ResolvePredecessor(handle)
	if status.Code(err) == codes.NotFound {
		key, err = c.signer.GenerateSuccessorKey(handle, c.signingAlg)
		if err != nil {
			// A concurrent or interrupted mint may have persisted the key.
			// Read back the exact handle; an absent or wrong-class key still fails.
			if recovered, readErr := c.signer.ResolvePredecessor(handle); readErr == nil {
				key, err = recovered, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if key.Algorithm() != c.signingAlg {
		return nil, fmt.Errorf("paired KEM signing key algorithm %s differs from %s", key.Algorithm(), c.signingAlg)
	}
	return key, nil
}

func (c pairedKEMCustody) GenerateKEMSuccessor(handle, kemAlg string) ([]byte, error) {
	want, err := pqc.KEMAlgorithmFromProto(c.kemAlg)
	if err != nil || string(want) != kemAlg {
		return nil, errors.New("paired KEM algorithm differs from the typed request")
	}
	got, public, err := c.kem.GenerateSuccessorKEM(c.ctx, handle, c.kemAlg)
	if err != nil {
		return nil, err
	}
	if got != c.kemAlg || len(public) == 0 {
		return nil, errors.New("paired KEM custody returned a different or empty public key")
	}
	return public, nil
}
