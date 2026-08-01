// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"bytes"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

const checkpointDomain = "trstctl/pcas/succession/epoch-checkpoint/v1"

// SignedEpochCheckpoint is a signer-issued checkpoint of an identity's current
// algorithm-epoch and key, binding the transparency-log head as of issuance. A
// relying party can verify from the checkpoint rather than from genesis (claim
// 14), and divergence between two checkpoints' log heads at one epoch evidences
// equivocation (PCAS-claim-29).
type SignedEpochCheckpoint struct {
	DeploymentScope string
	IdentityID      string
	TenantID        string
	Epoch           uint64
	Algorithm       crypto.Algorithm
	PublicKeyDER    []byte
	LogTreeSize     uint64 // transparency-log head as of issuance (PCAS-claim-29)
	LogRootHash     []byte
	IssuedAt        int64
	Signature       []byte
}

func (c SignedEpochCheckpoint) encode() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(checkpointDomain))
	writeField(&b, []byte(c.DeploymentScope))
	writeField(&b, []byte(c.IdentityID))
	writeField(&b, []byte(c.TenantID))
	writeUint(&b, c.Epoch)
	writeField(&b, []byte(c.Algorithm))
	writeField(&b, c.PublicKeyDER)
	writeUint(&b, c.LogTreeSize)
	writeField(&b, c.LogRootHash)
	writeUint(&b, uint64(c.IssuedAt))
	return b.Bytes()
}

// SignEpochCheckpoint signs c with the signer's checkpoint key.
func SignEpochCheckpoint(signer crypto.Signer, c SignedEpochCheckpoint) (SignedEpochCheckpoint, error) {
	sig, err := signer.Sign(c.encode(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SignedEpochCheckpoint{}, err
	}
	c.Signature = sig
	return c, nil
}

// VerifyEpochCheckpoint verifies the checkpoint signature (covering the bound log
// head, so tampering the head fails).
func VerifyEpochCheckpoint(signerPubDER []byte, c SignedEpochCheckpoint) error {
	if len(c.Signature) == 0 {
		return errors.New("succession: epoch checkpoint is unsigned")
	}
	return crypto.VerifyMessage(signerPubDER, c.encode(), c.Signature)
}

// CheckpointAnchor returns a genesis-shaped anchor at the checkpoint's epoch, so a
// relying party can VerifyChain records after the checkpoint without replaying
// from genesis (PCAS-claim-14). The caller verifies the checkpoint signature
// separately.
func CheckpointAnchor(c SignedEpochCheckpoint) GenesisRecord {
	return GenesisRecord{
		DeploymentScope: c.DeploymentScope,
		IdentityID:      c.IdentityID,
		TenantID:        c.TenantID,
		Algorithm:       c.Algorithm,
		PublicKey:       c.PublicKeyDER,
		Epoch:           c.Epoch,
	}
}

// CheckpointsEquivocate reports two checkpoints for the same identity and epoch
// that bind DIFFERENT transparency-log heads — evidence of equivocation (claim
// 29).
func CheckpointsEquivocate(a, b SignedEpochCheckpoint) bool {
	if a.IdentityID != b.IdentityID || a.Epoch != b.Epoch {
		return false
	}
	return a.LogTreeSize != b.LogTreeSize || !bytes.Equal(a.LogRootHash, b.LogRootHash)
}
