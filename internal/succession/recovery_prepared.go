// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

const recoverySuccessorDomain = "trstctl/pcas/recovery-successor/v1\x00"
const recoveryRecordDomain = "trstctl/pcas/recovery-record/v1\x00"
const recoveryProofDomain = "trstctl/pcas/recovery-proof/v1\x00"

// RecoveryProofEventID is the unique proof decision for one recovery record.
func RecoveryProofEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return uuid.NewSHA1(uuid.NameSpaceOID, append([]byte(recoveryProofDomain), bound...)).String()
}

// RecoveryRecordEventID fences a recovery record by its authenticated tenant,
// stable identity and epoch, independent of request ID. Competing approved
// requests cannot both become the source of the same succession epoch.
func RecoveryRecordEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return uuid.NewSHA1(uuid.NameSpaceOID, append([]byte(recoveryRecordDomain), bound...)).String()
}

// RecoverySuccessorEventID is a first-writer fence for one tenant identity's
// epoch. The event log's indexed ID lookup makes admission and crash retries
// bounded even when the tenant has a long history.
func RecoverySuccessorEventID(tenantID, identityID string, epoch uint64) string {
	bound, _ := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		IdentityID string `json:"identity_id"`
		Epoch      uint64 `json:"epoch"`
	}{tenantID, identityID, epoch})
	return uuid.NewSHA1(uuid.NameSpaceOID, append([]byte(recoverySuccessorDomain), bound...)).String()
}

// RecoverySuccessorSigningMessage includes every public field except the
// signature. Its explicit domain keeps a signature for this custody receipt
// from authorizing any other signer command.
func RecoverySuccessorSigningMessage(p RecoverySuccessorPreparedV1) ([]byte, error) {
	bound, err := json.Marshal(struct {
		TenantID        string `json:"tenant_id"`
		IdentityID      string `json:"identity_id"`
		Epoch           uint64 `json:"epoch"`
		Algorithm       string `json:"algorithm"`
		Handle          string `json:"handle"`
		PublicKeyDER    []byte `json:"public_key_der"`
		DeploymentScope string `json:"deployment_scope"`
		RequestID       string `json:"request_id"`
	}{p.TenantID, p.IdentityID, p.Epoch, p.Algorithm, p.Handle,
		p.PublicKeyDER, p.DeploymentScope, p.RequestID})
	if err != nil {
		return nil, err
	}
	return append([]byte(recoverySuccessorDomain), bound...), nil
}

// VerifyRecoverySuccessorPrepared proves that the signer holding the exact
// tenant-scoped key acknowledged this immutable public receipt.
func VerifyRecoverySuccessorPrepared(p RecoverySuccessorPreparedV1) error {
	if p.TenantID == "" || p.IdentityID == "" || p.Epoch == 0 ||
		p.Algorithm == "" || p.DeploymentScope == "" || p.RequestID == "" ||
		len(p.PublicKeyDER) == 0 || len(p.SignerSignature) == 0 {
		return errors.New("pcas recovery: incomplete prepared successor receipt")
	}
	if p.Handle != TenantKeyHandle(p.TenantID, p.IdentityID, p.Epoch) {
		return errors.New("pcas recovery: prepared successor handle is not tenant bound")
	}
	message, err := RecoverySuccessorSigningMessage(p)
	if err != nil {
		return err
	}
	if err := crypto.VerifyAlgorithmMessage(crypto.PublicKey{
		Algorithm: crypto.Algorithm(p.Algorithm), DER: p.PublicKeyDER,
	}, message, p.SignerSignature); err != nil {
		return fmt.Errorf("pcas recovery: prepared successor signature: %w", err)
	}
	return nil
}
