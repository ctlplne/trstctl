// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package recovery implements recovery succession for a LOST (not compromised)
// predecessor key (establishes INV-12; red-team RT-4). When the predecessor key is
// unavailable, the ordinary dual-attested path cannot proceed — there is no
// predecessor to sign. Recovery mints a DISTINCT record type at the next
// algorithm-epoch that omits the predecessor signature and instead carries an m-of-n
// recovery authorization rooted in the tenant trust root (verified inside the
// signer), plus a mandatory transparency-log inclusion proof. The record still
// chains and stays epoch-monotonic, so recovery bypasses neither the ledger, nor the
// epoch discipline, nor auditability. Relying parties apply strictly stronger policy
// to it (ee/rpverify). All crypto routes through the core internal/crypto AN-3
// boundary.
//
// Recovery is the highest-value fraud target — the only path omitting the
// predecessor signature — so the ordinary MintSuccessor path is UNCHANGED: no flag,
// parameter, or error path there removes the predecessor signature. Recovery is a
// separate function producing a separate type.
package recovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

// Domain separators for the recovery statement and the trust-root-rooted roster.
const (
	statementDomain = "trstctl/pcas/recovery/statement/v1"
	rosterDomain    = "trstctl/pcas/recovery/roster/v1"
)

// Errors.
var (
	ErrRosterUnrooted    = errors.New("recovery: approver roster is not rooted in the tenant trust root")
	ErrThreshold         = errors.New("recovery: invalid approval threshold")
	ErrStatementMismatch = errors.New("recovery: authorization statement does not bind this succession")
	ErrQuorumNotMet      = errors.New("recovery: fewer than the required distinct approvals")
	ErrEpochNotMonotonic = errors.New("recovery: epoch must exceed the current high-water (INV-3)")
	ErrPossession        = errors.New("recovery: successor possession proof invalid or missing")
)

// Approver is a recovery approver: a stable identifier and its verification key.
type Approver struct {
	ID     string
	PubDER []byte
}

// RecoveryStatement is the message the approvers sign to authorize a recovery. It
// binds the identity, tenant, target epoch, and successor key so an approval cannot
// be replayed onto another succession.
type RecoveryStatement struct {
	DeploymentScope string
	IdentityID      string
	TenantID        string
	Epoch           uint64
	SuccessorAlg    string
	SuccessorPub    []byte
	Nonce           string
}

// Approval is one approver's signature over the recovery statement.
type Approval struct {
	ApproverID string
	Signature  []byte
}

// RecoveryAuthorization is the m-of-n authorization rooted in the tenant trust root.
// RosterSig is the trust root's signature over (threshold, roster), rooting the
// approver set in the trust root; Approvals are the approver signatures over the
// statement. At least Threshold distinct rostered approvers must have signed.
type RecoveryAuthorization struct {
	Statement RecoveryStatement
	Threshold int
	Roster    []Approver
	RosterSig []byte
	Approvals []Approval
}

// RecoveryRecord is the distinct recovery-succession artifact: committed fields (whose
// predecessor names the LOST key), a successor possession proof, the m-of-n recovery
// authorization, and a MANDATORY inclusion proof. It carries NO predecessor
// attestation — that is exactly what distinguishes it from an ordinary record.
type RecoveryRecord struct {
	Fields         succession.CommitmentFields
	Possession     succession.PossessionProof
	Authorization  RecoveryAuthorization
	InclusionProof []byte
}

// Expected is the binding a verifier requires the authorization statement to match.
type Expected struct {
	IdentityID   string
	TenantID     string
	Epoch        uint64
	SuccessorAlg string
	SuccessorPub []byte
}

func encodeStatement(s RecoveryStatement) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(statementDomain))
	writeField(&b, []byte(s.DeploymentScope))
	writeField(&b, []byte(s.IdentityID))
	writeField(&b, []byte(s.TenantID))
	writeUint(&b, s.Epoch)
	writeField(&b, []byte(s.SuccessorAlg))
	writeField(&b, s.SuccessorPub)
	writeField(&b, []byte(s.Nonce))
	return b.Bytes()
}

func encodeRoster(threshold int, roster []Approver) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(rosterDomain))
	writeUint(&b, uint64(threshold))
	writeUint(&b, uint64(len(roster)))
	for _, a := range roster {
		writeField(&b, []byte(a.ID))
		writeField(&b, a.PubDER)
	}
	return b.Bytes()
}

// SignRoster produces the tenant trust root's signature over (threshold, roster),
// rooting the approver set in the trust root. Recovery-ceremony tooling calls it.
func SignRoster(trustRoot crypto.Signer, threshold int, roster []Approver) ([]byte, error) {
	return trustRoot.Sign(encodeRoster(threshold, roster), crypto.SignOptions{Hash: crypto.SHA256})
}

// SignApproval produces one approver's signature over the recovery statement.
func SignApproval(approver crypto.Signer, s RecoveryStatement) ([]byte, error) {
	return approver.Sign(encodeStatement(s), crypto.SignOptions{Hash: crypto.SHA256})
}

// VerifyAuthorization checks that the authorization is rooted in the tenant trust
// root, binds exp, and carries at least Threshold distinct valid approver signatures.
// Distinct approvers are counted once (a replayed approval does not inflate the
// tally), and only rostered approvers count (a forged approval by a non-rostered key
// is ignored).
func VerifyAuthorization(auth RecoveryAuthorization, trustRootPubDER []byte, exp Expected) error {
	if auth.Threshold < 1 {
		return ErrThreshold
	}
	if len(trustRootPubDER) == 0 {
		return ErrRosterUnrooted
	}
	if err := crypto.VerifyMessage(trustRootPubDER, encodeRoster(auth.Threshold, auth.Roster), auth.RosterSig); err != nil {
		return fmt.Errorf("%w: %v", ErrRosterUnrooted, err)
	}
	s := auth.Statement
	if s.IdentityID != exp.IdentityID || s.TenantID != exp.TenantID || s.Epoch != exp.Epoch ||
		s.SuccessorAlg != exp.SuccessorAlg || !bytes.Equal(s.SuccessorPub, exp.SuccessorPub) {
		return ErrStatementMismatch
	}
	rosterByID := make(map[string][]byte, len(auth.Roster))
	for _, a := range auth.Roster {
		rosterByID[a.ID] = a.PubDER
	}
	msg := encodeStatement(s)
	seen := map[string]bool{}
	for _, ap := range auth.Approvals {
		pub, ok := rosterByID[ap.ApproverID]
		if !ok || seen[ap.ApproverID] {
			continue
		}
		if crypto.VerifyMessage(pub, msg, ap.Signature) == nil {
			seen[ap.ApproverID] = true
		}
	}
	if len(seen) < auth.Threshold {
		return fmt.Errorf("%w: %d of %d", ErrQuorumNotMet, len(seen), auth.Threshold)
	}
	return nil
}

// Mint produces a recovery record at fields.Epoch. It refuses an epoch at or below
// the current high-water (recovery obeys epoch monotonicity exactly like an ordinary
// record, INV-3), verifies the recovery authorization against the trust root BEFORE
// finalizing, sets the signer-generated successor into the commitment, and signs the
// successor possession proof. It never adds a predecessor signature. The mandatory
// inclusion proof is attached after ledger inclusion (empty here; required at verify).
func Mint(fields succession.CommitmentFields, auth RecoveryAuthorization, trustRootPubDER []byte, successor crypto.Signer, highWater uint64) (RecoveryRecord, error) {
	if fields.Epoch <= highWater {
		return RecoveryRecord{}, fmt.Errorf("%w: epoch %d <= high-water %d", ErrEpochNotMonotonic, fields.Epoch, highWater)
	}
	fields.SuccessorAlg = successor.Algorithm()
	fields.SuccessorPub = successor.Public().DER

	exp := Expected{fields.IdentityID, fields.TenantID, fields.Epoch, string(fields.SuccessorAlg), fields.SuccessorPub}
	if err := VerifyAuthorization(auth, trustRootPubDER, exp); err != nil {
		return RecoveryRecord{}, err
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		return RecoveryRecord{}, err
	}
	sig, err := successor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return RecoveryRecord{}, err
	}
	return RecoveryRecord{
		Fields:        fields,
		Possession:    succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: sig},
		Authorization: auth,
	}, nil
}

// VerifyRecord checks a recovery record's integrity (not the RP's stricter policy —
// that is ee/rpverify.VerifyRecovery): the successor possession proof over the
// commitment, and the m-of-n recovery authorization rooted in the trust root binding
// this succession. It deliberately requires NO predecessor signature.
func VerifyRecord(rec RecoveryRecord, trustRootPubDER []byte) error {
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	if rec.Possession.Kind != succession.ProofSuccessorSignature || len(rec.Possession.Signature) == 0 {
		return ErrPossession
	}
	if err := crypto.VerifyMessage(rec.Fields.SuccessorPub, commitment, rec.Possession.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrPossession, err)
	}
	exp := Expected{rec.Fields.IdentityID, rec.Fields.TenantID, rec.Fields.Epoch, string(rec.Fields.SuccessorAlg), rec.Fields.SuccessorPub}
	return VerifyAuthorization(rec.Authorization, trustRootPubDER, exp)
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}

func writeUint(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}
