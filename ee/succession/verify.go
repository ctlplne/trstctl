// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"bytes"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Verification errors. They are sentinels so callers (and the RP verifier,
// PCAS-07) can distinguish failure modes.
var (
	ErrPredecessorAttestation = errors.New("succession: predecessor attestation invalid or missing")
	ErrPossessionProof        = errors.New("succession: successor possession proof invalid or missing")
	ErrUnsupportedProof       = errors.New("succession: unsupported possession-proof mechanism")
	ErrEpochNotIncrement      = errors.New("succession: epoch must equal predecessor_epoch + 1")
	ErrEpochNotMonotonic      = errors.New("succession: epoch not strictly increasing along chain")
	ErrChainAnchor            = errors.New("succession: chain does not anchor to genesis / linkage broken")
	ErrDowngrade              = errors.New("succession: chain head epoch <= last-accepted (downgrade)")
	ErrGenesisAttestation     = errors.New("succession: genesis trust-root attestation invalid or missing")
	ErrRecordFieldMismatch    = errors.New("succession: v2 record field does not match its committed value")
)

// VerifyRecord recomputes the commitment from rec.Fields and verifies BOTH limbs
// of the dual attestation over that commitment: the predecessor attestation (a
// signature by the predecessor public key named in the commitment) and the
// successor possession proof (a signature by the successor public key). Neither
// limb alone suffices (PCAS-claim-25). It negotiates no algorithm and loads no
// runtime provider — it verifies with the algorithms the keys already carry
// (INV-6 building block). Signature verification routes through the core AN-3
// boundary (crypto.VerifyMessage).
//
// It is the relying-party limb of the independent method claim (PCAS-claim-1):
// both signatures over the commitment are verified offline, without invoking a
// runtime cryptographic-provider engine and without re-negotiating an algorithm
// with the identity. The other half of that limb — confirming the incremented
// algorithm-epoch value exceeds the last-accepted value for the identity — is
// VerifyChain below (ErrDowngrade).
func VerifyRecord(rec SuccessionRecord) error {
	commitment, err := Commit(rec.Fields)
	if err != nil {
		return err
	}
	// Predecessor attestation limb.
	if len(rec.PredecessorAtt) == 0 {
		return ErrPredecessorAttestation
	}
	if err := crypto.VerifyMessage(rec.Fields.PredecessorPub, commitment, rec.PredecessorAtt); err != nil {
		return fmt.Errorf("%w: %v", ErrPredecessorAttestation, err)
	}
	// Successor possession-proof limb.
	switch rec.Possession.Kind {
	case ProofSuccessorSignature:
		if len(rec.Possession.Signature) == 0 {
			return ErrPossessionProof
		}
		if err := crypto.VerifyMessage(rec.Fields.SuccessorPub, commitment, rec.Possession.Signature); err != nil {
			return fmt.Errorf("%w: %v", ErrPossessionProof, err)
		}
	case ProofDecapTranscript, ProofNIZKPoP:
		return fmt.Errorf("%w: %s (implemented in PCAS-14)", ErrUnsupportedProof, rec.Possession.Kind)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedProof, rec.Possession.Kind)
	}
	// v2 consistency (INT-08/09): the record-level fields that readers consume must
	// match the commitment-bound copies, so a flipped top-level RecordType / authz /
	// attestation cannot diverge from what both dual signatures cover. This closes the
	// naive-relying-party bypass — base chain verification alone now rejects a
	// RecordType flip on a v2 record. (v1 records bind these via the signer attestation;
	// that path is unchanged and verified by VerifyExceptional.)
	if rec.Fields.CommitmentVersion >= 2 {
		if rec.RecordType != rec.Fields.RecordType {
			return fmt.Errorf("%w: record type %q != committed %q", ErrRecordFieldMismatch, rec.RecordType, rec.Fields.RecordType)
		}
		if !bytes.Equal(rec.AuthzDigest, rec.Fields.AuthzDigest) {
			return fmt.Errorf("%w: authz digest", ErrRecordFieldMismatch)
		}
		if !bytes.Equal(rec.AttestationEvidenceDigest, rec.Fields.AttestationEvidenceDigest) {
			return fmt.Errorf("%w: attestation evidence digest", ErrRecordFieldMismatch)
		}
		if rec.AttestationType != rec.Fields.AttestationType {
			return fmt.Errorf("%w: attestation type", ErrRecordFieldMismatch)
		}
	}
	return nil
}

// VerifyChain verifies a succession chain anchored at genesis. For each record it
// verifies both dual-attestation limbs (VerifyRecord), then enforces that
// predecessor_epoch matches the running epoch, epoch == predecessor_epoch + 1,
// epochs strictly increase, and the predecessor public key + algorithm link to
// the previous record's successor (or, for the first record, to the genesis key).
// Finally it rejects a chain whose head epoch is <= lastAccepted (a downgrade /
// stale replay). Verification is offline: no algorithm negotiation, no provider
// load (INV-6).
func VerifyChain(genesis GenesisRecord, chain []SuccessionRecord, lastAccepted uint64) error {
	if _, err := registryID(genesis.Algorithm); err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	prevEpoch := genesis.Epoch
	prevPub := genesis.PublicKey
	prevAlg := genesis.Algorithm
	for i, rec := range chain {
		// Structural chain checks run BEFORE signature verification so that an
		// inconsistent-but-validly-signed record yields a specific epoch/anchor
		// error rather than being masked by a commitment/signature mismatch (the
		// epoch is bound in the commitment, so tampering it also breaks the
		// signature). Security is unchanged: every check must pass.
		if rec.Fields.PredecessorEpoch != prevEpoch {
			return fmt.Errorf("record %d: %w (predecessor_epoch %d != %d)", i, ErrChainAnchor, rec.Fields.PredecessorEpoch, prevEpoch)
		}
		if rec.Fields.Epoch != rec.Fields.PredecessorEpoch+1 {
			return fmt.Errorf("record %d: %w", i, ErrEpochNotIncrement)
		}
		// Strict monotonicity. Implied by the two checks above (predecessor_epoch
		// == prevEpoch and epoch == predecessor_epoch+1), retained as explicit
		// defense in depth against a future refactor of either check.
		if rec.Fields.Epoch <= prevEpoch {
			return fmt.Errorf("record %d: %w", i, ErrEpochNotMonotonic)
		}
		if !bytes.Equal(rec.Fields.PredecessorPub, prevPub) || rec.Fields.PredecessorAlg != prevAlg {
			return fmt.Errorf("record %d: %w", i, ErrChainAnchor)
		}
		if err := VerifyRecord(rec); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		prevEpoch = rec.Fields.Epoch
		prevPub = rec.Fields.SuccessorPub
		prevAlg = rec.Fields.SuccessorAlg
	}
	// The downgrade check must NOT be skipped for an empty chain. That exemption
	// was the whole attack: a relying party that has durably accepted epoch 5
	// resolves a chainless presentation to the GENESIS key at epoch 0
	// (rpverify.Verify seeds its Result from the genesis record and only advances
	// it when len(chain) > 0), so omitting the chain rolls the identity back to a
	// key that may have been rotated away precisely because it was compromised.
	// Presenting nothing was strictly stronger than presenting a stale chain.
	//
	// lastAccepted == 0 means "never accepted anything", which is legitimate first
	// contact — federation and issuer both call with 0 by design — so the check
	// engages only once the verifier has something to be rolled back from.
	if lastAccepted > 0 && prevEpoch <= lastAccepted {
		return ErrDowngrade
	}
	return nil
}

// encodeGenesis produces the canonical, domain-separated encoding of a genesis
// record's bound fields (the same length-prefixed scheme as the commitment).
func encodeGenesis(g GenesisRecord) ([]byte, error) {
	algID, err := registryID(g.Algorithm)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeField(&b, []byte(genesisDomain))
	writeField(&b, []byte(g.DeploymentScope))
	writeField(&b, []byte(g.IdentityID))
	writeField(&b, []byte(g.TenantID))
	writeUint(&b, algID)
	writeField(&b, g.PublicKey)
	writeUint(&b, g.Epoch)
	return b.Bytes(), nil
}

// GenesisDigest returns H(encodeGenesis(g)), the message the tenant trust root
// signs to anchor the chain.
func GenesisDigest(g GenesisRecord) ([]byte, error) {
	enc, err := encodeGenesis(g)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(enc), nil
}

// VerifyGenesis checks the tenant-trust-root attestation over the genesis
// encoding using the supplied trust-root public key (obtained out of band).
func VerifyGenesis(trustRootPubDER []byte, g GenesisRecord) error {
	digest, err := GenesisDigest(g)
	if err != nil {
		return err
	}
	if len(g.TrustRootAtt) == 0 {
		return ErrGenesisAttestation
	}
	if err := crypto.VerifyMessage(trustRootPubDER, digest, g.TrustRootAtt); err != nil {
		return fmt.Errorf("%w: %v", ErrGenesisAttestation, err)
	}
	return nil
}
