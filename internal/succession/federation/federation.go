// SPDX-License-Identifier: BUSL-1.1

// Package federation bridges succession trust across deployment boundaries without
// merging ledgers (PCAS-claims-34, 43, 44; FIG. 10). The importing deployment verifies
// a foreign identity's succession chain record-by-record against the foreign
// genesis anchor, then appends only a BRIDGE record — binding the foreign chain
// head, both deployment ids, and a monotone epoch mapping — to its own ledger. The
// foreign ledger is evidence, never authority. Verification/hashing route through
// internal/succession (PCAS-04) and the core internal/crypto AN-3 boundary.
package federation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
)

const (
	bridgeDomain     = "trstctl/pcas/federation/bridge/v1"
	quarantineDomain = "trstctl/pcas/federation/quarantine/v1"
)

// ErrImportVerification is returned when a foreign chain fails import verification
// (and is quarantined instead of bridged).
var ErrImportVerification = errors.New("federation: foreign chain failed verification (quarantined)")

// BridgeRecord binds a verified foreign chain head to the local deployment via a
// monotone epoch mapping. It is signed by the local bridging authority and,
// for a mutual bridge, countersigned by the foreign bridging authority over the
// same commitment (PCAS-claims-34, 43).
type BridgeRecord struct {
	ForeignDeployment   string
	LocalDeployment     string
	IdentityID          string
	ForeignHeadDigest   []byte // commitment of the verified foreign chain head
	ForeignHeadEpoch    uint64
	LocalBaseEpoch      uint64 // monotone mapping: local(foreignEpoch) = LocalBaseEpoch + foreignEpoch
	LocalAuthoritySig   []byte
	ForeignAuthoritySig []byte // mutual bridge (PCAS-claim-43)
}

func (b BridgeRecord) commitment() []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte(bridgeDomain))
	writeField(&buf, []byte(b.ForeignDeployment))
	writeField(&buf, []byte(b.LocalDeployment))
	writeField(&buf, []byte(b.IdentityID))
	writeField(&buf, b.ForeignHeadDigest)
	writeUint(&buf, b.ForeignHeadEpoch)
	writeUint(&buf, b.LocalBaseEpoch)
	return crypto.SHA256Sum(buf.Bytes())
}

// MapEpoch maps a foreign epoch to the local trust epoch through the bridge's
// monotone mapping (strictly non-decreasing in foreignEpoch).
func (b BridgeRecord) MapEpoch(foreignEpoch uint64) uint64 { return b.LocalBaseEpoch + foreignEpoch }

// QuarantineEvent is a signed verification-failure event emitted when a foreign
// chain fails import. No bridge record is appended and local state is untouched
// (PCAS-claim-44).
type QuarantineEvent struct {
	ForeignDeployment string
	IdentityID        string
	Reason            string
	Signature         []byte
}

func (q QuarantineEvent) encode() []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte(quarantineDomain))
	writeField(&buf, []byte(q.ForeignDeployment))
	writeField(&buf, []byte(q.IdentityID))
	writeField(&buf, []byte(q.Reason))
	return buf.Bytes()
}

// ImportResult is the outcome of importing a foreign chain: exactly one of a
// signed bridge record (success) or a signed quarantine event (failure). Foreign
// succession records are NEVER returned for local authoritative storage.
type ImportResult struct {
	Bridge     *BridgeRecord
	Quarantine *QuarantineEvent
}

// Import verifies a foreign identity's succession chain record-by-record against
// its genesis anchor and, on success, produces a signed bridge record. On any
// verification failure it produces a signed quarantine event instead and returns
// ErrImportVerification; it never mutates local succession state (PCAS-claims-34, 44).
func Import(localAuthority crypto.Signer, localDeployment string, foreignTrustRootPubDER []byte, foreignGenesis succession.GenesisRecord, foreignChain []succession.SuccessionRecord, localBaseEpoch uint64) (ImportResult, error) {
	if err := succession.VerifyGenesis(foreignTrustRootPubDER, foreignGenesis); err != nil {
		return quarantine(localAuthority, foreignGenesis, err)
	}
	// Record-by-record dual-attestation verification against the foreign anchor.
	if err := succession.VerifyChain(foreignGenesis, foreignChain, 0); err != nil {
		return quarantine(localAuthority, foreignGenesis, err)
	}

	headEpoch := foreignGenesis.Epoch
	headDigest, err := succession.GenesisDigest(foreignGenesis)
	if err != nil {
		return ImportResult{}, err
	}
	if n := len(foreignChain); n > 0 {
		head := foreignChain[n-1]
		headEpoch = head.Fields.Epoch
		if headDigest, err = succession.Commit(head.Fields); err != nil {
			return ImportResult{}, err
		}
	}

	b := BridgeRecord{
		ForeignDeployment: foreignGenesis.DeploymentScope,
		LocalDeployment:   localDeployment,
		IdentityID:        foreignGenesis.IdentityID,
		ForeignHeadDigest: headDigest,
		ForeignHeadEpoch:  headEpoch,
		LocalBaseEpoch:    localBaseEpoch,
	}
	sig, err := localAuthority.Sign(b.commitment(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return ImportResult{}, err
	}
	b.LocalAuthoritySig = sig
	return ImportResult{Bridge: &b}, nil
}

func quarantine(localAuthority crypto.Signer, g succession.GenesisRecord, cause error) (ImportResult, error) {
	q := QuarantineEvent{ForeignDeployment: g.DeploymentScope, IdentityID: g.IdentityID, Reason: cause.Error()}
	sig, err := localAuthority.Sign(q.encode(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return ImportResult{}, err
	}
	q.Signature = sig
	return ImportResult{Quarantine: &q}, ErrImportVerification
}

// Countersign has the foreign deployment's bridging authority sign the same
// bridging commitment, forming a mutual bridge (PCAS-claim-43).
func Countersign(foreignAuthority crypto.Signer, b BridgeRecord) (BridgeRecord, error) {
	sig, err := foreignAuthority.Sign(b.commitment(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return BridgeRecord{}, err
	}
	b.ForeignAuthoritySig = sig
	return b, nil
}

// VerifyBridge verifies the local bridging authority's signature over the bridging
// commitment, and — when requireMutual — the foreign authority's countersignature
// (PCAS-claim-43).
func VerifyBridge(localAuthorityPubDER, foreignAuthorityPubDER []byte, b BridgeRecord, requireMutual bool) error {
	c := b.commitment()
	if len(b.LocalAuthoritySig) == 0 {
		return errors.New("federation: bridge missing local authority signature")
	}
	if err := crypto.VerifyMessage(localAuthorityPubDER, c, b.LocalAuthoritySig); err != nil {
		return fmt.Errorf("federation: local bridge signature: %w", err)
	}
	if requireMutual {
		if len(b.ForeignAuthoritySig) == 0 {
			return errors.New("federation: mutual bridge missing foreign authority signature")
		}
		if err := crypto.VerifyMessage(foreignAuthorityPubDER, c, b.ForeignAuthoritySig); err != nil {
			return fmt.Errorf("federation: foreign bridge signature: %w", err)
		}
	}
	return nil
}

// VerifyQuarantine checks the signed verification-failure event.
func VerifyQuarantine(localAuthorityPubDER []byte, q QuarantineEvent) error {
	if len(q.Signature) == 0 {
		return errors.New("federation: unsigned quarantine event")
	}
	return crypto.VerifyMessage(localAuthorityPubDER, q.encode(), q.Signature)
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
