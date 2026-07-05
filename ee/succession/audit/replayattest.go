// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package audit provides the PCAS replay-correspondence attestation (claim 38): a
// signed artifact pairing the head of a tamper-evident audit hash chain with the
// PCAS-01 posture-projection checkpoint it corresponds to at a stated ledger
// offset. An optional independent-auditor countersignature lets consumers trust
// the pairing without re-executing the replay. All hashing/signing routes through
// the core internal/crypto AN-3 boundary.
package audit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

const (
	auditChainDomain = "trstctl/pcas/audit/chain/v1"
	attestDomain     = "trstctl/pcas/audit/replay-attestation/v1"
	projectionDomain = "trstctl/pcas/audit/projection/v1"
)

// ReplayAttestation binds an audit-chain head, a ledger offset, and the digest of
// the posture projection at that offset, signed by an attesting key. It attests
// that replay of the ledger to LedgerOffset yields the stated projection.
type ReplayAttestation struct {
	AuditChainHead       []byte
	LedgerOffset         uint64
	ProjectionCheckpoint []byte
	Signature            []byte // by the attesting signer/audit key
	AuditorCountersig    []byte // optional independent-auditor countersignature
}

func (a ReplayAttestation) encode() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(attestDomain))
	writeField(&b, a.AuditChainHead)
	writeUint(&b, a.LedgerOffset)
	writeField(&b, a.ProjectionCheckpoint)
	return b.Bytes()
}

// AuditChainHead computes the tamper-evident hash-chain head over the first
// offset events: h_0 = H(domain); h_i = H(h_{i-1} || H(event_i)).
func AuditChainHead(seq []events.Event, offset int) []byte {
	h := crypto.SHA256Sum([]byte(auditChainDomain))
	for i := 0; i < offset && i < len(seq); i++ {
		h = crypto.SHA256Sum(append(append([]byte{}, h...), eventDigest(seq[i])...))
	}
	return h
}

func eventDigest(e events.Event) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(e.Type))
	writeField(&b, []byte(e.TenantID))
	writeUint(&b, uint64(e.SchemaVersion))
	writeField(&b, e.Data)
	return crypto.SHA256Sum(b.Bytes())
}

// ProjectionCheckpoint returns the deterministic digest of the PCAS-01 posture
// projection over the first offset events.
func ProjectionCheckpoint(seq []events.Event, offset int) ([]byte, error) {
	if offset < 0 || offset > len(seq) {
		return nil, fmt.Errorf("audit: offset %d out of range [0,%d]", offset, len(seq))
	}
	posture, err := succession.Fold(seq[:offset])
	if err != nil {
		return nil, err
	}
	return projectionDigest(posture), nil
}

func projectionDigest(p succession.Posture) []byte {
	ids := make([]string, 0, len(p))
	for id := range p {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b bytes.Buffer
	writeField(&b, []byte(projectionDomain))
	writeUint(&b, uint64(len(ids)))
	for _, id := range ids {
		ip := p[id]
		writeField(&b, []byte(ip.IdentityID))
		writeField(&b, []byte(ip.TenantID))
		writeUint(&b, ip.CurrentEpoch)
		writeField(&b, []byte(ip.CurrentAlgorithm))
		writeField(&b, ip.CurrentPublicDER)
		writeField(&b, []byte(ip.State))
	}
	return crypto.SHA256Sum(b.Bytes())
}

// BuildReplayAttestation computes the head + projection checkpoint over the first
// offset events and signs the pairing with signer.
func BuildReplayAttestation(seq []events.Event, offset int, signer crypto.Signer) (ReplayAttestation, error) {
	cp, err := ProjectionCheckpoint(seq, offset)
	if err != nil {
		return ReplayAttestation{}, err
	}
	a := ReplayAttestation{
		AuditChainHead:       AuditChainHead(seq, offset),
		LedgerOffset:         uint64(offset),
		ProjectionCheckpoint: cp,
	}
	sig, err := signer.Sign(a.encode(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return ReplayAttestation{}, err
	}
	a.Signature = sig
	return a, nil
}

// VerifyReplayAttestation checks the attesting signature. A consumer that trusts
// the attesting key accepts the pairing WITHOUT re-executing the replay.
func VerifyReplayAttestation(signerPubDER []byte, a ReplayAttestation) error {
	if len(a.Signature) == 0 {
		return errors.New("audit: attestation is unsigned")
	}
	return crypto.VerifyMessage(signerPubDER, a.encode(), a.Signature)
}

// VerifyAgainstLedger recomputes the head and projection checkpoint from seq and
// checks they match the attestation. It is what an auditor runs (once) before
// countersigning, and detects a tampered ledger, stale offset, or a digest of a
// different projection.
func VerifyAgainstLedger(seq []events.Event, a ReplayAttestation) error {
	if int(a.LedgerOffset) > len(seq) {
		return errors.New("audit: attestation offset exceeds the ledger")
	}
	if !bytes.Equal(a.AuditChainHead, AuditChainHead(seq, int(a.LedgerOffset))) {
		return errors.New("audit: audit-chain head mismatch")
	}
	cp, err := ProjectionCheckpoint(seq, int(a.LedgerOffset))
	if err != nil {
		return err
	}
	if !bytes.Equal(a.ProjectionCheckpoint, cp) {
		return errors.New("audit: projection checkpoint mismatch")
	}
	return nil
}

// AuditorCountersign has an independent auditor re-run the replay, confirm the
// correspondence, and countersign the pairing (claim 38).
func AuditorCountersign(seq []events.Event, a ReplayAttestation, auditor crypto.Signer) (ReplayAttestation, error) {
	if err := VerifyAgainstLedger(seq, a); err != nil {
		return ReplayAttestation{}, err
	}
	sig, err := auditor.Sign(a.encode(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return ReplayAttestation{}, err
	}
	a.AuditorCountersig = sig
	return a, nil
}

// VerifyAuditorCountersig checks the independent-auditor countersignature; a
// consumer thereafter trusts the pairing without replay.
func VerifyAuditorCountersig(auditorPubDER []byte, a ReplayAttestation) error {
	if len(a.AuditorCountersig) == 0 {
		return errors.New("audit: no auditor countersignature")
	}
	return crypto.VerifyMessage(auditorPubDER, a.encode(), a.AuditorCountersig)
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
