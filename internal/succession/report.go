// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"bytes"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

const postureReportDomain = "trstctl/pcas/succession/posture-report/v1"

// PostureReport is a signed, standalone statement of an identity's current
// cryptographic posture (PCAS-claim-50): the algorithm in force, its epoch, and a
// digest of the succession record that put it in force. A consumer verifies it
// from the report bytes plus the reporter's public key ALONE — with no ledger
// replay (distinct from PCAS-24's replay-correspondence attestation).
type PostureReport struct {
	IdentityID              string
	TenantID                string
	Algorithm               crypto.Algorithm
	Epoch                   uint64
	IntroducingRecordDigest []byte // digest of the succession record that introduced Algorithm
	Signature               []byte // over the canonical encoding, by the reporter
}

func (r PostureReport) encode() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(postureReportDomain))
	writeField(&b, []byte(r.IdentityID))
	writeField(&b, []byte(r.TenantID))
	writeField(&b, []byte(r.Algorithm))
	writeUint(&b, r.Epoch)
	writeField(&b, r.IntroducingRecordDigest)
	return b.Bytes()
}

// BuildPostureReport derives an unsigned posture report from a projected identity
// posture (PCAS-01) and the digest of the introducing record.
func BuildPostureReport(p IdentityPosture, introducingRecordDigest []byte) PostureReport {
	return PostureReport{
		IdentityID:              p.IdentityID,
		TenantID:                p.TenantID,
		Algorithm:               crypto.Algorithm(p.CurrentAlgorithm),
		Epoch:                   p.CurrentEpoch,
		IntroducingRecordDigest: introducingRecordDigest,
	}
}

// SignPostureReport signs r with the reporter's key (through the core AN-3
// boundary) and returns the signed report.
func SignPostureReport(reporter crypto.Signer, r PostureReport) (PostureReport, error) {
	sig, err := reporter.Sign(r.encode(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return PostureReport{}, err
	}
	r.Signature = sig
	return r, nil
}

// VerifyPostureReport verifies r against the reporter's public key. It consults
// ONLY the report bytes and the key — it performs no ledger replay (PCAS-claim-50).
func VerifyPostureReport(reporterPubDER []byte, r PostureReport) error {
	if len(r.Signature) == 0 {
		return errors.New("succession: posture report is unsigned")
	}
	return crypto.VerifyMessage(reporterPubDER, r.encode(), r.Signature)
}
