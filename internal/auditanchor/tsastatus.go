// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/tsa"
)

// TSA certificate revocation and long-term evidence (A145, A146).
//
// A timestamp is only as good as the certificate it was signed under. Checking
// the token's signature and its chain to the pinned root says nothing about
// whether the TSA's key was later found compromised, so the verifier also asks
// the TSA's issuing CA. An export carries that answer with it — a signed OCSP
// response per TSA certificate its timestamps rely on, captured when the export
// was made — and an auditor can supply a fresher CRL from the same CA. A
// certificate revoked for key or CA compromise taints every timestamp it
// signed; one revoked for an ordinary reason (superseded, retired) still
// vouches for the timestamps it signed before its revocation.

// TSAStatusEvidence is a signed OCSP response for one TSA certificate.
type TSAStatusEvidence struct {
	Serial string `json:"serial"`
	OCSP   []byte `json:"ocsp"`
}

// Validation is the long-term validation material an export carries.
type Validation struct {
	TSAStatus  []TSAStatusEvidence `json:"tsa_status"`
	CapturedAt time.Time           `json:"captured_at"`
}

// TSARevocationPolicy is the auditor's revocation input.
type TSARevocationPolicy struct {
	// CRLDER is a CRL from the TSA's issuer (the pinned root), fetched by the
	// auditor; the fresher of it and the export's own evidence decides.
	CRLDER []byte
	// Require refuses an export when any TSA certificate's status cannot be
	// established from evidence issued after its newest timestamp.
	Require bool
}

// TSACertificateStatus is one TSA certificate's verdict in a receipt.
type TSACertificateStatus struct {
	Serial      string    `json:"serial"`
	Status      string    `json:"status"`
	Source      string    `json:"source,omitempty"`
	ThisUpdate  time.Time `json:"this_update,omitempty"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Tokens      int       `json:"tokens"`
	NewestToken time.Time `json:"newest_token"`
}

// tsaStatusAnswer is one source's statement about a serial.
type tsaStatusAnswer struct {
	source     string
	status     string // good | revoked | unknown
	thisUpdate time.Time
	revokedAt  time.Time
	reason     int
}

// compromiseReasons taint every timestamp a certificate signed: once the key
// may have been in someone else's hands, its timestamps prove nothing, early
// or late. Unspecified is treated the same, because it does not say otherwise.
var compromiseReasons = map[int]bool{0: true, 1: true, 2: true, 10: true}

// VerifyTSARevocation establishes the revocation status of every TSA
// certificate the verified tokens were issued under, from the export's own
// validation evidence and the auditor's CRL, all checked against the pinned
// root. It fails when a certificate was revoked in a way that invalidates the
// tokens, and, when the policy requires it, when a status cannot be
// established from evidence issued after the newest timestamp it covers.
func VerifyTSARevocation(tokens []tsa.Token, validation *Validation, rootDER []byte, policy TSARevocationPolicy) ([]TSACertificateStatus, error) {
	type group struct{ status TSACertificateStatus }
	groups := map[string]*group{}
	for _, token := range tokens {
		info, err := certinfo.Inspect(token.TSACertDER)
		if err != nil {
			return nil, fmt.Errorf("auditanchor: inspect a TSA certificate: %w", err)
		}
		g := groups[info.SerialNumber]
		if g == nil {
			g = &group{status: TSACertificateStatus{Serial: info.SerialNumber}}
			groups[info.SerialNumber] = g
		}
		at := token.Info.GenTime.UTC()
		g.status.Tokens++
		if at.After(g.status.NewestToken) {
			g.status.NewestToken = at
		}
	}
	answers := map[string][]tsaStatusAnswer{}
	if validation != nil {
		for _, evidence := range validation.TSAStatus {
			info, err := crypto.ParseOCSPResponse(evidence.OCSP, rootDER)
			if err != nil {
				return nil, fmt.Errorf("auditanchor: the export's OCSP evidence for TSA certificate %s does not verify against the pinned root: %w", evidence.Serial, err)
			}
			if info.Serial != evidence.Serial {
				return nil, fmt.Errorf("auditanchor: the export's OCSP evidence labeled %s answers for %s", evidence.Serial, info.Serial)
			}
			if !info.ResponderIsIssuer && !info.ResponderHasOCSPSigningEKU {
				return nil, fmt.Errorf("auditanchor: the OCSP evidence for TSA certificate %s is signed by a certificate not delegated to answer OCSP", info.Serial)
			}
			answers[info.Serial] = append(answers[info.Serial], tsaStatusAnswer{
				source: "ocsp", status: info.Status, thisUpdate: info.ThisUpdate.UTC(),
				revokedAt: info.RevokedAt.UTC(), reason: info.Reason,
			})
		}
	}
	if len(policy.CRLDER) > 0 {
		crl, err := crypto.ParseCRL(policy.CRLDER, rootDER)
		if err != nil {
			return nil, fmt.Errorf("auditanchor: the supplied CRL does not verify against the pinned TSA root: %w", err)
		}
		if crl.HasDeltaCRLIndicator {
			return nil, errors.New("auditanchor: the supplied CRL is a delta CRL; supply the full CRL")
		}
		for serial := range groups {
			answer := tsaStatusAnswer{source: "crl", status: "good", thisUpdate: crl.ThisUpdate.UTC()}
			for _, entry := range crl.Revoked {
				if entry.Serial == serial {
					answer.status, answer.revokedAt, answer.reason = "revoked", entry.RevokedAt.UTC(), entry.Reason
				}
			}
			answers[serial] = append(answers[serial], answer)
		}
	}

	serials := make([]string, 0, len(groups))
	for serial := range groups {
		serials = append(serials, serial)
	}
	sort.Strings(serials)
	out := make([]TSACertificateStatus, 0, len(serials))
	for _, serial := range serials {
		g := groups[serial]
		status := g.status
		status.Status = "unchecked"
		// A revocation is decisive whenever it was recorded; a clean answer
		// counts only when issued after the newest timestamp it vouches for.
		// OCSP and CRL times carry whole seconds, so the comparison does too.
		newest := status.NewestToken.Truncate(time.Second)
		var decisive *tsaStatusAnswer
		for i := range answers[serial] {
			answer := answers[serial][i]
			switch {
			case answer.status == "revoked":
				if decisive == nil || decisive.status != "revoked" || answer.revokedAt.Before(decisive.revokedAt) {
					decisive = &answers[serial][i]
				}
			case answer.thisUpdate.Before(newest):
				continue
			case decisive == nil || (decisive.status != "revoked" && answer.thisUpdate.After(decisive.thisUpdate)):
				decisive = &answers[serial][i]
			}
		}
		if decisive != nil {
			status.Status, status.Source, status.ThisUpdate = decisive.status, decisive.source, decisive.thisUpdate
		}
		if decisive != nil && decisive.status == "revoked" {
			status.RevokedAt = decisive.revokedAt
			if reason, ok := crypto.RevocationReasonFromCRLCode(decisive.reason); ok {
				status.Reason = string(reason)
			}
			if compromiseReasons[decisive.reason] {
				return out, fmt.Errorf("auditanchor: TSA certificate %s was revoked (%s) at %s; none of its %d timestamp(s) can be trusted",
					serial, status.Reason, status.RevokedAt.Format(time.RFC3339), status.Tokens)
			}
			if !newest.Before(status.RevokedAt) {
				return out, fmt.Errorf("auditanchor: TSA certificate %s was revoked (%s) at %s, before its timestamp from %s",
					serial, status.Reason, status.RevokedAt.Format(time.RFC3339), status.NewestToken.Format(time.RFC3339))
			}
		}
		if status.Status == "unknown" {
			return out, fmt.Errorf("auditanchor: the TSA's issuing CA does not know TSA certificate %s", serial)
		}
		if status.Status == "unchecked" && policy.Require {
			return out, fmt.Errorf("auditanchor: the revocation status of TSA certificate %s could not be established from evidence issued after its newest timestamp (%s); supply a current CRL with --tsa-crl",
				serial, status.NewestToken.Format(time.RFC3339))
		}
		out = append(out, status)
	}
	return out, nil
}
