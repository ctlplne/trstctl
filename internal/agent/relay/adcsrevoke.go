// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/adcsdb"
)

// A162: the relay-executed AD CS revocation. trstctl's external revocation of a
// certificate an adcs issuer issued is handed to the domain-joined relay named
// on that issuer. The relay revokes it at the CA with certutil as its own
// domain identity, publishes a new CRL, and reads the CA database row back; the
// control plane records the revocation only from a report that says all three
// happened.

// KindADCSRevoke is the relay-executed AD CS revocation.
const KindADCSRevoke = "adcs.revoke"

const certutilRevokeTimeout = 2 * time.Minute

// ADCSRevokeIntent is the job payload: one certificate, by serial, at one CA.
type ADCSRevokeIntent struct {
	// ID is the revocation's own id; the control plane records the revocation
	// under it, so a retried job cannot record twice.
	ID              string `json:"id"`
	CAConfig        string `json:"ca_config"`
	Serial          string `json:"serial"`
	ReasonCode      int    `json:"reason_code"`
	RequiredAgentID string `json:"required_agent_id"`
}

// ADCSRevokeReport is what returns: what the CA now says about the serial.
type ADCSRevokeReport struct {
	CAConfig     string `json:"ca_config"`
	Serial       string `json:"serial"`
	ReasonCode   int    `json:"reason_code"`
	Disposition  string `json:"disposition"`
	CRLPublished bool   `json:"crl_published"`
}

// ValidADCSSerial reports whether s is a serial certutil takes: hex, at most a
// 20-octet serial.
func ValidADCSSerial(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// ADCSRevocationReason reports whether certutil -revoke takes this RFC 5280
// reason code: 0 (unspecified) through 5 (cessationOfOperation).
func ADCSRevocationReason(code int) bool { return code >= 0 && code <= 5 }

// ValidateADCSRevokeIntent checks a queued AD CS revocation.
func ValidateADCSRevokeIntent(intent ADCSRevokeIntent) error {
	if intent.ID == "" || intent.RequiredAgentID == "" || !ValidCAConfig(intent.CAConfig) ||
		!ValidADCSSerial(intent.Serial) || !ADCSRevocationReason(intent.ReasonCode) {
		return errors.New("relay: an AD CS revocation needs its id, one certsrv CA, a hex serial, a reason certutil takes and one exact relay")
	}
	return nil
}

// ValidateADCSRevokeReport checks a relay's answer against the queued
// revocation: the same CA, serial and reason, the CA database row read back as
// revoked, and a new CRL published.
func ValidateADCSRevokeReport(intent ADCSRevokeIntent, r ADCSRevokeReport) error {
	switch {
	case r.CAConfig != intent.CAConfig || !strings.EqualFold(r.Serial, intent.Serial) || r.ReasonCode != intent.ReasonCode:
		return errors.New("relay: AD CS revocation report names a different certificate, CA or reason than the queued one")
	case r.Disposition != string(adcsdb.DispositionRevoked):
		return errors.New("relay: AD CS revocation report does not read the certificate back as revoked")
	case !r.CRLPublished:
		return errors.New("relay: AD CS revocation report says no new CRL was published")
	}
	return nil
}

func runADCSRevoke(ctx context.Context, ch Channel, job Job) bool {
	var intent ADCSRevokeIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || ValidateADCSRevokeIntent(intent) != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not an AD CS revocation of one certificate")
		return false
	}
	if CertutilPath == "" {
		report(ctx, ch, job, OutcomeFailed, "this relay has no certutil; AD CS revocation needs a domain-joined Windows relay")
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, certutilRevokeTimeout)
	defer cancel()
	serial := strings.ToLower(intent.Serial)
	if err := runCertutil(ctx, CertutilPath, "-config", intent.CAConfig, "-revoke", serial, strconv.Itoa(intent.ReasonCode)); err != nil {
		report(ctx, ch, job, OutcomeFailed, "certutil could not revoke the certificate at the CA")
		return false
	}
	if err := runCertutil(ctx, CertutilPath, "-config", intent.CAConfig, "-CRL"); err != nil {
		report(ctx, ch, job, OutcomeFailed, "the CA revoked the certificate but certutil could not publish a new CRL")
		return false
	}
	rows, err := readCertutilCSV(ctx, CertutilPath, "-config", intent.CAConfig, "-view",
		"-restrict", "SerialNumber="+serial, "-out", "SerialNumber,Request.Disposition", "csv")
	disposition := ""
	if err == nil && len(rows) == 1 && strings.EqualFold(adcsdb.SerialOf(rows[0]), serial) {
		disposition = string(adcsdb.DispositionOf(rows[0]))
	}
	if disposition != string(adcsdb.DispositionRevoked) {
		report(ctx, ch, job, OutcomeFailed, "certutil reported the revocation but the CA database does not read the certificate back as revoked")
		return false
	}
	detail, err := json.Marshal(ADCSRevokeReport{CAConfig: intent.CAConfig, Serial: serial, ReasonCode: intent.ReasonCode,
		Disposition: disposition, CRLPublished: true})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the AD CS revocation report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
