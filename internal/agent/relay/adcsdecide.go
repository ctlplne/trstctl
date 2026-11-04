// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/adcsdb"
)

// N1: a request an AD CS template holds for a CA manager's approval is
// approved or denied through the domain-joined relay on the CA's network,
// after trstctl's own approval. The relay reads the request's row first and
// acts only while the CA still holds it as pending — certutil -resubmit would
// otherwise issue a request a manager already denied — then runs certutil as
// its own domain identity (-resubmit to issue, -deny to refuse) and reads the
// row back; the control plane records the decision only from a report whose
// row says the CA now holds that disposition.

// KindADCSDecide is the relay-executed decision on a pending AD CS request.
const KindADCSDecide = "adcs.request.decide"

// Decisions on a pending AD CS request.
const (
	ADCSDecisionApprove = "approve"
	ADCSDecisionDeny    = "deny"
)

// ADCSDecideIntent is the job payload: one pending request, at one CA, and
// what to do with it.
type ADCSDecideIntent struct {
	// ID is the decision's own id; the control plane records the decision under
	// it, so a retried job cannot record twice.
	ID              string `json:"id"`
	CAConfig        string `json:"ca_config"`
	RequestID       int    `json:"request_id"`
	Decision        string `json:"decision"`
	RequiredAgentID string `json:"required_agent_id"`
}

// ADCSDecideReport is what returns: what the CA now says about the request.
type ADCSDecideReport struct {
	CAConfig    string `json:"ca_config"`
	RequestID   int    `json:"request_id"`
	Decision    string `json:"decision"`
	Disposition string `json:"disposition"`
	Serial      string `json:"serial,omitempty"`
}

// ADCSDecisionDisposition is the disposition a decision leaves at the CA.
func ADCSDecisionDisposition(decision string) adcsdb.DBDisposition {
	if decision == ADCSDecisionApprove {
		return adcsdb.DispositionIssued
	}
	return adcsdb.DispositionDenied
}

// ValidateADCSDecideIntent checks a queued decision.
func ValidateADCSDecideIntent(intent ADCSDecideIntent) error {
	if intent.ID == "" || intent.RequiredAgentID == "" || !ValidCAConfig(intent.CAConfig) || intent.RequestID <= 0 ||
		(intent.Decision != ADCSDecisionApprove && intent.Decision != ADCSDecisionDeny) {
		return errors.New("relay: an AD CS decision needs its id, one certsrv CA, a request id, approve or deny, and one exact relay")
	}
	return nil
}

// ValidateADCSDecideReport checks a relay's answer against the queued
// decision: the same CA, request and decision, and the request's row read
// back with the disposition the decision leaves.
func ValidateADCSDecideReport(intent ADCSDecideIntent, r ADCSDecideReport) error {
	switch {
	case r.CAConfig != intent.CAConfig || r.RequestID != intent.RequestID || r.Decision != intent.Decision:
		return errors.New("relay: AD CS decision report names a different request, CA or decision than the queued one")
	case r.Disposition != string(ADCSDecisionDisposition(intent.Decision)):
		return errors.New("relay: AD CS decision report does not read the request back with the decided disposition")
	case intent.Decision == ADCSDecisionApprove && !ValidADCSSerial(r.Serial):
		return errors.New("relay: AD CS approval report names no issued serial")
	}
	return nil
}

const certutilDecideTimeout = 2 * time.Minute

func runADCSDecide(ctx context.Context, ch Channel, job Job) bool {
	var intent ADCSDecideIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || ValidateADCSDecideIntent(intent) != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a decision on one pending AD CS request")
		return false
	}
	if CertutilPath == "" {
		report(ctx, ch, job, OutcomeFailed, "this relay has no certutil; AD CS decisions need a domain-joined Windows relay")
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, certutilDecideTimeout)
	defer cancel()
	id := strconv.Itoa(intent.RequestID)
	view := func() (disposition, serial string) {
		rows, err := readCertutilCSV(ctx, CertutilPath, "-config", intent.CAConfig, "-view",
			"-restrict", "RequestID="+id, "-out", "RequestID,SerialNumber,Request.Disposition", "csv")
		if err == nil && len(rows) == 1 && adcsdb.RequestIDOf(rows[0]) == intent.RequestID {
			return string(adcsdb.DispositionOf(rows[0])), adcsdb.SerialOf(rows[0])
		}
		return "", ""
	}
	if before, _ := view(); before != string(adcsdb.DispositionPending) {
		if before == "" {
			before = "not found"
		}
		report(ctx, ch, job, OutcomeFailed, "the CA does not hold request "+id+" as pending ("+before+"); nothing was changed")
		return false
	}
	verb := "-deny"
	if intent.Decision == ADCSDecisionApprove {
		verb = "-resubmit"
	}
	if err := runCertutil(ctx, CertutilPath, "-config", intent.CAConfig, verb, id); err != nil {
		report(ctx, ch, job, OutcomeFailed, "certutil could not "+intent.Decision+" the request at the CA")
		return false
	}
	disposition, serial := view()
	want := ADCSDecisionDisposition(intent.Decision)
	if disposition != string(want) {
		report(ctx, ch, job, OutcomeFailed, "certutil reported the decision but the CA database does not read the request back as "+string(want))
		return false
	}
	out := ADCSDecideReport{CAConfig: intent.CAConfig, RequestID: intent.RequestID, Decision: intent.Decision, Disposition: disposition}
	if intent.Decision == ADCSDecisionApprove {
		out.Serial = serial
	}
	detail, err := json.Marshal(out)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the AD CS decision report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
