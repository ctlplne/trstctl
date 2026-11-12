// SPDX-License-Identifier: BUSL-1.1

// Package adcsfake is a faithful in-process double of the MS-WCCE transport an
// ADCS CA exposes over DCOM/RPC, enough to exercise the ADCS plugin end-to-end
// in a Linux CI where the real DCOM/RPC wire cannot run. It implements
// adcs.Transport with the protocol's semantics — assigning request ids, returning
// the CR_DISP_* dispositions (issued, under-submission for manager approval,
// denied), and signing submitted CSRs with a local software authority via the
// crypto boundary — so it holds no crypto/* itself.
package adcsfake

import (
	"context"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca/adcs"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// certValidity is the validity the CA's template grants issued certificates
// (ADCS validity is template-driven, not request-driven).
const certValidity = 365 * 24 * time.Hour

type pendingReq struct {
	csrDER    []byte
	remaining int // RetrievePending calls that stay under submission before issuing
	// held keeps the request under submission until Approve or Deny (N1-L1).
	held bool
}

// Transport is a fake MS-WCCE transport backed by a software CA.
type Transport struct {
	authority *cryptoca.Authority

	mu           sync.Mutex
	pending      map[int]*pendingReq
	seq          int
	pendingPolls int
	deny         bool
	// holdForApproval holds every new request until Approve or Deny; issued and
	// denied keep each decided request's answer, which RetrievePending
	// returns again, as a CA does (N1-L1).
	holdForApproval bool
	issued          map[int]adcs.Submission
	denied          map[int]bool
}

var _ adcs.Transport = (*Transport)(nil)

// NewTransport starts a fake transport backed by a fresh software CA. By default
// requests are issued immediately.
func NewTransport() (*Transport, error) {
	authority, err := cryptoca.NewAuthority("Contoso Issuing CA")
	if err != nil {
		return nil, err
	}
	return &Transport{authority: authority, pending: map[int]*pendingReq{}, issued: map[int]adcs.Submission{}, denied: map[int]bool{}}, nil
}

// SetHoldForApproval makes every new request wait under submission until a CA
// manager decides it with Approve or Deny, modeling a template that requires
// manager approval (N1-L1).
func (t *Transport) SetHoldForApproval(hold bool) {
	t.mu.Lock()
	t.holdForApproval = hold
	t.mu.Unlock()
}

// Approve issues a held request, as a CA manager's approval does.
func (t *Transport) Approve(requestID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	pr := t.pending[requestID]
	if pr == nil || !pr.held {
		return false
	}
	delete(t.pending, requestID)
	t.issue(requestID, pr.csrDER)
	return true
}

// Deny refuses a held request, as a CA manager's denial does.
func (t *Transport) Deny(requestID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	pr := t.pending[requestID]
	if pr == nil || !pr.held {
		return false
	}
	delete(t.pending, requestID)
	t.denied[requestID] = true
	return true
}

// HeldRequests lists the requests the CA holds for approval, in order.
func (t *Transport) HeldRequests() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []int
	for id, pr := range t.pending {
		if pr.held {
			out = append(out, id)
		}
	}
	sort.Ints(out)
	return out
}

// SetPendingPolls makes a submitted request come back under submission and stay
// there for the next n RetrievePending calls before it is issued, modeling a
// request held for manager approval.
func (t *Transport) SetPendingPolls(n int) {
	t.mu.Lock()
	t.pendingPolls = n
	t.mu.Unlock()
}

// SetDeny makes the CA's policy module deny every submission (CR_DISP_DENIED).
func (t *Transport) SetDeny(deny bool) {
	t.mu.Lock()
	t.deny = deny
	t.mu.Unlock()
}

// Submit implements adcs.Transport (ICertRequestD2::Request2).
func (t *Transport) Submit(_ context.Context, _, _ string, csrDER []byte) (adcs.Submission, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	reqID := t.seq
	if t.deny {
		return adcs.Submission{Disposition: adcs.DispDenied, RequestID: reqID, StatusMessage: "Denied by Policy Module"}, nil
	}
	if t.holdForApproval {
		t.pending[reqID] = &pendingReq{csrDER: append([]byte(nil), csrDER...), held: true}
		return adcs.Submission{Disposition: adcs.DispUnderSubmission, RequestID: reqID, StatusMessage: "Taken Under Submission"}, nil
	}
	if t.pendingPolls > 0 {
		t.pending[reqID] = &pendingReq{csrDER: append([]byte(nil), csrDER...), remaining: t.pendingPolls}
		return adcs.Submission{Disposition: adcs.DispUnderSubmission, RequestID: reqID, StatusMessage: "Taken Under Submission"}, nil
	}
	return t.issue(reqID, csrDER), nil
}

// RetrievePending implements adcs.Transport (ICertRequest::RetrievePending).
func (t *Transport) RetrievePending(_ context.Context, _ string, requestID int) (adcs.Submission, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sub, ok := t.issued[requestID]; ok {
		return sub, nil
	}
	if t.denied[requestID] {
		return adcs.Submission{Disposition: adcs.DispDenied, RequestID: requestID, StatusMessage: "Denied by the CA manager"}, nil
	}
	pr := t.pending[requestID]
	if pr == nil {
		return adcs.Submission{Disposition: adcs.DispError, RequestID: requestID, StatusMessage: "no such request"}, nil
	}
	if pr.held || pr.remaining > 0 {
		if !pr.held {
			pr.remaining--
		}
		return adcs.Submission{Disposition: adcs.DispUnderSubmission, RequestID: requestID, StatusMessage: "Taken Under Submission"}, nil
	}
	delete(t.pending, requestID)
	return t.issue(requestID, pr.csrDER), nil
}

// issue signs the CSR and returns an issued submission, which a later
// RetrievePending returns again (caller holds t.mu).
func (t *Transport) issue(reqID int, csrDER []byte) adcs.Submission {
	issued, err := t.authority.IssueFromCSR(csrDER, certValidity)
	if err != nil {
		return adcs.Submission{Disposition: adcs.DispError, RequestID: reqID, StatusMessage: err.Error()}
	}
	sub := adcs.Submission{Disposition: adcs.DispIssued, RequestID: reqID, CertChainPEM: issued.CertificatePEM}
	t.issued[reqID] = sub
	return sub
}
