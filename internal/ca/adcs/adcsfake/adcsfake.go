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
}

// Transport is a fake MS-WCCE transport backed by a software CA.
type Transport struct {
	authority *cryptoca.Authority

	mu           sync.Mutex
	pending      map[int]*pendingReq
	seq          int
	pendingPolls int
	deny         bool
}

var _ adcs.Transport = (*Transport)(nil)

// NewTransport starts a fake transport backed by a fresh software CA. By default
// requests are issued immediately.
func NewTransport() (*Transport, error) {
	authority, err := cryptoca.NewAuthority("Contoso Issuing CA")
	if err != nil {
		return nil, err
	}
	return &Transport{authority: authority, pending: map[int]*pendingReq{}}, nil
}

// SetPendingPolls makes a submitted request come back under submission and stay
// there for the next n RetrievePending calls before it is issued, modelling a
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
	pr := t.pending[requestID]
	if pr == nil {
		return adcs.Submission{Disposition: adcs.DispError, RequestID: requestID, StatusMessage: "no such request"}, nil
	}
	if pr.remaining > 0 {
		pr.remaining--
		return adcs.Submission{Disposition: adcs.DispUnderSubmission, RequestID: requestID, StatusMessage: "Taken Under Submission"}, nil
	}
	delete(t.pending, requestID)
	return t.issue(requestID, pr.csrDER), nil
}

// issue signs the CSR and returns an issued submission (caller holds t.mu).
func (t *Transport) issue(reqID int, csrDER []byte) adcs.Submission {
	issued, err := t.authority.IssueFromCSR(csrDER, certValidity)
	if err != nil {
		return adcs.Submission{Disposition: adcs.DispError, RequestID: reqID, StatusMessage: err.Error()}
	}
	return adcs.Submission{Disposition: adcs.DispIssued, RequestID: reqID, CertChainPEM: issued.CertificatePEM}
}
