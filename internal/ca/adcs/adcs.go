// Package adcs is the internal Microsoft Active Directory Certificate Services
// (ADCS) CA plugin (F4, sprint S4.9), built from the CA-plugin template
// (internal/ca/catemplate): it implements only the CA-specific Backend and the
// template contributes the rest.
//
// ADCS enrolls over MS-WCCE (the Windows Client Certificate Enrollment Protocol)
// via DCOM/RPC — ICertRequestD2::Request2 to submit a PKCS#10 under a CA config
// ("HOST\CAName") and certificate template, returning a disposition and request
// id, then ICertRequest::RetrievePending to collect a request held for manager
// approval. That DCOM/RPC wire transport is Windows-specific and cannot run in a
// Linux CI, so this package separates the *enrollment semantics* (which are the
// CA-specific logic — dispositions, request ids, the under-submission poll, and
// denial handling) from the *wire transport*, behind the Transport seam. An
// in-process faithful double exercises the semantics in CI (internal/ca/adcs/
// adcsfake); the production DCOM/RPC Transport is the integration follow-up.
//
// The package holds no crypto/* (AN-3) and custodies no signing key — ADCS does —
// so AN-4 is not implicated; on the platform it runs behind ca.IssuanceService
// for idempotency (AN-5) and the outbox (AN-6).
package adcs

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
)

// Disposition mirrors the MS-WCCE CR_DISP_* request dispositions returned by
// ICertRequestD2::Request2 and ICertRequest::RetrievePending.
type Disposition int

const (
	DispIncomplete      Disposition = 0 // CR_DISP_INCOMPLETE
	DispError           Disposition = 1 // CR_DISP_ERROR
	DispDenied          Disposition = 2 // CR_DISP_DENIED
	DispIssued          Disposition = 3 // CR_DISP_ISSUED
	DispIssuedOutOfBand Disposition = 4 // CR_DISP_ISSUED_OUT_OF_BAND
	DispUnderSubmission Disposition = 5 // CR_DISP_UNDER_SUBMISSION (pending approval)
	DispRevoked         Disposition = 6 // CR_DISP_REVOKED
)

// String names the disposition for diagnostics.
func (d Disposition) String() string {
	switch d {
	case DispIncomplete:
		return "incomplete"
	case DispError:
		return "error"
	case DispDenied:
		return "denied"
	case DispIssued:
		return "issued"
	case DispIssuedOutOfBand:
		return "issued out of band"
	case DispUnderSubmission:
		return "under submission"
	case DispRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("disposition(%d)", int(d))
	}
}

// Submission is the result of an MS-WCCE Request2/RetrievePending call: the
// disposition, the CA-assigned request id (needed to retrieve a pending request),
// the issued chain (PEM, when DispIssued), and the disposition message.
type Submission struct {
	Disposition   Disposition
	RequestID     int
	CertChainPEM  []byte
	StatusMessage string
}

// Transport performs the MS-WCCE operations against an ADCS CA. The production
// implementation speaks ICertRequestD2 over DCOM/RPC; tests use an in-process
// double. Implementations format the PKCS#10 and request attributes (certificate
// template, SANs) for the wire and decode the issued certificate to a PEM chain.
type Transport interface {
	// Submit submits csrDER under the CA config "HOST\CAName" with the given
	// certificate template (ICertRequestD2::Request2).
	Submit(ctx context.Context, caConfig, template string, csrDER []byte) (Submission, error)
	// RetrievePending fetches a request previously taken under submission, by its
	// request id (ICertRequest::RetrievePending).
	RetrievePending(ctx context.Context, caConfig string, requestID int) (Submission, error)
}

const (
	defaultPoll = 2 * time.Second
	maxPolls    = 60
)

// Config holds the ADCS target: the authority's display name, the CA config
// string ("HOST\CAName", the MS-WCCE pwszAuthority), and the certificate template.
type Config struct {
	Name     string
	CAConfig string
	Template string
}

// backend drives the WCCE enrollment state machine over a Transport. It is the
// only CA-specific code; the template supplies the ca.CA behaviour.
type backend struct {
	cfg       Config
	transport Transport
	poll      time.Duration
}

// Option configures the plugin.
type Option func(*backend)

// WithPollInterval sets the delay between RetrievePending polls while a request
// is under submission.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the ADCS plugin over transport. The returned *catemplate.Plugin is a
// ca.CA.
func New(cfg Config, transport Transport, opts ...Option) *catemplate.Plugin {
	b := &backend{cfg: cfg, transport: transport, poll: defaultPoll}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue submits the CSR and resolves the request to an issued chain, polling
// through any under-submission (manager-approval) state.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("adcs: at least one DNS name is required")
	}
	sub, err := b.transport.Submit(ctx, b.cfg.CAConfig, b.cfg.Template, req.CSR)
	if err != nil {
		return nil, fmt.Errorf("adcs: submit: %w", err)
	}
	return b.resolve(ctx, sub)
}

// resolve turns a submission into an issued chain: it returns the certificate
// when issued, polls RetrievePending while under submission, and errors on any
// other disposition (denied, error, revoked, issued-out-of-band).
func (b *backend) resolve(ctx context.Context, sub Submission) ([]byte, error) {
	for polls := 0; ; polls++ {
		switch sub.Disposition {
		case DispIssued:
			if len(sub.CertChainPEM) == 0 {
				return nil, fmt.Errorf("adcs: request %d issued but returned no certificate", sub.RequestID)
			}
			return sub.CertChainPEM, nil
		case DispUnderSubmission:
			if polls >= maxPolls {
				return nil, fmt.Errorf("adcs: request %d still under submission after %d polls", sub.RequestID, polls)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(b.poll):
			}
			next, err := b.transport.RetrievePending(ctx, b.cfg.CAConfig, sub.RequestID)
			if err != nil {
				return nil, fmt.Errorf("adcs: retrieve pending request %d: %w", sub.RequestID, err)
			}
			sub = next
		default:
			msg := sub.StatusMessage
			if msg == "" {
				msg = "no disposition message"
			}
			return nil, fmt.Errorf("adcs: request %d not issued (%s): %s", sub.RequestID, sub.Disposition, msg)
		}
	}
}
