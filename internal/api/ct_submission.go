// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// CTSubmissionService queues Certificate Transparency precert/cert submission.
// The API owns authz/idempotency; the server service owns validation, outbox
// enqueue, and RFC 6962 delivery through the worker.
type CTSubmissionService interface {
	SubmitCertificateTransparency(ctx context.Context, tenantID, idempotencyKey string, req CTLogSubmissionRequest) (CTLogSubmissionResponse, error)
}

// WithCTSubmission mounts the served CAP-REV-06 CT submission surface. When unset,
// /api/v1/revocation/ct-submissions fails closed with 501.
func WithCTSubmission(svc CTSubmissionService) Option {
	return func(c *config) { c.ctSubmission = svc }
}

type CTLogSubmissionRequest struct {
	RequestedBy            string   `json:"-"`
	CertificatePEM         string   `json:"certificate_pem"`
	PrecertificatePEM      string   `json:"precertificate_pem,omitempty"`
	ChainPEM               []string `json:"chain_pem,omitempty"`
	Logs                   []string `json:"logs"`
	AllowPrivateEndpoint   bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs     []string `json:"private_egress_cidrs,omitempty"`
	SubmissionProfile      string   `json:"submission_profile,omitempty"`
	OperatorCorrelationRef string   `json:"operator_correlation_ref,omitempty"`
	// LogPublicKeys maps a log URL to its public key, base64 DER or PEM (A213):
	// an SCT from that log is verified against it and its inclusion is proven.
	LogPublicKeys map[string]string `json:"log_public_keys,omitempty"`
}

type CTLogSubmissionResponse struct {
	Capability string                `json:"capability"`
	Queued     int                   `json:"queued"`
	Logs       []CTLogSubmissionLog  `json:"logs"`
	Residuals  []CTLogSubmissionNote `json:"residuals,omitempty"`
}

type CTLogSubmissionLog struct {
	LogURL                     string `json:"log_url"`
	PrecertificateQueued       bool   `json:"precertificate_queued"`
	CertificateQueued          bool   `json:"certificate_queued"`
	PrecertificateSubmissionID string `json:"precertificate_submission_id,omitempty"`
	CertificateSubmissionID    string `json:"certificate_submission_id,omitempty"`
}

type CTLogSubmissionNote struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func ctSubmissionDisabledProblem() *apiError {
	return errStatus(http.StatusNotImplemented, "Certificate Transparency submission is not enabled")
}

func mapCTSubmissionError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "required"),
		strings.Contains(msg, "invalid"),
		strings.Contains(msg, "malformed"),
		strings.Contains(msg, "parse certificate"),
		strings.Contains(msg, "pem"),
		strings.Contains(msg, "certificate transparency log"),
		strings.Contains(msg, "outbound endpoint"),
		strings.Contains(msg, "ssrf"):
		return errStatus(http.StatusBadRequest, err.Error())
	default:
		return err
	}
}

//trstctl:mutation
func (a *API) submitCertificateTransparency(w http.ResponseWriter, r *http.Request) {
	if a.ctSubmission == nil {
		a.writeError(w, ctSubmissionDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req CTLogSubmissionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		req.RequestedBy = principal
		if req.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			if len(cleanAPIStringList(req.PrivateEgressCIDRs)) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
			}
			req.PrivateEgressCIDRs = cleanAPIStringList(req.PrivateEgressCIDRs)
			if err := validatePrivateEgressCIDRs(req.PrivateEgressCIDRs); err != nil {
				return 0, nil, err
			}
		}
		res, err := a.ctSubmission.SubmitCertificateTransparency(ctx, tenantID, idempotencyKey, req)
		if err != nil {
			return 0, nil, mapCTSubmissionError(err)
		}
		return http.StatusAccepted, res, nil
	})
}

// CertificateTransparencyEntry is one CT log's SCT for a certificate (A213):
// whether it verified against the log key the submission named, and whether
// the log proved the entry is in its tree against a signed tree head.
type CertificateTransparencyEntry struct {
	SubmissionID       string `json:"submission_id"`
	LogURL             string `json:"log_url"`
	LogID              string `json:"log_id,omitempty"`
	EntryType          string `json:"entry_type"`
	SCTTimestamp       string `json:"sct_timestamp"`
	SCTStatus          string `json:"sct_status"`
	SCTReason          string `json:"sct_reason,omitempty"`
	InclusionStatus    string `json:"inclusion_status"`
	InclusionReason    string `json:"inclusion_reason,omitempty"`
	LeafIndex          *int64 `json:"leaf_index,omitempty"`
	TreeSize           *int64 `json:"tree_size,omitempty"`
	RootHash           string `json:"root_hash,omitempty"`
	InclusionCheckedAt string `json:"inclusion_checked_at,omitempty"`
}

// certificateTransparency is what CT logs answered for one certificate, for
// its detail read.
func (a *API) certificateTransparency(ctx context.Context, tenantID, fingerprint string) ([]CertificateTransparencyEntry, error) {
	rows, err := a.store.CertificateSCTs(ctx, tenantID, fingerprint)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := make([]CertificateTransparencyEntry, 0, len(rows))
	for _, row := range rows {
		entry := CertificateTransparencyEntry{
			SubmissionID: row.SubmissionID, LogURL: row.LogURL, LogID: row.LogID, EntryType: row.EntryType,
			SCTTimestamp: row.SCTTimestamp.UTC().Format(time.RFC3339Nano), SCTStatus: row.SCTStatus,
			SCTReason: row.SCTReason, InclusionStatus: row.InclusionStatus, InclusionReason: row.InclusionReason,
			LeafIndex: row.LeafIndex, TreeSize: row.TreeSize, RootHash: row.RootHash,
		}
		if row.InclusionCheckedAt != nil {
			entry.InclusionCheckedAt = row.InclusionCheckedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, entry)
	}
	return out, nil
}
