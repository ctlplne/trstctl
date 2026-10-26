// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
)

// TSACertificate is one certificate the timestamping authority signs or
// signed under (A145). State is "active" for the one tokens are issued under,
// "retired" for one rotated out without revocation, and "revoked".
type TSACertificate struct {
	Serial     string     `json:"serial"`
	State      string     `json:"state"`
	NotBefore  time.Time  `json:"not_before"`
	NotAfter   time.Time  `json:"not_after"`
	CertSHA256 string     `json:"cert_sha256"`
	CertPEM    string     `json:"cert_pem"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// TSACertificateList lists the TSA's certificates, newest first, and where
// relying parties check their status.
type TSACertificateList struct {
	Items []TSACertificate `json:"items"`
	CRL   string           `json:"crl"`
	OCSP  string           `json:"ocsp"`
}

// TSARotation is the result of moving the TSA onto a new certificate.
type TSARotation struct {
	Current  TSACertificate `json:"current"`
	Previous TSACertificate `json:"previous"`
}

// TSAStatusEvidence is a signed OCSP response for one TSA certificate (A146).
type TSAStatusEvidence struct {
	Serial string `json:"serial"`
	OCSP   []byte `json:"ocsp"`
}

// TSACertificateManager manages the served timestamping authority's
// certificates. The shipped server attaches it when the TSA is served.
type TSACertificateManager interface {
	TSACertificates(ctx context.Context, tenantID string) (TSACertificateList, error)
	RotateTSACertificate(ctx context.Context, tenantID, revokeReason string) (TSARotation, error)
	RevokeTSACertificate(ctx context.Context, tenantID, serial, revokeReason string) (TSACertificate, error)
	TSAStatusEvidence(ctx context.Context, certs [][]byte) ([]TSAStatusEvidence, error)
}

// WithTSACertificates serves TSA certificate rotation and revocation (A145).
func WithTSACertificates(manager TSACertificateManager) Option {
	return func(c *config) { c.tsaCertificates = manager }
}

var (
	// ErrInvalidTSARequest marks a rotation or revocation the caller must change.
	ErrInvalidTSARequest = errors.New("invalid TSA certificate request")
	// ErrTSACertificateNotFound marks an unknown TSA certificate serial.
	ErrTSACertificateNotFound = errors.New("no TSA certificate with this serial")
	// ErrTSANotServed marks a tenant the timestamp authority does not serve.
	ErrTSANotServed = errors.New("the timestamp authority is not served for this tenant")
)

type tsaRotateRequest struct {
	RevokePreviousReason string `json:"revoke_previous_reason,omitempty"`
}

type tsaRevokeRequest struct {
	Reason string `json:"reason"`
}

func (a *API) tsaCertificateManager(w http.ResponseWriter) (TSACertificateManager, bool) {
	if a.tsaCertificates == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "the timestamp authority is not served"))
		return nil, false
	}
	return a.tsaCertificates, true
}

func tsaCertificateError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidTSARequest):
		return errStatus(http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrTSACertificateNotFound), errors.Is(err, ErrTSANotServed):
		return errStatus(http.StatusNotFound, err.Error())
	}
	return err
}

func (a *API) listTSACertificates(w http.ResponseWriter, r *http.Request) {
	manager, ok := a.tsaCertificateManager(w)
	if !ok {
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	list, err := manager.TSACertificates(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, tsaCertificateError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, list)
}

//trstctl:mutation
func (a *API) rotateTSACertificate(w http.ResponseWriter, r *http.Request) {
	manager, ok := a.tsaCertificateManager(w)
	if !ok {
		return
	}
	var req tsaRotateRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("tsa-certificate-rotate\x00" + principal + "\x00" + req.RevokePreviousReason))
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding, func(ctx context.Context, tenantID string) (int, any, error) {
		rotation, err := manager.RotateTSACertificate(ctx, tenantID, req.RevokePreviousReason)
		if err != nil {
			return 0, nil, tsaCertificateError(err)
		}
		return http.StatusOK, rotation, nil
	})
}

//trstctl:mutation
func (a *API) revokeTSACertificate(w http.ResponseWriter, r *http.Request) {
	manager, ok := a.tsaCertificateManager(w)
	if !ok {
		return
	}
	var req tsaRevokeRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	serial := r.PathValue("serial")
	binding := crypto.SHA256Hex([]byte("tsa-certificate-revoke\x00" + principal + "\x00" + serial + "\x00" + req.Reason))
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding, func(ctx context.Context, tenantID string) (int, any, error) {
		revoked, err := manager.RevokeTSACertificate(ctx, tenantID, serial, req.Reason)
		if err != nil {
			return 0, nil, tsaCertificateError(err)
		}
		return http.StatusOK, revoked, nil
	})
}

// auditValidation collects the revocation evidence (A146) for every TSA
// certificate the export's timestamps rely on: its own anchor and the anchor
// records it holds. The TSA's status is public PKI material, read from the
// served TSA's ledger whichever tenant exports. Without a served TSA the
// export carries none.
func (a *API) auditValidation(ctx context.Context, anchor auditanchor.Anchor, records []auditchain.Record) *auditanchor.Validation {
	if a.tsaCertificates == nil {
		return nil
	}
	var certs [][]byte
	if anchor.Kind == auditanchor.KindRFC3161 && anchor.Token != nil {
		certs = append(certs, anchor.Token.TSACertDER)
	}
	for _, record := range records {
		if record.Type != auditanchor.EventTypeAnchored {
			continue
		}
		var payload auditanchor.AnchoredEvent
		if json.Unmarshal(record.Data, &payload) == nil && payload.Anchor.Token != nil {
			certs = append(certs, payload.Anchor.Token.TSACertDER)
		}
	}
	if len(certs) == 0 {
		return nil
	}
	evidence, err := a.tsaCertificates.TSAStatusEvidence(ctx, certs)
	if err != nil {
		// Like the anchor itself, the evidence is best effort: the export
		// still verifies, and its receipt reports the TSA status as
		// unchecked, which --require-tsa-revocation refuses.
		slog.Warn("audit export: TSA status evidence unavailable", slog.String("error", err.Error()))
		return nil
	}
	if len(evidence) == 0 {
		return nil
	}
	validation := &auditanchor.Validation{CapturedAt: time.Now().UTC()}
	for _, e := range evidence {
		validation.TSAStatus = append(validation.TSAStatus, auditanchor.TSAStatusEvidence{Serial: e.Serial, OCSP: e.OCSP})
	}
	return validation
}
