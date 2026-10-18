// SPDX-License-Identifier: BUSL-1.1

// Package release reviews and executes an explicit, custodian-approved
// disposition of one historical managed-CA certificate dependency. It never
// equates expiry with proof that a certificate was not used outside trstctl.
package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/decommission/depstate"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

var (
	ErrInvalid  = errors.New("CA dependent release: invalid reviewed request")
	ErrConflict = errors.New("CA dependent release: source or outstanding state changed")
)

type Request struct {
	CertificateID             string `json:"certificate_id"`
	ExpectedCertificateSHA256 string `json:"expected_certificate_sha256"`
	Reason                    string `json:"reason"`
	RiskAccepted              bool   `json:"risk_accepted"`
}

// Review contains only public certificate facts and the operator's explicit
// risk decision. Custodians see these fields before approving the ceremony.
type Review struct {
	TenantID          string    `json:"tenant_id"`
	KeyID             string    `json:"key_id"`
	CertificateID     string    `json:"certificate_id"`
	SourceEventID     string    `json:"source_event_id"`
	SourceSequence    uint64    `json:"source_sequence"`
	Serial            string    `json:"serial"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	Subject           string    `json:"subject"`
	NotAfter          time.Time `json:"not_after"`
	KeyOrigin         string    `json:"key_origin"`
	Reason            string    `json:"reason"`
	RiskAccepted      bool      `json:"risk_accepted"`
}

func (r Review) releasePayload() depstate.DependencyReleasedV2 {
	return depstate.DependencyReleasedV2{
		TenantID: r.TenantID, KeyID: r.KeyID,
		Dependent:     depstate.Dependent{Class: depstate.DependentCredential, ID: r.CertificateID},
		SourceEventID: r.SourceEventID, SourceSequence: r.SourceSequence,
		Serial: r.Serial, CertificateSHA256: r.CertificateSHA256,
		Reason: r.Reason, RiskAccepted: r.RiskAccepted,
	}
}

func (r Review) Purpose() string { return depstate.ReleasePurposeV2(r.releasePayload()) }

type Reviewer struct {
	store *corestore.Store
	log   *events.Log
	repo  *decstore.Repo
}

func NewReviewer(store *corestore.Store, log *events.Log) *Reviewer {
	return &Reviewer{store: store, log: log, repo: decstore.New(store)}
}

func (r *Reviewer) Preview(ctx context.Context, tenantID, keyID string, request Request, now time.Time) (Review, error) {
	var empty Review
	if r == nil || r.store == nil || r.log == nil || r.repo == nil {
		return empty, fmt.Errorf("%w: review service unavailable", ErrInvalid)
	}
	keyID, request.CertificateID = strings.TrimSpace(keyID), strings.TrimSpace(request.CertificateID)
	request.ExpectedCertificateSHA256 = strings.ToLower(strings.TrimSpace(request.ExpectedCertificateSHA256))
	request.Reason = strings.TrimSpace(request.Reason)
	if tenantID == "" || keyID == "" || request.CertificateID == "" ||
		len(request.ExpectedCertificateSHA256) != 64 ||
		request.Reason != depstate.ReleaseReasonExpiredRequesterCustody ||
		!request.RiskAccepted {
		return empty, fmt.Errorf("%w: exact certificate, SHA-256, supported reason code and external-use risk acceptance are required", ErrInvalid)
	}
	cert, err := r.store.GetCertificate(ctx, tenantID, request.CertificateID)
	if err != nil {
		return empty, err
	}
	if cert.IssuanceEventID == "" || cert.Status != "active" ||
		cert.KeyOrigin != string(custody.OriginRequester) || cert.NotAfter == nil ||
		!now.After(*cert.NotAfter) || cert.DeploymentLocation != "" || cert.LastSeenAt != nil {
		return empty, fmt.Errorf("%w: certificate is not an expired, unobserved requester-custody managed leaf", ErrConflict)
	}
	source, found, err := r.log.EventByID(ctx, cert.IssuanceEventID)
	if err != nil {
		return empty, err
	}
	if !found || source.TenantID != tenantID || source.ID != cert.IssuanceEventID || source.Sequence == 0 ||
		source.Type != caevent.EventCAEndEntityIssued ||
		(source.SchemaVersion != caevent.CAIssuedCertificateEvidenceSchemaVersion &&
			source.SchemaVersion != caevent.CAEndEntityInventorySchemaVersion) {
		return empty, fmt.Errorf("%w: no exact historical managed-CA mint event", ErrConflict)
	}
	return r.reviewMint(ctx, tenantID, keyID, request, cert, source)
}

func (r *Reviewer) reviewMint(ctx context.Context, tenantID, keyID string, request Request, cert corestore.Certificate, source eventspec.Event) (Review, error) {
	var empty Review
	registrations, err := depstate.CARegistrations(source)
	if err != nil {
		return empty, err
	}
	if len(registrations) != 1 || registrations[0].KeyID != keyID ||
		registrations[0].Dependent != (depstate.Dependent{Class: depstate.DependentCredential, ID: cert.ID}) {
		return empty, fmt.Errorf("%w: mint does not register this CA key and inventory leaf", ErrConflict)
	}
	var mint struct {
		CAID           string `json:"ca_id"`
		Serial         string `json:"serial"`
		Fingerprint    string `json:"fingerprint"`
		CertificateDER []byte `json:"certificate_der"`
	}
	if err := json.Unmarshal(source.Data, &mint); err != nil {
		return empty, err
	}
	info, err := certinfo.Inspect(mint.CertificateDER)
	if err != nil {
		return empty, fmt.Errorf("%w: source certificate is not parseable", ErrConflict)
	}
	if info.IsCA || mint.CAID != keyID || mint.Serial != cert.Serial ||
		mint.Serial != info.SerialNumber || !bytes.Equal(mint.CertificateDER, cert.CertificateDER) ||
		!strings.EqualFold(mint.Fingerprint, info.SHA256Fingerprint) ||
		!strings.EqualFold(cert.Fingerprint, info.SHA256Fingerprint) ||
		request.ExpectedCertificateSHA256 != info.SHA256Fingerprint ||
		cert.NotAfter == nil || !cert.NotAfter.Equal(info.NotAfter) || cert.Subject != info.Subject {
		return empty, fmt.Errorf("%w: inventory, immutable mint and reviewed SHA-256 differ", ErrConflict)
	}
	authority, err := r.store.GetCAAuthority(ctx, tenantID, keyID)
	if err != nil {
		return empty, err
	}
	issuerDER, err := certinfo.LeafDER([]byte(authority.CertificatePEM))
	if err != nil || crypto.VerifyLeafSignedByCA(mint.CertificateDER, issuerDER) != nil {
		return empty, fmt.Errorf("%w: reviewed leaf has no signature from the exact CA authority", ErrConflict)
	}
	state, found, err := r.repo.FetchKeyState(ctx, tenantID, keyID)
	if err != nil {
		return empty, err
	}
	if !found {
		return empty, fmt.Errorf("%w: CA dependency state absent", ErrConflict)
	}
	outstanding := false
	for _, dep := range state.Unaccounted() {
		if dep == registrations[0].Dependent {
			outstanding = true
			break
		}
	}
	if !outstanding {
		return empty, fmt.Errorf("%w: exact certificate is no longer outstanding", ErrConflict)
	}
	claimed, err := r.store.CACeremonyEffectClaimedForDependent(ctx, tenantID, keyID, cert.ID)
	if err != nil {
		return empty, err
	}
	if claimed {
		return empty, fmt.Errorf("%w: exact certificate already has a durable release claim", ErrConflict)
	}
	return Review{
		TenantID: tenantID, KeyID: keyID, CertificateID: cert.ID,
		SourceEventID: source.ID, SourceSequence: source.Sequence,
		Serial: cert.Serial, CertificateSHA256: info.SHA256Fingerprint,
		Subject: info.Subject, NotAfter: info.NotAfter, KeyOrigin: cert.KeyOrigin,
		Reason: request.Reason, RiskAccepted: request.RiskAccepted,
	}, nil
}
