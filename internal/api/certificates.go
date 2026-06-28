package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

type certificateIngestRequest struct {
	PEM                string `json:"pem"`
	OwnerID            string `json:"owner_id"`
	DeploymentLocation string `json:"deployment_location"`
	Source             string `json:"source"`
}

type certificateResponse struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	OwnerID            *string    `json:"owner_id"`
	Subject            string     `json:"subject"`
	SANs               []string   `json:"sans"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	Fingerprint        string     `json:"fingerprint"`
	KeyAlgorithm       string     `json:"key_algorithm"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	DeploymentLocation string     `json:"deployment_location"`
	Source             string     `json:"source"`
	CreatedAt          time.Time  `json:"created_at"`
	// Lifecycle status (active | superseded | revoked) and revocation metadata, so
	// the served surface reflects a revoked certificate — a revoked cert is
	// visibly "revoked", not silently still "active".
	Status           string     `json:"status"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

type certificateHealthDashboard struct {
	GeneratedAt     time.Time                         `json:"generated_at"`
	InventoryPath   string                            `json:"inventory_path"`
	ExpiringPath    string                            `json:"expiring_path"`
	Summary         certificateHealthSummary          `json:"summary"`
	ExpiryBuckets   []certificateExpiryBucketResponse `json:"expiry_buckets"`
	SourceBreakdown []certificateSourceHealthResponse `json:"source_breakdown"`
	Expiring        []certificateHealthItem           `json:"expiring"`
}

type certificateHealthSummary struct {
	Total               int    `json:"total"`
	Active              int    `json:"active"`
	Revoked             int    `json:"revoked"`
	Superseded          int    `json:"superseded"`
	Expired             int    `json:"expired"`
	Expiring7d          int    `json:"expiring_7d"`
	Expiring30d         int    `json:"expiring_30d"`
	Expiring90d         int    `json:"expiring_90d"`
	ExternalSourceCount int    `json:"external_source_count"`
	ImportedCount       int    `json:"imported_count"`
	DiscoveredCount     int    `json:"discovered_count"`
	UnknownExpiryCount  int    `json:"unknown_expiry_count"`
	Health              string `json:"health"`
}

type certificateExpiryBucketResponse struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type certificateSourceHealthResponse struct {
	Source      string `json:"source"`
	Count       int    `json:"count"`
	External    bool   `json:"external"`
	Expired     int    `json:"expired"`
	Expiring30d int    `json:"expiring_30d"`
}

type certificateHealthItem struct {
	ID                 string     `json:"id"`
	Subject            string     `json:"subject"`
	Fingerprint        string     `json:"fingerprint"`
	DeploymentLocation string     `json:"deployment_location"`
	Source             string     `json:"source"`
	Status             string     `json:"status"`
	NotAfter           *time.Time `json:"not_after"`
	DaysRemaining      int        `json:"days_remaining"`
	ExternallyIssued   bool       `json:"externally_issued"`
}

func toCertificateResponse(c store.Certificate) certificateResponse {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	return certificateResponse{
		ID: c.ID, TenantID: c.TenantID, OwnerID: c.OwnerID, Subject: c.Subject, SANs: sans,
		Issuer: c.Issuer, Serial: c.Serial, Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, DeploymentLocation: c.DeploymentLocation,
		Source: c.Source, CreatedAt: c.CreatedAt,
		Status: c.Status, RevokedAt: c.RevokedAt, RevocationReason: c.RevocationReason,
	}
}

func toCertificateHealthDashboard(s store.CertificateHealthSnapshot) certificateHealthDashboard {
	summary := certificateHealthSummary{
		Total:               s.Summary.Total,
		Active:              s.Summary.Active,
		Revoked:             s.Summary.Revoked,
		Superseded:          s.Summary.Superseded,
		Expired:             s.Summary.Expired,
		Expiring7d:          s.Summary.Expiring7d,
		Expiring30d:         s.Summary.Expiring30d,
		Expiring90d:         s.Summary.Expiring90d,
		ExternalSourceCount: s.Summary.ExternalSourceCount,
		ImportedCount:       s.Summary.ImportedCount,
		DiscoveredCount:     s.Summary.DiscoveredCount,
		UnknownExpiryCount:  s.Summary.UnknownExpiryCount,
		Health:              certificateHealthState(s.Summary),
	}
	out := certificateHealthDashboard{
		GeneratedAt:   s.GeneratedAt,
		InventoryPath: "/api/v1/certificates",
		ExpiringPath:  "/api/v1/certificates?expiring_before=" + s.GeneratedAt.Add(30*24*time.Hour).UTC().Format(time.RFC3339),
		Summary:       summary,
	}
	for _, b := range s.ExpiryBuckets {
		out.ExpiryBuckets = append(out.ExpiryBuckets, certificateExpiryBucketResponse{Name: b.Name, Count: b.Count})
	}
	for _, src := range s.SourceBreakdown {
		out.SourceBreakdown = append(out.SourceBreakdown, certificateSourceHealthResponse{
			Source: src.Source, Count: src.Count, External: src.External, Expired: src.Expired, Expiring30d: src.Expiring30d,
		})
	}
	for _, c := range s.Expiring {
		item := certificateHealthItem{
			ID: c.ID, Subject: c.Subject, Fingerprint: c.Fingerprint, DeploymentLocation: c.DeploymentLocation,
			Source: c.Source, Status: c.Status, NotAfter: c.NotAfter, ExternallyIssued: certificateExternallyIssued(c.Source),
		}
		if c.NotAfter != nil {
			item.DaysRemaining = int(c.NotAfter.Sub(s.GeneratedAt).Hours() / 24)
		}
		out.Expiring = append(out.Expiring, item)
	}
	return out
}

func certificateHealthState(s store.CertificateHealthSummary) string {
	switch {
	case s.Expired > 0 || s.Expiring7d > 0:
		return "critical"
	case s.Expiring30d > 0 || s.UnknownExpiryCount > 0:
		return "warning"
	default:
		return "ok"
	}
}

func certificateExternallyIssued(source string) bool {
	return strings.TrimSpace(strings.ToLower(source)) != "issued"
}

func sansOf(info certinfo.Info) []string {
	sans := []string{}
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	return sans
}

//trstctl:mutation
func (a *API) ingestCertificate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req certificateIngestRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.PEM == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "pem is required")
		}
		info, err := certinfo.Inspect([]byte(req.PEM))
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "could not parse certificate: "+err.Error())
		}
		var ownerID *string
		if req.OwnerID != "" {
			if _, err := a.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
				if store.IsNotFound(err) {
					return 0, nil, errStatus(http.StatusUnprocessableEntity, "owner_id does not reference an existing owner")
				}
				return 0, nil, err
			}
			ownerID = &req.OwnerID
		}
		source := req.Source
		if source == "" {
			source = "import"
		}
		notBefore, notAfter := info.NotBefore, info.NotAfter
		// Per-feature telemetry (COVER-009): time the served inventory ingest and record
		// a non-sensitive feature/action/outcome signal (no subject/serial/tenant labels).
		start := time.Now()
		c, err := a.orch.RecordCertificate(ctx, tenantID, store.Certificate{
			OwnerID: ownerID, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter,
			DeploymentLocation: req.DeploymentLocation, Source: source,
		})
		a.observeFeature("inventory", "ingest", start, err)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toCertificateResponse(c), nil
	})
}

func (a *API) getCertificate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	c, err := a.store.GetCertificate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toCertificateResponse(c))
}

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var expiringBefore *time.Time
	if s := r.URL.Query().Get("expiring_before"); s != "" {
		ts, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "expiring_before must be RFC3339"))
			return
		}
		expiringBefore = &ts
	}

	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	// The cursor is keyset state. For the expiring query it carries (not_after, id)
	// so the page rides the (tenant_id, not_after, id) expiry index (SPINE-006); for
	// the plain query it carries id alone. They are distinct cursor shapes, so a
	// cursor from one mode is not valid in the other.
	afterID := store.ZeroUUID
	var afterNotAfter *time.Time
	if c := r.URL.Query().Get("cursor"); c != "" {
		na, id, perr := decodeCertCursor(c, expiringBefore != nil)
		if perr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		afterID = id
		afterNotAfter = na
	}

	certs, err := a.store.ListCertificatesPage(r.Context(), tenantID, afterID, afterNotAfter, limit, expiringBefore)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		items = append(items, toCertificateResponse(c))
	}
	next := ""
	if len(certs) == limit {
		last := certs[len(certs)-1]
		next = encodeCertCursor(last, expiringBefore != nil)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getCertificateHealth(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	snapshot, err := a.store.CertificateHealth(r.Context(), tenantID, time.Now(), 25)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toCertificateHealthDashboard(snapshot))
}

// certCursorSep separates not_after from id in the composite expiry cursor. A
// canonical UUID and an RFC3339Nano timestamp never contain it.
const certCursorSep = "|"

// encodeCertCursor encodes the keyset cursor for the certificate inventory page.
// For the plain (id-ordered) page it is the row id alone (unchanged wire shape);
// for the expiry-ordered page (SPINE-006) it is "not_after|id" so the next page can
// keyset on (not_after, id) and ride the composite expiry index.
func encodeCertCursor(c store.Certificate, expiring bool) string {
	if !expiring {
		return encodeCursor(c.ID)
	}
	na := ""
	if c.NotAfter != nil {
		na = c.NotAfter.UTC().Format(time.RFC3339Nano)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(na + certCursorSep + c.ID))
}

// decodeCertCursor decodes the keyset cursor produced by encodeCertCursor. The
// shape depends on whether the request is the expiry-ordered page (a composite
// not_after+id cursor) or the plain page (an id-only cursor); a cursor minted for
// one mode is rejected in the other so a client cannot mix them and skip rows.
func decodeCertCursor(c string, expiring bool) (*time.Time, string, error) {
	if !expiring {
		id, err := decodeCursor(c)
		return nil, id, err
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, "", err
	}
	naStr, id, found := strings.Cut(string(b), certCursorSep)
	if !found || len(id) != 36 {
		return nil, "", errors.New("cursor is not a valid expiry cursor")
	}
	ts, err := time.Parse(time.RFC3339Nano, naStr)
	if err != nil {
		return nil, "", errors.New("cursor not_after is not a valid timestamp")
	}
	return &ts, id, nil
}
