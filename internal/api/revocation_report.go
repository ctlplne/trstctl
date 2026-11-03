// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// The revocation report (A245) keeps apart the four places a revocation has
// to take hold, so a revoked certificate is never read as gone because one of
// them answered: the CA's status (what OCSP and the CRL answer), the deployed
// material (every destination it was delivered to), new connections (whether
// endpoints still present it) and existing sessions (whether anything ended
// the sessions opened before the revocation).

const (
	revocationConfirmed   = "confirmed"
	revocationPending     = "pending"
	revocationFailed      = "failed"
	revocationNotObserved = "not_observed"
)

var revocationFacetStates = []string{revocationConfirmed, revocationPending, revocationFailed, revocationNotObserved}

type revocationFacet struct {
	State  string     `json:"state"`
	Detail string     `json:"detail"`
	At     *time.Time `json:"at,omitempty"`
}

type revocationDestination struct {
	Target string `json:"target"`
	State  string `json:"state"`
	// Now is what the destination holds: replaced, removed, still_deployed or
	// failed.
	Now string    `json:"now"`
	At  time.Time `json:"at"`
}

type revocationEndpoint struct {
	EndpointID string    `json:"endpoint_id"`
	Vantage    string    `json:"vantage"`
	State      string    `json:"state"`
	Detail     string    `json:"detail"`
	CheckedAt  time.Time `json:"checked_at"`
}

type revocationCertificateReport struct {
	CertificateID    string                  `json:"certificate_id"`
	Serial           string                  `json:"serial"`
	Fingerprint      string                  `json:"fingerprint"`
	RevokedAt        *time.Time              `json:"revoked_at,omitempty"`
	Reason           string                  `json:"reason,omitempty"`
	CAStatus         revocationFacet         `json:"ca_status"`
	DeployedMaterial revocationFacet         `json:"deployed_material"`
	Destinations     []revocationDestination `json:"destinations"`
	NewConnections   revocationFacet         `json:"new_connections"`
	Endpoints        []revocationEndpoint    `json:"endpoints"`
	ExistingSessions revocationFacet         `json:"existing_sessions"`
}

type revocationReport struct {
	IdentityID   string                        `json:"identity_id"`
	Certificates []revocationCertificateReport `json:"certificates"`
}

// buildRevocationCertificateReport decides the four facets from the evidence.
func buildRevocationCertificateReport(cert store.Certificate, ev store.RevocationEvidence) revocationCertificateReport {
	revokedAt := time.Time{}
	if cert.RevokedAt != nil {
		revokedAt = *cert.RevokedAt
	}
	out := revocationCertificateReport{CertificateID: cert.ID, Serial: cert.Serial, Fingerprint: cert.Fingerprint,
		RevokedAt: cert.RevokedAt, Reason: cert.RevocationReason, Destinations: []revocationDestination{}, Endpoints: []revocationEndpoint{}}

	switch {
	case cert.IssuingExternalCAID != "":
		out.CAStatus = revocationFacet{State: revocationNotObserved,
			Detail: "revoked in trstctl's inventory; the external CA's own status is not read back"}
	case ev.CA.Recorded && ev.CA.RevokedAt != nil && ev.CA.CRLThisUpdate != nil:
		out.CAStatus = revocationFacet{State: revocationConfirmed, At: ev.CA.CRLThisUpdate,
			Detail: fmt.Sprintf("OCSP answers revoked, and CRL #%d lists it", ev.CA.CRLNumber)}
	case ev.CA.Recorded && ev.CA.RevokedAt != nil:
		out.CAStatus = revocationFacet{State: revocationPending, At: ev.CA.RevokedAt,
			Detail: "OCSP answers revoked; no CRL has been generated since the revocation"}
	case ev.CA.Recorded:
		out.CAStatus = revocationFacet{State: revocationFailed,
			Detail: "the CA's record of the serial is not marked revoked, so OCSP and the CRL still answer good"}
	default:
		out.CAStatus = revocationFacet{State: revocationNotObserved, Detail: "trstctl's CA has no record of this serial"}
	}

	counts := map[string]int{}
	for _, d := range ev.Deliveries {
		dest := revocationDestination{Target: d.Target, At: d.LatestAt}
		switch {
		case strings.HasSuffix(d.LatestStatus, "failed") || d.LatestStatus == "rollback_refused" || d.LatestStatus == "takedown_refused":
			dest.State, dest.Now = revocationFailed, "failed"
		case d.LatestPrint == cert.Fingerprint && (d.LatestStatus == "containment_stopped" || d.LatestStatus == "purged" ||
			d.LatestStatus == "taken_down" || d.LatestStatus == "purge_absent" || d.LatestStatus == "takedown_absent"):
			dest.State, dest.Now = revocationConfirmed, "removed"
		case d.LatestPrint != "" && d.LatestPrint != cert.Fingerprint &&
			(d.LatestStatus == "delivered" || d.LatestStatus == "verified" || d.LatestStatus == "rolled_back"):
			dest.State, dest.Now = revocationConfirmed, "replaced"
		default:
			dest.State, dest.Now = revocationPending, "still_deployed"
		}
		counts[dest.State]++
		out.Destinations = append(out.Destinations, dest)
	}
	switch total := len(out.Destinations); {
	case total == 0:
		out.DeployedMaterial = revocationFacet{State: revocationNotObserved,
			Detail: "trstctl delivered it to no destination it manages; copies elsewhere are not seen"}
	case counts[revocationFailed] > 0:
		out.DeployedMaterial = revocationFacet{State: revocationFailed,
			Detail: fmt.Sprintf("%d of %d destinations failed to take it down", counts[revocationFailed], total)}
	case counts[revocationPending] > 0:
		out.DeployedMaterial = revocationFacet{State: revocationPending,
			Detail: fmt.Sprintf("%d of %d destinations still hold it", counts[revocationPending], total)}
	default:
		out.DeployedMaterial = revocationFacet{State: revocationConfirmed,
			Detail: fmt.Sprintf("all %d destinations hold a replacement or had it removed", total)}
	}

	counts = map[string]int{}
	for _, o := range ev.Observations {
		ep := revocationEndpoint{EndpointID: o.EndpointID, Vantage: o.Vantage, CheckedAt: o.CheckedAt}
		switch {
		case o.CheckedAt.Before(revokedAt):
			ep.State, ep.Detail = revocationNotObserved, "not checked since the revocation"
		case o.Reached && o.ObservedFingerprint == cert.Fingerprint:
			ep.State, ep.Detail = revocationFailed, "still presents the revoked certificate"
		case o.Reached:
			ep.State, ep.Detail = revocationConfirmed, "presents another certificate"
		default:
			ep.State, ep.Detail = revocationConfirmed, "no longer answers"
		}
		counts[ep.State]++
		out.Endpoints = append(out.Endpoints, ep)
	}
	switch total := len(out.Endpoints); {
	case total == 0:
		out.NewConnections = revocationFacet{State: revocationNotObserved, Detail: "no endpoint was checked for this certificate"}
	case counts[revocationFailed] > 0:
		out.NewConnections = revocationFacet{State: revocationFailed,
			Detail: fmt.Sprintf("%d of %d checked endpoints still present it to new connections", counts[revocationFailed], total)}
	case counts[revocationNotObserved] > 0:
		out.NewConnections = revocationFacet{State: revocationNotObserved,
			Detail: fmt.Sprintf("%d of %d endpoints were not checked since the revocation", counts[revocationNotObserved], total)}
	default:
		out.NewConnections = revocationFacet{State: revocationConfirmed,
			Detail: fmt.Sprintf("all %d checked endpoints stopped presenting it", total)}
	}

	if len(ev.Stops) > 0 {
		at := ev.Stops[0].At
		out.ExistingSessions = revocationFacet{State: revocationConfirmed, At: &at,
			Detail: "the listener holding it was stopped (" + ev.Stops[0].Status + " on " + ev.Stops[0].Target + "), ending the sessions it held"}
	} else {
		out.ExistingSessions = revocationFacet{State: revocationNotObserved,
			Detail: "sessions opened before the revocation are not observed; a containment stop or a listener restart ends them"}
	}
	return out
}

func (a *API) getIdentityRevocationReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id := r.PathValue("id")
	if _, err := a.store.GetIdentity(r.Context(), tenantID, id); err != nil {
		a.writeError(w, err)
		return
	}
	certs, err := a.store.IdentityRevokedCertificates(r.Context(), tenantID, id, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	report := revocationReport{IdentityID: id, Certificates: []revocationCertificateReport{}}
	for _, cert := range certs {
		if cert.Status != "revoked" || cert.RevokedAt == nil {
			continue
		}
		// A leaf the platform issuing CA minted carries no CA id on its row; the
		// revocation recorded it under that CA, as the projection does.
		caID := cert.CAID
		if caID == "" && cert.IssuingExternalCAID == "" {
			caID = a.platformIssuingCAID
		}
		ev, err := a.store.CertificateRevocationEvidence(r.Context(), tenantID, id, caID, cert.Serial, cert.Fingerprint, *cert.RevokedAt)
		if err != nil {
			a.writeError(w, err)
			return
		}
		report.Certificates = append(report.Certificates, buildRevocationCertificateReport(cert, ev))
	}
	a.writeJSON(w, http.StatusOK, report)
}

// WithPlatformIssuingCAID names the platform issuing CA's id, the CA a
// platform-issued leaf's revocation is recorded under.
func WithPlatformIssuingCAID(id string) Option {
	return func(c *config) { c.platformIssuingCAID = id }
}

func revocationReportRoutes(a *API) []route {
	return []route{
		{method: "GET", path: "/api/v1/identities/{id}/revocation-report", opID: "getIdentityRevocationReport",
			summary: "Report, per revoked certificate, the CA status, the deployed material, new-connection rejection and existing-session termination, each confirmed, pending, failed or not observed",
			handler: a.getIdentityRevocationReport, pathParams: []param{pathUUID("id")}, resSchema: "IdentityRevocationReport",
			successCode: "200", perm: authz.IdentitiesRead},
	}
}

func revocationReportSchemas() map[string]*Schema {
	facet := func() *Schema {
		return object(map[string]*Schema{"state": {Type: "string", Enum: revocationFacetStates}, "detail": str(), "at": timestamp()}, "state", "detail")
	}
	return map[string]*Schema{
		"IdentityRevocationReport": object(map[string]*Schema{
			"identity_id": str(),
			"certificates": {Type: "array", Items: object(map[string]*Schema{
				"certificate_id": str(), "serial": str(), "fingerprint": str(), "revoked_at": timestamp(), "reason": str(),
				"ca_status": facet(), "deployed_material": facet(), "new_connections": facet(), "existing_sessions": facet(),
				"destinations": {Type: "array", Items: object(map[string]*Schema{
					"target": str(), "state": {Type: "string", Enum: revocationFacetStates},
					"now": {Type: "string", Enum: []string{"replaced", "removed", "still_deployed", "failed"}}, "at": timestamp(),
				}, "target", "state", "now", "at")},
				"endpoints": {Type: "array", Items: object(map[string]*Schema{
					"endpoint_id": str(), "vantage": str(), "state": {Type: "string", Enum: revocationFacetStates}, "detail": str(), "checked_at": timestamp(),
				}, "endpoint_id", "vantage", "state", "detail", "checked_at")},
			}, "certificate_id", "serial", "fingerprint", "ca_status", "deployed_material", "destinations", "new_connections", "endpoints", "existing_sessions")},
		}, "identity_id", "certificates"),
	}
}
