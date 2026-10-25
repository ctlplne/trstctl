// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// RevocationEndpointHealth is one relay-verified CRL or OCSP observation.
type RevocationEndpointHealth struct {
	TargetKey              string `json:"target_key"`
	Protocol               string `json:"protocol"`
	Endpoint               string `json:"endpoint"`
	IssuerSubject          string `json:"issuer_subject"`
	IssuerFingerprint      string `json:"issuer_fingerprint,omitempty"`
	CertificateID          string `json:"certificate_id"`
	CertificateSubject     string `json:"certificate_subject"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	CertificateSerial      string `json:"certificate_serial"`
	Status                 string `json:"status"`
	DetailCode             string `json:"detail_code"`
	LatencyMS              int64  `json:"latency_ms"`
	ThisUpdate             string `json:"this_update,omitempty"`
	NextUpdate             string `json:"next_update,omitempty"`
	SignatureVerified      bool   `json:"signature_verified"`
	RevokedCount           int    `json:"revoked_count,omitempty"`
	ResponseStatus         string `json:"response_status,omitempty"`
	ResponderSubject       string `json:"responder_subject,omitempty"`
	ProbeID                string `json:"probe_id"`
	ObservedByAgentID      string `json:"observed_by_agent_id"`
	ObservedByAgentName    string `json:"observed_by_agent_name"`
	EvidenceDigest         string `json:"evidence_digest"`
	ObservedAt             string `json:"observed_at"`
}

type RevocationHealthSummary struct {
	Endpoints   int `json:"endpoints"`
	Fresh       int `json:"fresh"`
	Expiring    int `json:"expiring"`
	Stale       int `json:"stale"`
	Unreachable int `json:"unreachable"`
	Unparseable int `json:"unparseable"`
}

type RevocationHealth struct {
	Observed bool                       `json:"observed"`
	Items    []RevocationEndpointHealth `json:"items"`
	Summary  RevocationHealthSummary    `json:"summary"`
	Guidance string                     `json:"guidance"`
}

const revocationHealthGuidance = "No signed relay observation means endpoint health is unknown, never healthy. CRLs fit offline and batch clients because one signed list covers many certificates; monitor nextUpdate and distribution reachability. OCSP fits clients that need current per-certificate status; monitor the signed response status plus thisUpdate/nextUpdate. A client configured to soft-fail may continue when either service is unreachable, so green application traffic is not proof that revocation works. Test the behavior of each real client stack before choosing fail-open or fail-closed policy."

func (a *API) listRevocationHealth(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "revocation health is not configured"))
		return
	}
	rows, err := a.store.ListRevocationEndpointHealth(r.Context(), tenantID, 500)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := RevocationHealth{
		Observed: len(rows) > 0, Items: make([]RevocationEndpointHealth, 0, len(rows)),
		Summary: RevocationHealthSummary{Endpoints: len(rows)}, Guidance: revocationHealthGuidance,
	}
	for _, row := range rows {
		item := RevocationEndpointHealth{
			TargetKey: row.TargetKey, Protocol: row.Protocol, Endpoint: row.Endpoint,
			IssuerSubject: row.IssuerSubject, IssuerFingerprint: row.IssuerFingerprint,
			CertificateID: row.CertificateID, CertificateSubject: row.CertificateSubject,
			CertificateFingerprint: row.CertificateFingerprint, CertificateSerial: row.CertificateSerial,
			Status: row.Status, DetailCode: row.DetailCode, LatencyMS: row.LatencyMS,
			SignatureVerified: row.SignatureVerified, RevokedCount: row.RevokedCount,
			ResponseStatus: row.ResponseStatus, ResponderSubject: row.ResponderSubject,
			ProbeID: row.ProbeID, ObservedByAgentID: row.ObservedByAgentID,
			ObservedByAgentName: row.ObservedByAgentName, EvidenceDigest: row.EvidenceDigest,
			ObservedAt: row.ObservedAt.UTC().Format(time.RFC3339),
		}
		if row.ThisUpdate != nil {
			item.ThisUpdate = row.ThisUpdate.UTC().Format(time.RFC3339)
		}
		if row.NextUpdate != nil {
			item.NextUpdate = row.NextUpdate.UTC().Format(time.RFC3339)
		}
		switch row.Status {
		case "fresh":
			out.Summary.Fresh++
		case "expiring":
			out.Summary.Expiring++
		case "stale":
			out.Summary.Stale++
		case "unreachable":
			out.Summary.Unreachable++
		case "unparseable":
			out.Summary.Unparseable++
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}

// revocationHealthRoutes serves the relay-verified endpoint health and the
// operator's on-demand probe (replay defect B14-R1).
func (a *API) revocationHealthRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/revocation/health", opID: "listRevocationHealth", summary: "List relay-verified CRL and OCSP endpoint reachability, signature, status, and freshness", handler: a.listRevocationHealth, resSchema: "RevocationHealth", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/revocation/health/probe", opID: "probeRevocationHealth", summary: "Probe this tenant's CRL and OCSP endpoints now through the network relay, instead of at the next hourly sweep", handler: a.probeRevocationHealth, resSchema: "RevocationProbeNow", successCode: "202", mutation: true, perm: authz.CertsWrite},
	}
}

// RevocationProbeNow answers an on-demand probe request.
type RevocationProbeNow struct {
	// Queued is false when a request in the same minute already queued it.
	Queued   bool   `json:"queued"`
	Bucket   string `json:"bucket"`
	Guidance string `json:"guidance"`
}

const revocationProbeNowGuidance = "The network relay probes every CRL and OCSP endpoint the inventory names, then signs its observations; " +
	"read them with GET /api/v1/revocation/health once it reports. Scheduled probes also run every hour. " +
	"Requests inside the same minute share one probe."

func (a *API) probeRevocationHealth(w http.ResponseWriter, r *http.Request) {
	a.mutateWithRecorder(w, r, r.Header.Get("Idempotency-Key"), "", func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "revocation health probing is not configured")
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		request, queued, err := a.orch.RequestRevocationProbe(ctx, tenantID, subject)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, RevocationProbeNow{Queued: queued, Bucket: request.Bucket, Guidance: revocationProbeNowGuidance}, nil
	}, false)
}
