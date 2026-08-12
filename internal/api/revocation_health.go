// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"
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
