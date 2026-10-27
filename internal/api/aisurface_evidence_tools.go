// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/mcpserver"
)

// The evidence tools answer an agent's posture and exposure questions from the
// served read routes, entered with the caller's own credentials, so tenant scope,
// RBAC and rate limits apply exactly as they do over REST: a token that may not
// read discovery findings gets no discovery findings here either. Each answers
// with a narrative and structured findings under the published result schema.
var mcpEvidenceTools = map[string]string{
	"posture_findings":  "NHI posture findings (shadow, stale, static credentials, over-privileged, exposed) with their evidence; subject narrows by name, kind or inventory ID",
	"weak_key_exposure": "certificates and trust anchors whose keys are weak, with the reader that rated each; subject narrows by subject, issuer or host",
	"distrust_exposure": "the certificates and host trust stores a distrust-list entry affects; subject is the entry's name or SPKI SHA-256",
	"assurance_record":  "a certificate's signed lifecycle assurance record as findings, one per stage, with what was independently observed; subject is the certificate ID",
	"revocation_status": "a certificate's recorded revocation state and the relay's CRL and OCSP observations of it; subject is the certificate ID",
	"crypto_inventory":  "crypto inventory (CBOM) assets with strength, quantum exposure and migration target; subject narrows by algorithm, location or library",
}

// mcpEvidenceFindingLimit bounds one result. A caller narrows the subject for
// the rest; the result says it was truncated.
const mcpEvidenceFindingLimit = 200

// mcpDiscoveryPageLimit and mcpDiscoveryMaxPages bound the discovery findings one
// exposure answer reads.
const (
	mcpDiscoveryPageLimit = 100
	mcpDiscoveryMaxPages  = 20
)

// mcpEvidence is what one evidence tool assembled.
type mcpEvidence struct {
	text      string
	citations []string
	findings  []mcpserver.Finding
	truncated bool
	// partial names the reads the caller's token was refused; the answer covers
	// only what it may read.
	partial []string
	// notes are what the reads themselves say about their coverage.
	notes []string
}

// mcpReadError is a refused or failed read, passed back to the caller as the
// route answered it.
type mcpReadError struct {
	status int
	header http.Header
	body   []byte
}

func (e *mcpReadError) Error() string { return fmt.Sprintf("mcp: read answered HTTP %d", e.status) }

func (a *API) mcpCallEvidence(w http.ResponseWriter, r *http.Request, principal authz.Principal, tool string, req mcpCallRequest) {
	if !a.ai.rate.Allow(principal.Subject + "|" + tool) {
		_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.ratelimited", principal.TenantID,
			[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q}`, principal.Subject, tool)))
		a.writeError(w, errStatus(http.StatusTooManyRequests, "rate limit exceeded"))
		return
	}
	subject := strings.TrimSpace(req.Subject)
	var ev mcpEvidence
	var err error
	switch tool {
	case "posture_findings":
		ev, err = a.mcpPostureFindings(r, subject)
	case "weak_key_exposure":
		ev, err = a.mcpWeakKeyExposure(r, subject)
	case "distrust_exposure":
		ev, err = a.mcpDistrustExposure(r, subject)
	case "assurance_record":
		ev, err = a.mcpAssuranceRecord(r, subject)
	case "revocation_status":
		ev, err = a.mcpRevocationStatus(r, subject)
	case "crypto_inventory":
		ev, err = a.mcpCryptoInventory(r, subject)
	default:
		a.writeError(w, errStatus(http.StatusNotFound, "unknown MCP tool"))
		return
	}
	if err != nil {
		var refused *mcpReadError
		if errors.As(err, &refused) {
			copyMCPRESTResponseHeaders(w.Header(), refused.header)
			w.WriteHeader(refused.status)
			_, _ = w.Write(refused.body)
			return
		}
		a.writeError(w, err)
		return
	}
	if len(ev.findings) > mcpEvidenceFindingLimit {
		ev.findings, ev.truncated = ev.findings[:mcpEvidenceFindingLimit], true
		ev.notes = append(ev.notes, fmt.Sprintf("Only the first %d findings are listed; narrow the subject for the rest.", mcpEvidenceFindingLimit))
	}
	for _, note := range ev.notes {
		ev.text += "\n" + note
	}
	if len(ev.partial) > 0 {
		ev.text += "\nThis token could not read " + strings.Join(ev.partial, ", ") + "; the answer covers only what it may read."
	}
	_ = auditsink.Emit(r.Context(), a.ai.be.Audit, nil, "mcp.tool.call", principal.TenantID,
		[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"scope":%q,"citations":%d,"outcome":"ok"}`, principal.Subject, tool, principal.TenantID, len(ev.citations))))
	res := mcpResult(tool, ev.text, ev.citations, ev.findings)
	sufficient := !ev.truncated && len(ev.partial) == 0
	res.Sufficient, res.Truncated = &sufficient, ev.truncated
	a.writeJSON(w, http.StatusOK, res)
}

// mcpResult is a tool result under the published result schema: every tool, of
// every kind, answers with its narrative and its structured findings.
func mcpResult(tool, text string, citations []string, findings []mcpserver.Finding) mcpCallResponse {
	if findings == nil {
		findings = []mcpserver.Finding{}
	}
	return mcpCallResponse{Schema: mcpserver.ResultSchemaID, Tool: tool, Text: text, Citations: citations,
		GeneratedAt: time.Now().UTC(), Findings: findings}
}

// mcpRead enters one served GET route with the caller's own credentials and
// decodes its JSON answer.
func (a *API) mcpRead(r *http.Request, path string, out any) error {
	inner, err := http.NewRequestWithContext(r.Context(), http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	copyMCPRESTHeaders(inner.Header, r.Header)
	inner.Header.Del("Content-Type")
	rec := newMCPRESTRecorder()
	a.ServeHTTP(rec, inner)
	if status := rec.status(); status < 200 || status >= 300 {
		return &mcpReadError{status: status, header: rec.Header().Clone(), body: append([]byte(nil), rec.body.Bytes()...)}
	}
	if err := json.Unmarshal(rec.body.Bytes(), out); err != nil {
		return fmt.Errorf("mcp: decode %s: %w", path, err)
	}
	return nil
}

// mcpReadOptional is mcpRead for a supplementary read: a refusal for want of
// permission is reported in the answer instead of failing it.
func (a *API) mcpReadOptional(r *http.Request, path string, out any, ev *mcpEvidence, what string) (bool, error) {
	err := a.mcpRead(r, path, out)
	var refused *mcpReadError
	if errors.As(err, &refused) && refused.status == http.StatusForbidden {
		ev.partial = append(ev.partial, what)
		return false, nil
	}
	return err == nil, err
}

// mcpDiscoveryFindings pages the discovery findings a filter matches, bounded.
func (a *API) mcpDiscoveryFindings(r *http.Request, query url.Values, ev *mcpEvidence) ([]discoveryFindingResponse, error) {
	var out []discoveryFindingResponse
	cursor := ""
	for page := 0; page < mcpDiscoveryMaxPages; page++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", strconv.Itoa(mcpDiscoveryPageLimit))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var list struct {
			Items      []discoveryFindingResponse `json:"items"`
			NextCursor string                     `json:"next_cursor"`
		}
		ok, err := a.mcpReadOptional(r, "/api/v1/discovery/findings?"+q.Encode(), &list, ev, "discovery findings")
		if err != nil || !ok {
			return out, err
		}
		out = append(out, list.Items...)
		if list.NextCursor == "" {
			return out, nil
		}
		cursor = list.NextCursor
	}
	ev.truncated = true
	ev.notes = append(ev.notes, fmt.Sprintf("More than %d discovery findings matched; only the first %d were read.",
		mcpDiscoveryPageLimit*mcpDiscoveryMaxPages, mcpDiscoveryPageLimit*mcpDiscoveryMaxPages))
	return out, nil
}

func mcpMentions(subject string, values ...string) bool {
	if subject == "" {
		return true
	}
	s := strings.ToLower(subject)
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), s) {
			return true
		}
	}
	return false
}

// mcpEvidenceIDs keeps the non-empty references, once each, in order.
func mcpEvidenceIDs(ids ...string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] || strings.HasSuffix(id, ":") {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func mcpAttributes(kv ...string) map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if v := strings.TrimSpace(kv[i+1]); v != "" {
			out[kv[i]] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mcpTimeOf(raw string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return mcpserver.At(t)
}

func mcpTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return mcpserver.At(*t)
}

// ---- posture_findings ----------------------------------------------------------

var mcpPostureLists = []struct{ category, path, kind string }{
	{"shadow", "/api/v1/nhi/posture/shadow", "nhi_shadow"},
	{"stale", "/api/v1/nhi/posture/stale", "nhi_stale"},
	{"static credentials", "/api/v1/nhi/posture/static-credentials", "nhi_static_credential"},
	{"over-privilege", "/api/v1/nhi/posture/overprivilege", "nhi_over_privilege"},
	{"exposure", "/api/v1/nhi/posture/exposure", "nhi_exposure"},
}

type mcpPostureItem struct {
	FindingID      string          `json:"finding_id"`
	InventoryID    string          `json:"inventory_id"`
	Ref            string          `json:"ref"`
	Kind           string          `json:"kind"`
	DisplayName    string          `json:"display_name"`
	Severity       string          `json:"severity"`
	RiskScore      int             `json:"risk_score"`
	FindingTypes   []string        `json:"finding_types"`
	Recommendation string          `json:"recommendation"`
	EvidenceRefs   []string        `json:"evidence_refs"`
	Reachability   json.RawMessage `json:"reachability"`
}

func (a *API) mcpPostureFindings(r *http.Request, subject string) (mcpEvidence, error) {
	ev := mcpEvidence{}
	type scored struct {
		finding mcpserver.Finding
		risk    int
	}
	var all []scored
	counts := map[string]int{}
	for _, list := range mcpPostureLists {
		var resp struct {
			GeneratedAt time.Time        `json:"generated_at"`
			Findings    []mcpPostureItem `json:"findings"`
		}
		if err := a.mcpRead(r, list.path, &resp); err != nil {
			return mcpEvidence{}, err
		}
		ev.citations = append(ev.citations, "GET "+list.path)
		for _, it := range resp.Findings {
			id := firstNonEmpty(it.InventoryID, it.FindingID, it.Ref)
			if id == "" || !mcpMentions(subject, it.DisplayName, it.Ref, it.Kind, it.InventoryID, it.FindingID) {
				continue
			}
			confidence := mcpserver.ConfidenceRecorded
			if list.kind == "nhi_exposure" && len(it.Reachability) > 0 && string(it.Reachability) != "null" {
				confidence = mcpserver.ConfidenceObserved
			}
			evidence := mcpEvidenceIDs(it.EvidenceRefs...)
			if len(evidence) == 0 {
				evidence = []string{"nhi_inventory:" + id}
			}
			counts[list.category]++
			all = append(all, scored{risk: it.RiskScore, finding: mcpserver.Finding{
				FindingID: list.kind + ":" + id, Kind: list.kind,
				Summary: fmt.Sprintf("%s (%s%s): severity %s, risk %d. %s", firstNonEmpty(it.DisplayName, it.Ref, id), it.Kind,
					mcpTypesSuffix(it.FindingTypes), it.Severity, it.RiskScore, it.Recommendation),
				EvidenceIDs: evidence, Source: "nhi_posture", ObservedAt: mcpserver.At(resp.GeneratedAt), Confidence: confidence,
				Attributes: mcpAttributes("category", list.category, "nhi_kind", it.Kind, "severity", it.Severity,
					"risk_score", strconv.Itoa(it.RiskScore), "finding_types", strings.Join(it.FindingTypes, ",")),
			}})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].risk != all[j].risk {
			return all[i].risk > all[j].risk
		}
		return all[i].finding.FindingID < all[j].finding.FindingID
	})
	for _, s := range all {
		ev.findings = append(ev.findings, s.finding)
	}
	if len(all) == 0 {
		ev.text = "No NHI posture findings" + mcpSubjectSuffix(subject) + "."
		return ev, nil
	}
	parts := make([]string, 0, len(mcpPostureLists))
	for _, list := range mcpPostureLists {
		if counts[list.category] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[list.category], list.category))
		}
	}
	ev.text = fmt.Sprintf("%s%s (%s). Highest risk: %s", mcpCount(len(all), "NHI posture finding"), mcpSubjectSuffix(subject),
		strings.Join(parts, ", "), all[0].finding.Summary)
	return ev, nil
}

func mcpTypesSuffix(types []string) string {
	if len(types) == 0 {
		return ""
	}
	return "; " + strings.Join(types, ", ")
}

// mcpCount words a count with its noun: "1 certificate", "2 certificates".
func mcpCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func mcpSubjectSuffix(subject string) string {
	if subject == "" {
		return ""
	}
	return fmt.Sprintf(" matching %q", subject)
}

// ---- weak_key_exposure and distrust_exposure -------------------------------------

// mcpKeyExposure reads the two record sets key exposure is answered from: the
// rated certificate inventory (rogue-certificate posture, which carries every
// certificate's weak-key and distrust verdict) and the discovery findings a
// reader rated while the certificate's bytes were at hand, trust-store anchors
// included.
func (a *API) mcpKeyExposure(r *http.Request, discovery url.Values, ev *mcpEvidence) (rogueCertificatePostureResponse, []discoveryFindingResponse, error) {
	var posture rogueCertificatePostureResponse
	if err := a.mcpRead(r, "/api/v1/revocation/rogue-certificates", &posture); err != nil {
		return posture, nil, err
	}
	ev.citations = append(ev.citations, "GET /api/v1/revocation/rogue-certificates")
	if posture.ReadLimited {
		ev.truncated = true
		ev.notes = append(ev.notes, fmt.Sprintf("The rated certificate inventory covers the first %d certificates and discovery findings, so this answer may be incomplete.", rogueCertificateReadLimit))
	}
	found, err := a.mcpDiscoveryFindings(r, discovery, ev)
	if err != nil {
		return posture, nil, err
	}
	if len(ev.partial) == 0 {
		ev.citations = append(ev.citations, "GET /api/v1/discovery/findings?"+discovery.Encode())
	}
	return posture, found, nil
}

// mcpDiscoveryMeta is the part of a discovery finding's metadata exposure reads:
// the receiver-stamped host and agent, the store an anchor sits in, and the
// verdict the reader computed.
type mcpDiscoveryMeta struct {
	Host           string `json:"host"`
	AgentID        string `json:"agent_id"`
	TrustStoreKind string `json:"trust_store_kind"`
	Profile        string `json:"profile"`
	Platform       string `json:"platform"`
	Subject        string `json:"subject"`
	KeyWeakReason  string `json:"key_weak_reason"`
	DistrustEntry  string `json:"distrust_entry"`
	DistrustHow    string `json:"distrust_how"`
}

func mcpDiscoveryMetaOf(f discoveryFindingResponse) mcpDiscoveryMeta {
	var meta mcpDiscoveryMeta
	_ = json.Unmarshal(f.Metadata, &meta)
	if meta.TrustStoreKind == "" && f.Kind == "trust-store" {
		meta.TrustStoreKind = "trust-store"
	}
	return meta
}

// mcpDiscoveredExposure turns one discovery finding into a trust-store or
// certificate finding. kindPrefix is "distrusted" or "weak_key".
func mcpDiscoveredExposure(f discoveryFindingResponse, kindPrefix, detail string) (mcpserver.Finding, string) {
	meta := mcpDiscoveryMetaOf(f)
	host := firstNonEmpty(strings.TrimSpace(meta.Host), f.Provenance)
	if f.Kind == "trust-store" {
		storeNode := graph.TrustStoreNodeID(host, meta.TrustStoreKind, meta.Profile)
		return mcpserver.Finding{
			FindingID: kindPrefix + "_trust_anchor:discovery_finding:" + f.ID, Kind: kindPrefix + "_trust_anchor",
			Summary: fmt.Sprintf("%s on %s holds %s (%s).", mcpStoreName(meta.TrustStoreKind), firstNonEmpty(host, "an unnamed host"),
				firstNonEmpty(meta.Subject, f.Ref), detail),
			EvidenceIDs: mcpEvidenceIDs("discovery_finding:"+f.ID, "graph:"+storeNode, "agent:"+meta.AgentID),
			Source:      "discovery_findings", ObservedAt: mcpserver.At(f.LastSeenAt), Confidence: mcpserver.ConfidenceObserved,
			Attributes: mcpAttributes("host", host, "trust_store", storeNode, "trust_store_kind", meta.TrustStoreKind, "profile", meta.Profile,
				"platform", meta.Platform, "anchor", f.Ref, "fingerprint", f.Fingerprint, "agent_id", meta.AgentID),
		}, host
	}
	return mcpserver.Finding{
		FindingID: kindPrefix + "_certificate:discovery_finding:" + f.ID, Kind: kindPrefix + "_certificate",
		Summary:     fmt.Sprintf("Discovered certificate %s at %s (%s).", firstNonEmpty(meta.Subject, f.Fingerprint), firstNonEmpty(f.Ref, host), detail),
		EvidenceIDs: mcpEvidenceIDs("discovery_finding:"+f.ID, "agent:"+meta.AgentID),
		Source:      "discovery_findings", ObservedAt: mcpserver.At(f.LastSeenAt), Confidence: mcpserver.ConfidenceObserved,
		Attributes: mcpAttributes("host", host, "location", f.Ref, "fingerprint", f.Fingerprint, "agent_id", meta.AgentID),
	}, host
}

// mcpStoreName names a trust store by its kind; an older agent reports none.
func mcpStoreName(kind string) string {
	if kind == "" || kind == "trust-store" {
		return "A trust store"
	}
	return "The " + kind + " trust store"
}

// mcpInventoryExposure turns one rated inventory certificate into a finding.
func mcpInventoryExposure(f rogueCertificateFinding, kindPrefix, detail string, confidence mcpserver.Confidence) mcpserver.Finding {
	evidence := []string{}
	if f.CertificateID != "" {
		evidence = append(evidence, "certificate:"+f.CertificateID)
	}
	if f.DiscoveryID != "" {
		evidence = append(evidence, "discovery_finding:"+f.DiscoveryID)
	}
	for _, target := range f.InstalledOn {
		evidence = append(evidence, "connector_target:"+target.TargetID)
	}
	evidence = mcpEvidenceIDs(append(evidence, f.EvidenceRefs...)...)
	if len(evidence) == 0 {
		evidence = []string{"rogue_certificate:" + f.ID}
	}
	installed := make([]string, 0, len(f.InstalledOn))
	for _, target := range f.InstalledOn {
		installed = append(installed, firstNonEmpty(target.TargetName, target.TargetID))
	}
	return mcpserver.Finding{
		FindingID: kindPrefix + "_certificate:" + evidence[0], Kind: kindPrefix + "_certificate",
		Summary:     fmt.Sprintf("Certificate %s (serial %s, issuer %s): %s.", f.Subject, firstNonEmpty(f.Serial, "unknown"), firstNonEmpty(f.Issuer, "unknown"), detail),
		EvidenceIDs: evidence, Source: "certificates", ObservedAt: mcpTimePtr(f.DiscoveredAt), Confidence: confidence,
		Attributes: mcpAttributes("certificate_id", f.CertificateID, "subject", f.Subject, "issuer", f.Issuer, "serial", f.Serial,
			"fingerprint", strings.ToLower(f.Fingerprint), "severity", f.Severity, "risk_score", strconv.Itoa(f.RiskScore),
			"installed_on", strings.Join(installed, ",")),
	}
}

func (a *API) mcpWeakKeyExposure(r *http.Request, subject string) (mcpEvidence, error) {
	ev := mcpEvidence{}
	posture, found, err := a.mcpKeyExposure(r, url.Values{"key_strength": {"weak"}}, &ev)
	if err != nil {
		return mcpEvidence{}, err
	}
	inventory := map[string]bool{}
	certs, anchors := 0, 0
	for _, f := range posture.Findings {
		if len(f.WeakKeyReasons) == 0 || !mcpMentions(subject, f.Subject, f.Issuer, f.Serial, f.Fingerprint) {
			continue
		}
		inventory[strings.ToLower(f.Fingerprint)] = f.Fingerprint != ""
		certs++
		ev.findings = append(ev.findings, mcpInventoryExposure(f, "weak_key", "weak key: "+strings.Join(f.WeakKeyReasons, "; "), mcpserver.ConfidenceObserved))
	}
	hosts := map[string]bool{}
	for _, f := range found {
		meta := mcpDiscoveryMetaOf(f)
		if inventory[strings.ToLower(f.Fingerprint)] || !mcpMentions(subject, meta.Subject, f.Ref, meta.Host, f.Fingerprint) {
			continue
		}
		finding, host := mcpDiscoveredExposure(f, "weak_key", "weak key: "+firstNonEmpty(meta.KeyWeakReason, "rated weak by its reader"))
		if f.Kind == "trust-store" {
			anchors++
		} else {
			certs++
		}
		if host != "" {
			hosts[host] = true
		}
		ev.findings = append(ev.findings, finding)
	}
	if len(ev.findings) == 0 {
		ev.text = "No certificate or trust anchor with a weak key" + mcpSubjectSuffix(subject) + " was found."
		return ev, nil
	}
	ev.text = fmt.Sprintf("%s and %s%s have weak keys, on %s reported by discovery. Replace each key; the findings name where each one was seen.",
		mcpCount(certs, "certificate"), mcpCount(anchors, "trust anchor"), mcpSubjectSuffix(subject), mcpCount(len(hosts), "host"))
	return ev, nil
}

// mcpDistrustEntry finds the distrust-list entry an agent named, by name or by
// its SPKI SHA-256.
func mcpDistrustEntry(subject string) (trust.Entry, error) {
	if subject == "" {
		return trust.Entry{}, errStatus(http.StatusBadRequest, "distrust_exposure needs the distrust-list entry's name (or SPKI SHA-256) in subject")
	}
	entries := trust.Active().Entries()
	for _, e := range entries {
		if strings.EqualFold(e.Name, subject) || strings.EqualFold(e.SPKISHA256, subject) {
			return e, nil
		}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	if len(names) > 20 {
		names = append(names[:20], "…")
	}
	return trust.Entry{}, errStatus(http.StatusNotFound, fmt.Sprintf("no distrust-list entry is named %q; the list names: %s", subject, strings.Join(names, "; ")))
}

func (a *API) mcpDistrustExposure(r *http.Request, subject string) (mcpEvidence, error) {
	entry, err := mcpDistrustEntry(subject)
	if err != nil {
		return mcpEvidence{}, err
	}
	ev := mcpEvidence{}
	posture, found, err := a.mcpKeyExposure(r, url.Values{"distrust_entry": {entry.Name}}, &ev)
	if err != nil {
		return mcpEvidence{}, err
	}
	inventory := map[string]bool{}
	certs, stores := 0, 0
	hosts := map[string]bool{}
	for _, f := range posture.Findings {
		if f.Distrust == nil || !strings.EqualFold(f.Distrust.Entry, entry.Name) {
			continue
		}
		confidence := mcpserver.ConfidenceObserved
		if f.Distrust.How == "issuer_name" {
			// Matched by the recorded issuer name only: another CA can carry it.
			confidence = mcpserver.ConfidenceInferred
		}
		inventory[strings.ToLower(f.Fingerprint)] = f.Fingerprint != ""
		certs++
		finding := mcpInventoryExposure(f, "distrusted", mcpDistrustDetail(entry.Name, f.Distrust.How), confidence)
		finding.Attributes = mcpWithAttribute(finding.Attributes, "distrust_how", f.Distrust.How)
		ev.findings = append(ev.findings, finding)
	}
	for _, f := range found {
		meta := mcpDiscoveryMetaOf(f)
		if !strings.EqualFold(meta.DistrustEntry, entry.Name) || (f.Kind != "trust-store" && inventory[strings.ToLower(f.Fingerprint)]) {
			continue
		}
		finding, host := mcpDiscoveredExposure(f, "distrusted", mcpDistrustDetail(entry.Name, meta.DistrustHow))
		finding.Attributes = mcpWithAttribute(finding.Attributes, "distrust_how", meta.DistrustHow)
		if meta.DistrustHow == "issuer_name" {
			finding.Confidence = mcpserver.ConfidenceInferred
		}
		if f.Kind == "trust-store" {
			stores++
		} else {
			certs++
		}
		if host != "" {
			hosts[host] = true
		}
		ev.findings = append(ev.findings, finding)
	}
	ev.citations = append(ev.citations, "distrust_list:"+entry.Name)
	ev.text = fmt.Sprintf("%s is on the distrust list (since %s): %s It affects %s and %s across %s.",
		entry.Name, firstNonEmpty(entry.Since, "an unrecorded date"), strings.TrimSpace(entry.Reason),
		mcpCount(certs, "certificate"), mcpCount(stores, "trust store"), mcpCount(len(hosts), "host"))
	if certs+stores == 0 {
		ev.text = fmt.Sprintf("%s is on the distrust list (since %s): %s No certificate or trust store this tenant has discovered or recorded is affected; hosts and stores no agent has scanned are not covered.",
			entry.Name, firstNonEmpty(entry.Since, "an unrecorded date"), strings.TrimSpace(entry.Reason))
	}
	return ev, nil
}

// mcpDistrustDetail words how a certificate matched the entry.
func mcpDistrustDetail(entry, how string) string {
	switch how {
	case "itself":
		return "it is " + entry
	case "chain":
		return "issued under " + entry + ", matched in its recorded chain"
	case "issuer_key_id":
		return "issued under " + entry + ", matched by its authority key identifier"
	case "issuer_name":
		return "issued under " + entry + ", matched by issuer name only"
	default:
		return "matched " + entry
	}
}

func mcpWithAttribute(attrs map[string]string, key, value string) map[string]string {
	if strings.TrimSpace(value) == "" {
		return attrs
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs[key] = value
	return attrs
}

// ---- assurance_record ---------------------------------------------------------------

func mcpBasisConfidence(b assurance.Basis) mcpserver.Confidence {
	switch b {
	case assurance.BasisSignedObservation:
		return mcpserver.ConfidenceVerified
	case assurance.BasisObserved:
		return mcpserver.ConfidenceObserved
	default:
		return mcpserver.ConfidenceRecorded
	}
}

func (a *API) mcpAssuranceRecord(r *http.Request, subject string) (mcpEvidence, error) {
	if subject == "" {
		return mcpEvidence{}, errStatus(http.StatusBadRequest, "assurance_record needs the certificate ID in subject")
	}
	path := "/api/v1/certificates/" + url.PathEscape(subject) + "/assurance-record"
	var signed assurance.Signed
	if err := a.mcpRead(r, path, &signed); err != nil {
		return mcpEvidence{}, err
	}
	var rec assurance.Record
	if err := json.Unmarshal(signed.Record, &rec); err != nil {
		return mcpEvidence{}, fmt.Errorf("mcp: decode assurance record: %w", err)
	}
	recordRef := "assurance_record:" + rec.Credential.CertificateID
	ev := mcpEvidence{citations: []string{"GET /api/v1/certificates/{id}/assurance-record", recordRef}}
	add := func(kind, evidenceID string, basis assurance.Basis, at *time.Time, summary string, extra ...string) {
		ids := mcpEvidenceIDs(append([]string{evidenceID}, extra...)...)
		if len(ids) == 0 {
			ids = []string{recordRef}
		}
		ev.findings = append(ev.findings, mcpserver.Finding{
			FindingID: kind + ":" + ids[0], Kind: kind, Summary: summary, EvidenceIDs: ids,
			Source: "assurance_record", ObservedAt: at, Confidence: mcpBasisConfidence(basis),
		})
	}
	for _, d := range rec.Discovery {
		add("assurance_discovery", d.EvidenceID, d.Basis, mcpserver.At(d.ObservedAt),
			fmt.Sprintf("Discovered by %s (%s) at %s.", d.Source, d.SourceKind, d.Location))
	}
	if o := rec.Owner; o != nil {
		add("assurance_owner", o.EvidenceID, o.Basis, nil, fmt.Sprintf("Owned by %s (%s).", o.Name, o.Kind))
	}
	if i := rec.Issuance; i.EvidenceID != "" {
		extra := []string{}
		detail := ""
		if i.Profile != nil {
			extra = append(extra, i.Profile.EvidenceID)
			detail += fmt.Sprintf(" under profile %s v%d", i.Profile.Name, i.Profile.Version)
		}
		if i.Approval != nil {
			extra = append(extra, i.Approval.EvidenceID)
			detail += fmt.Sprintf(" with approval request %s", i.Approval.RequestID)
		}
		add("assurance_issuance", i.EvidenceID, i.Basis, mcpTimePtr(i.IssuedAt),
			fmt.Sprintf("Issued by %s (%s)%s.", firstNonEmpty(i.CA, "an unrecorded CA"), i.Source, detail), extra...)
	}
	for _, d := range rec.Deployments {
		add("assurance_deployment", d.EvidenceID, d.Basis, mcpserver.At(d.At),
			fmt.Sprintf("Delivered to %s through %s: %s.", firstNonEmpty(d.Target, d.Destination), d.Connector, d.Status))
	}
	for _, v := range rec.Verifications {
		add("assurance_verification", v.EvidenceID, v.Basis, mcpserver.At(v.At),
			fmt.Sprintf("Verified from %s at %s: %s.", v.Vantage, firstNonEmpty(v.Endpoint, v.Address, v.Target), v.Outcome))
	}
	for _, o := range rec.ExternalObservations {
		add("assurance_external_observation", o.EvidenceID, o.Basis, mcpserver.At(o.At),
			fmt.Sprintf("Observed by %s at %s: %s.", o.Observer, o.Endpoint, o.Verdict))
	}
	for _, run := range rec.Renewals.Runs {
		add("assurance_renewal", run.EvidenceID, run.Basis, mcpserver.At(run.StartedAt),
			fmt.Sprintf("Renewal (%s, %s): %s.", run.Role, run.Trigger, run.Status))
	}
	if rv := rec.Revocation; rv != nil {
		add("assurance_revocation", rv.EvidenceID, rv.Basis, mcpserver.At(rv.RevokedAt), fmt.Sprintf("Revoked: %s.", rv.Reason))
	}
	coverage := fmt.Sprintf("independently observed: %s; recorded only: %s; absent: %s",
		mcpStages(rec.IndependentlyObserved), mcpStages(rec.RecordedOnly), mcpStages(rec.Absent))
	ev.findings = append(ev.findings, mcpserver.Finding{
		FindingID: "assurance_coverage:" + recordRef, Kind: "assurance_coverage",
		Summary:     "Stages " + coverage + ".",
		EvidenceIDs: mcpEvidenceIDs(recordRef, signed.RecordSHA256), Source: "assurance_record",
		ObservedAt: mcpserver.At(rec.GeneratedAt), Confidence: mcpserver.ConfidenceRecorded,
		Attributes: mcpAttributes("record_sha256", signed.RecordSHA256, "truncated", strings.Join(rec.Truncated, ",")),
	})
	ev.text = fmt.Sprintf("Assurance record for %s (serial %s, status %s): %s. The record is signed (%s) and verifies offline against the published key set.",
		rec.Credential.Subject, rec.Credential.Serial, rec.Credential.Status, coverage, signed.RecordSHA256)
	return ev, nil
}

func mcpStages(stages []string) string {
	if len(stages) == 0 {
		return "none"
	}
	return strings.Join(stages, ", ")
}

// ---- revocation_status ---------------------------------------------------------------

func (a *API) mcpRevocationStatus(r *http.Request, subject string) (mcpEvidence, error) {
	if subject == "" {
		return mcpEvidence{}, errStatus(http.StatusBadRequest, "revocation_status needs the certificate ID in subject")
	}
	var cert certificateResponse
	if err := a.mcpRead(r, "/api/v1/certificates/"+url.PathEscape(subject), &cert); err != nil {
		return mcpEvidence{}, err
	}
	certRef := "certificate:" + cert.ID
	ev := mcpEvidence{citations: []string{"GET /api/v1/certificates/{id}", certRef}}
	state := "not revoked (status " + cert.Status + ")"
	if cert.RevokedAt != nil {
		state = fmt.Sprintf("revoked at %s (%s)", cert.RevokedAt.UTC().Format(time.RFC3339), firstNonEmpty(cert.RevocationReason, "no reason recorded"))
	} else if cert.RevocationPending {
		state = "revocation requested and pending"
	}
	ev.findings = append(ev.findings, mcpserver.Finding{
		FindingID: "revocation_state:" + certRef, Kind: "revocation_state",
		Summary: fmt.Sprintf("trstctl records %s as %s.", cert.Subject, state), EvidenceIDs: []string{certRef},
		Source: "certificates", ObservedAt: mcpTimePtr(cert.RevokedAt), Confidence: mcpserver.ConfidenceRecorded,
		Attributes: mcpAttributes("status", cert.Status, "revocation_reason", cert.RevocationReason,
			"revocation_pending", strconv.FormatBool(cert.RevocationPending), "serial", cert.Serial),
	})
	var health RevocationHealth
	ok, err := a.mcpReadOptional(r, "/api/v1/revocation/health", &health, &ev, "revocation endpoint health")
	if err != nil {
		return mcpEvidence{}, err
	}
	observed := 0
	if ok {
		ev.citations = append(ev.citations, "GET /api/v1/revocation/health")
		for _, item := range health.Items {
			if item.CertificateID != cert.ID {
				continue
			}
			observed++
			at := mcpTimeOf(item.ObservedAt)
			confidence := mcpserver.ConfidenceObserved
			if item.SignatureVerified && item.EvidenceDigest != "" {
				confidence = mcpserver.ConfidenceVerified
			}
			evidence := mcpEvidenceIDs("revocation_probe:"+item.ProbeID, "agent:"+item.ObservedByAgentID, "evidence_digest:"+item.EvidenceDigest, certRef)
			response := ""
			if item.ResponseStatus != "" {
				response = ", answered " + item.ResponseStatus
			}
			ev.findings = append(ev.findings, mcpserver.Finding{
				FindingID: "revocation_endpoint:" + item.TargetKey, Kind: "revocation_endpoint",
				Summary: fmt.Sprintf("%s %s: %s (%s)%s, signature verified %t, observed by %s.", strings.ToUpper(item.Protocol), item.Endpoint,
					item.Status, item.DetailCode, response, item.SignatureVerified, firstNonEmpty(item.ObservedByAgentName, item.ObservedByAgentID)),
				EvidenceIDs: evidence, Source: "revocation_health", ObservedAt: at, Confidence: confidence,
				Attributes: mcpAttributes("protocol", item.Protocol, "endpoint", item.Endpoint, "status", item.Status,
					"response_status", item.ResponseStatus, "this_update", item.ThisUpdate, "next_update", item.NextUpdate),
			})
			if cert.RevokedAt != nil && strings.EqualFold(item.Protocol, "ocsp") && strings.EqualFold(item.ResponseStatus, "good") && at != nil && at.After(*cert.RevokedAt) {
				ev.findings = append(ev.findings, mcpserver.Finding{
					FindingID: "revocation_unpublished:" + item.TargetKey, Kind: "revocation_unpublished",
					Summary: fmt.Sprintf("trstctl recorded the revocation at %s, but OCSP at %s still answered good at %s.",
						cert.RevokedAt.UTC().Format(time.RFC3339), item.Endpoint, at.Format(time.RFC3339)),
					EvidenceIDs: evidence, Source: "revocation_health", ObservedAt: at, Confidence: confidence,
				})
			}
		}
	}
	ev.text = fmt.Sprintf("trstctl records %s (serial %s) as %s. The relay observed %s for it.", cert.Subject, cert.Serial, state, mcpCount(observed, "CRL or OCSP endpoint"))
	if ok && observed == 0 {
		ev.text += " No relay has probed its revocation endpoints yet, so publication is unobserved."
	}
	return ev, nil
}

// ---- crypto_inventory ----------------------------------------------------------------

func (a *API) mcpCryptoInventory(r *http.Request, subject string) (mcpEvidence, error) {
	var inv CBOMInventoryResponse
	if err := a.mcpRead(r, "/api/v1/cbom/assets", &inv); err != nil {
		return mcpEvidence{}, err
	}
	ev := mcpEvidence{citations: []string{"GET /api/v1/cbom/assets"}}
	items := make([]CBOMAsset, 0, len(inv.Items))
	for _, it := range inv.Items {
		if mcpMentions(subject, it.Algorithm, it.Location, it.Library, it.Kind, it.Protocol, it.Cipher) {
			items = append(items, it)
		}
	}
	rank := func(it CBOMAsset) int {
		n := 0
		if it.OutOfPolicy {
			n += 4
		}
		if it.QuantumVulnerable {
			n += 2
		}
		if it.Strength == "weak" {
			n++
		}
		return n
	}
	sort.SliceStable(items, func(i, j int) bool {
		if rank(items[i]) != rank(items[j]) {
			return rank(items[i]) > rank(items[j])
		}
		return items[i].Location+items[i].ID < items[j].Location+items[j].ID
	})
	quantum, weak, outOfPolicy := 0, 0, 0
	for _, it := range items {
		if it.QuantumVulnerable {
			quantum++
		}
		if it.Strength == "weak" {
			weak++
		}
		if it.OutOfPolicy {
			outOfPolicy++
		}
		detail := it.Algorithm
		if it.KeyBits > 0 {
			detail += fmt.Sprintf(" %d-bit", it.KeyBits)
		}
		flags := "strength " + it.Strength
		if it.QuantumVulnerable {
			flags += ", quantum-vulnerable"
		}
		if it.OutOfPolicy {
			flags += ", out of policy: " + strings.Join(it.Reasons, "; ")
		}
		ev.findings = append(ev.findings, mcpserver.Finding{
			FindingID: "crypto_asset:" + it.ID, Kind: "crypto_asset",
			Summary:     fmt.Sprintf("%s at %s: %s, %s; migration target %s (%s).", it.Kind, it.Location, detail, flags, firstNonEmpty(it.MigrationTarget, "none"), firstNonEmpty(it.MigrationStandard, "none")),
			EvidenceIDs: mcpEvidenceIDs("crypto_asset:"+it.ID, "fingerprint:"+strings.ToLower(it.CertificateFingerprint)),
			Source:      "cbom", ObservedAt: nil, Confidence: mcpserver.ConfidenceObserved,
			Attributes: mcpAttributes("kind", it.Kind, "location", it.Location, "algorithm", it.Algorithm, "key_bits", mcpNonZero(it.KeyBits),
				"strength", it.Strength, "quantum_vulnerable", strconv.FormatBool(it.QuantumVulnerable), "out_of_policy", strconv.FormatBool(it.OutOfPolicy),
				"library", it.Library, "migration_target", it.MigrationTarget, "migration_standard", it.MigrationStandard),
		})
	}
	ev.text = fmt.Sprintf("%s%s: %d quantum-vulnerable, %d weak, %d out of policy.", mcpCount(len(items), "crypto inventory asset"), mcpSubjectSuffix(subject), quantum, weak, outOfPolicy)
	return ev, nil
}

func mcpNonZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
