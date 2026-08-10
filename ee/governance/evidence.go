// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

const DefaultEvidenceWindow = 90 * 24 * time.Hour

// EvidenceWindow is the inclusive period evaluated by every control in a pack.
// A gap therefore means "not evidenced in this exact window", never an unbounded
// claim about an unknown amount of history.
type EvidenceWindow struct {
	From    time.Time `json:"from"`
	Through time.Time `json:"through"`
}

// EvidenceReference is a resolvable tenant fact included inside the signed
// manifest. Event references carry the immutable event ID, type, sequence, and
// chain hash. Object snapshots carry the exact graph object ID and the time the
// tenant-scoped projection was read.
type EvidenceReference struct {
	Ref        string    `json:"ref"`
	Source     string    `json:"source"`
	Type       string    `json:"type"`
	ObservedAt time.Time `json:"observed_at"`
	Sequence   uint64    `json:"sequence,omitempty"`
	Digest     string    `json:"digest,omitempty"`
}

type evidenceIndex struct {
	tenantID string
	window   EvidenceWindow
	byType   map[string][]audit.Record
	graph    *graph.Graph
	runtime  map[string][]EvidenceReference
}

func newEvidenceIndex(tenantID string, records []audit.Record, g *graph.Graph, window EvidenceWindow) *evidenceIndex {
	idx := &evidenceIndex{
		tenantID: tenantID,
		window:   window,
		byType:   map[string][]audit.Record{},
		graph:    g,
		runtime:  map[string][]EvidenceReference{},
	}
	for _, rec := range records {
		if rec.TenantID != tenantID || rec.Time.Before(window.From) || rec.Time.After(window.Through) {
			continue
		}
		idx.byType[rec.Type] = append(idx.byType[rec.Type], rec)
	}
	return idx
}

func (i *evidenceIndex) addRuntime(label, typ string) {
	i.runtime[label] = []EvidenceReference{{
		Ref: "runtime:" + label, Source: "runtime", Type: typ, ObservedAt: i.window.Through,
	}}
}

func (i *evidenceIndex) eventRefs(types ...string) []EvidenceReference {
	var latest audit.Record
	found := false
	for _, typ := range types {
		for _, rec := range i.byType[typ] {
			if !found || rec.Time.After(latest.Time) || (rec.Time.Equal(latest.Time) && rec.Sequence > latest.Sequence) {
				latest = rec
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return []EvidenceReference{eventReference(latest)}
}

func uintString(v uint64) string {
	if v == 0 {
		return "unknown"
	}
	const digits = "0123456789"
	var buf [20]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = digits[v%10]
		v /= 10
	}
	return string(buf[pos:])
}

func (i *evidenceIndex) graphRefs(kind graph.NodeKind) []EvidenceReference {
	if i.graph == nil {
		return nil
	}
	var refs []EvidenceReference
	for _, node := range i.graph.Nodes() {
		if node.Kind != kind {
			continue
		}
		refs = append(refs, EvidenceReference{
			Ref: "object:" + node.ID, Source: "tenant_graph_snapshot", Type: string(node.Kind), ObservedAt: i.window.Through,
		})
	}
	return refs
}

func (i *evidenceIndex) ownedCredentialRefs() []EvidenceReference {
	if i.graph == nil {
		return nil
	}
	credentials := map[string]graph.Node{}
	for _, node := range i.graph.Nodes() {
		if node.Kind == graph.KindCredential {
			credentials[node.ID] = node
		}
	}
	if len(credentials) == 0 {
		return nil
	}
	owned := map[string]bool{}
	owners := map[string]bool{}
	for _, edge := range i.graph.Edges() {
		if edge.Type == graph.EdgeOwns {
			owned[edge.To] = true
			owners[edge.From] = true
		}
	}
	for id := range credentials {
		if !owned[id] {
			return nil
		}
	}
	refs := i.graphRefs(graph.KindCredential)
	for id := range owners {
		refs = append(refs, EvidenceReference{
			Ref: "object:" + id, Source: "tenant_graph_snapshot", Type: string(graph.KindWorkload), ObservedAt: i.window.Through,
		})
	}
	return dedupeEvidenceRefs(refs)
}

func (i *evidenceIndex) completedAccessReviewRefs() []EvidenceReference {
	type reviewStart struct {
		ID    string `json:"id"`
		Items []struct {
			ItemID string `json:"item_id"`
		} `json:"items"`
	}
	type reviewDecision struct {
		CampaignID string `json:"campaign_id"`
		ItemID     string `json:"item_id"`
		Decision   string `json:"decision"`
	}
	decisions := map[string]map[string]audit.Record{}
	for _, rec := range i.byType["nhi.access_review.item.decided"] {
		var payload reviewDecision
		if json.Unmarshal(rec.Data, &payload) != nil || payload.CampaignID == "" || payload.ItemID == "" || payload.Decision == "" {
			continue
		}
		if decisions[payload.CampaignID] == nil {
			decisions[payload.CampaignID] = map[string]audit.Record{}
		}
		decisions[payload.CampaignID][payload.ItemID] = rec
	}
	for _, started := range i.byType["nhi.access_review.campaign.started"] {
		var payload reviewStart
		if json.Unmarshal(started.Data, &payload) != nil || payload.ID == "" || len(payload.Items) == 0 {
			continue
		}
		refs := []EvidenceReference{eventReference(started)}
		complete := true
		for _, item := range payload.Items {
			decided, ok := decisions[payload.ID][item.ItemID]
			if item.ItemID == "" || !ok {
				complete = false
				break
			}
			refs = append(refs, eventReference(decided))
		}
		if complete {
			return dedupeEvidenceRefs(refs)
		}
	}
	return nil
}

func (i *evidenceIndex) approvedAccessChangeRefs() []EvidenceReference {
	type request struct {
		ID                string   `json:"id"`
		RequesterSubject  string   `json:"requester_subject"`
		ChangeRef         string   `json:"change_ref"`
		EvidenceRefs      []string `json:"evidence_refs"`
		RequiredApprovals int      `json:"required_approvals"`
	}
	type decision struct {
		RequestID            string   `json:"request_id"`
		Decision             string   `json:"decision"`
		ApproverSubject      string   `json:"approver_subject"`
		DecisionEvidenceRefs []string `json:"decision_evidence_refs"`
	}
	decisions := map[string]map[string]audit.Record{}
	for _, rec := range i.byType["access.change_request.decided"] {
		var payload decision
		if json.Unmarshal(rec.Data, &payload) != nil || payload.RequestID == "" || payload.Decision != "approved" || payload.ApproverSubject == "" || len(payload.DecisionEvidenceRefs) == 0 {
			continue
		}
		if decisions[payload.RequestID] == nil {
			decisions[payload.RequestID] = map[string]audit.Record{}
		}
		decisions[payload.RequestID][payload.ApproverSubject] = rec
	}
	for _, created := range i.byType["access.change_request.created"] {
		var payload request
		if json.Unmarshal(created.Data, &payload) != nil || payload.ID == "" || payload.ChangeRef == "" || len(payload.EvidenceRefs) == 0 {
			continue
		}
		required := payload.RequiredApprovals
		if required < 1 {
			required = 2
		}
		refs := []EvidenceReference{eventReference(created)}
		count := 0
		for approver, rec := range decisions[payload.ID] {
			if approver == payload.RequesterSubject {
				continue
			}
			count++
			refs = append(refs, eventReference(rec))
		}
		if count >= required {
			return dedupeEvidenceRefs(refs)
		}
	}
	return nil
}

func (i *evidenceIndex) activePolicyRefs() []EvidenceReference {
	type authored struct {
		ID           string   `json:"id"`
		ModuleSHA256 string   `json:"module_sha256"`
		EvidenceRefs []string `json:"evidence_refs"`
		ChangeRef    string   `json:"change_ref"`
	}
	type activated struct {
		ID           string   `json:"id"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	type rolledBack struct {
		ID           string   `json:"id"`
		RollbackToID string   `json:"rollback_to_id"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	authoredByID := map[string]audit.Record{}
	validAuthored := map[string]bool{}
	activeID := ""
	var activeEvent audit.Record
	for _, rec := range orderedRecords(i.byType, "policy.version.authored", "policy.version.activated", "policy.version.rolled_back") {
		switch rec.Type {
		case "policy.version.authored":
			var payload authored
			if json.Unmarshal(rec.Data, &payload) == nil && payload.ID != "" && payload.ModuleSHA256 != "" && payload.ChangeRef != "" && len(payload.EvidenceRefs) > 0 {
				authoredByID[payload.ID] = rec
				validAuthored[payload.ID] = true
			}
		case "policy.version.activated":
			var payload activated
			if json.Unmarshal(rec.Data, &payload) == nil && validAuthored[payload.ID] && len(payload.EvidenceRefs) > 0 {
				activeID = payload.ID
				activeEvent = rec
			}
		case "policy.version.rolled_back":
			var payload rolledBack
			if json.Unmarshal(rec.Data, &payload) == nil && payload.ID == activeID {
				activeID = ""
				activeEvent = audit.Record{}
			}
		}
	}
	if activeID == "" {
		return nil
	}
	return []EvidenceReference{eventReference(authoredByID[activeID]), eventReference(activeEvent)}
}

func (i *evidenceIndex) tenantCustodyRefs(requireValidationRefs bool) []EvidenceReference {
	type custody struct {
		ProtectionMode         string   `json:"protection_mode"`
		State                  string   `json:"state"`
		WrapperKind            string   `json:"wrapper_kind"`
		WrapperID              string   `json:"wrapper_id"`
		TransitionEvidenceRefs []string `json:"transition_evidence_refs"`
	}
	var latest audit.Record
	var payload custody
	for _, rec := range orderedRecords(i.byType,
		"tenant.key_domain.migration_started", "tenant.key_domain.migration_progressed", "tenant.key_domain.migration_completed",
		"tenant.key_domain.migration_failed", "tenant.key_domain.seal_requested", "tenant.key_domain.seal_failed",
		"tenant.key_domain.sealed", "tenant.key_domain.unseal_requested", "tenant.key_domain.unsealed") {
		var candidate custody
		if json.Unmarshal(rec.Data, &candidate) == nil {
			latest = rec
			payload = candidate
		}
	}
	if latest.ID == "" || payload.ProtectionMode != "tenant_domain" || payload.WrapperKind == "" || payload.WrapperID == "" {
		return nil
	}
	if payload.State != "unsealed" && payload.State != "sealed" {
		return nil
	}
	if requireValidationRefs && len(payload.TransitionEvidenceRefs) == 0 {
		return nil
	}
	return []EvidenceReference{eventReference(latest)}
}

func (i *evidenceIndex) fipsApprovedAssetRefs() []EvidenceReference {
	refs := i.graphRefs(graph.KindCryptoAsset)
	if len(refs) == 0 || i.graph == nil {
		return nil
	}
	for _, node := range i.graph.Nodes() {
		if node.Kind != graph.KindCryptoAsset {
			continue
		}
		if !compliance.FIPSApprovedUnderRegulatedProfile(crypto.Algorithm(node.Attrs["algorithm"])) {
			return nil
		}
	}
	return refs
}

func orderedRecords(byType map[string][]audit.Record, types ...string) []audit.Record {
	var out []audit.Record
	for _, typ := range types {
		out = append(out, byType[typ]...)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].StreamSequence != out[b].StreamSequence {
			return out[a].StreamSequence < out[b].StreamSequence
		}
		if out[a].Sequence != out[b].Sequence {
			return out[a].Sequence < out[b].Sequence
		}
		return out[a].Time.Before(out[b].Time)
	})
	return out
}

func eventReference(rec audit.Record) EvidenceReference {
	ref := "event:" + rec.ID
	if rec.ID == "" {
		ref = "event:" + rec.Type + ":sequence:" + uintString(rec.Sequence)
	}
	return EvidenceReference{
		Ref: ref, Source: "audit_event", Type: rec.Type, ObservedAt: rec.Time,
		Sequence: rec.Sequence, Digest: rec.Hash,
	}
}

func dedupeEvidenceRefs(in []EvidenceReference) []EvidenceReference {
	seen := map[string]bool{}
	out := make([]EvidenceReference, 0, len(in))
	for _, ref := range in {
		key := ref.Source + "|" + ref.Ref
		if ref.Ref == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if !out[a].ObservedAt.Equal(out[b].ObservedAt) {
			return out[a].ObservedAt.Before(out[b].ObservedAt)
		}
		return out[a].Ref < out[b].Ref
	})
	return out
}

type controlRequirement struct {
	label string
	refs  func(*evidenceIndex) []EvidenceReference
}

func eventRequirement(label string, types ...string) controlRequirement {
	return controlRequirement{label: label, refs: func(i *evidenceIndex) []EvidenceReference { return i.eventRefs(types...) }}
}

func graphRequirement(label string, kind graph.NodeKind) controlRequirement {
	return controlRequirement{label: label, refs: func(i *evidenceIndex) []EvidenceReference { return i.graphRefs(kind) }}
}

func customRequirement(label string, fn func(*evidenceIndex) []EvidenceReference) controlRequirement {
	return controlRequirement{label: label, refs: fn}
}

func evaluatedControl(id, title string, idx *evidenceIndex, requirements ...controlRequirement) Control {
	control := Control{ID: id, Title: title, Status: "evidenced", Window: idx.window}
	for _, requirement := range requirements {
		refs := requirement.refs(idx)
		if len(refs) == 0 {
			control.Status = "gap"
			control.Missing = append(control.Missing, requirement.label)
			continue
		}
		control.Evidence = append(control.Evidence, requirement.label)
		control.EvidenceRefs = append(control.EvidenceRefs, refs...)
	}
	control.EvidenceRefs = dedupeEvidenceRefs(control.EvidenceRefs)
	return control
}

func residualControl(id, title string, idx *evidenceIndex, missing ...string) Control {
	return Control{ID: id, Title: title, Status: "gap", Missing: append([]string(nil), missing...), Window: idx.window}
}

func controlsFor(fw Framework, p Posture, idx *evidenceIndex) []Control {
	cryptoInventory := graphRequirement("current tenant CBOM cryptographic inventory", graph.KindCryptoAsset)
	credentialInventory := graphRequirement("current tenant NHI credential inventory", graph.KindCredential)
	ownedCredentials := customRequirement("complete credential ownership attribution", (*evidenceIndex).ownedCredentialRefs)
	accessReview := customRequirement("completed NHI access-review campaign and item decisions", (*evidenceIndex).completedAccessReviewRefs)
	approvedChange := customRequirement("approved access-change request with request and decision evidence", (*evidenceIndex).approvedAccessChangeRefs)
	activePolicy := customRequirement("active policy version with authored and activation evidence", (*evidenceIndex).activePolicyRefs)
	custody := customRequirement("tenant key-domain custody transition and wrapper posture", func(i *evidenceIndex) []EvidenceReference { return i.tenantCustodyRefs(false) })
	custodyValidation := customRequirement("tenant key-domain transition with deployment validation references", func(i *evidenceIndex) []EvidenceReference { return i.tenantCustodyRefs(true) })
	credentialAudit := eventRequirement("credential lifecycle audit events", "certificate.recorded", "certificate.revoked", "certificate.superseded", "identity.issued", "identity.renewed", "identity.revoked")
	policyDecision := eventRequirement("policy decision events", "policy.decision")
	monitoring := eventRequirement("security monitoring or incident events", "discovery.finding.recorded", "incident.execution.recorded", "incident.fleet_reissuance.recorded")
	caIssuance := eventRequirement("CA issuance events", "ca.certificate.issued", "ca.endentity.issued", "certificate.recorded")
	caRevocation := eventRequirement("CA revocation events", "ca.certificate.revoked", "certificate.revoked", "ca.crl.published")
	profileDecision := eventRequirement("certificate profile version or decision events", "profile.created", "profile.updated", "issuance.profile_evaluated")

	controls := []Control{
		evaluatedControl(string(fw)+"-crypto-inventory", "Cryptographic inventory maintained", idx, cryptoInventory),
		evaluatedControl(string(fw)+"-audit-trail", "Tamper-evident audit trail of credential operations", idx, credentialAudit),
		evaluatedControl(string(fw)+"-key-management", "Keys managed behind a hardened tenant custody boundary", idx, cryptoInventory, custody),
	}

	switch fw {
	case CNSA2:
		controls = append(controls, evaluatedControl("cnsa-2.0-pqc-adoption", "Post-quantum algorithms in use without a known quantum-vulnerable asset", idx,
			customRequirement("post-quantum-only tenant CBOM", func(i *evidenceIndex) []EvidenceReference {
				if p.PostQuantum == 0 || p.QuantumVulnerable != 0 {
					return nil
				}
				return i.graphRefs(graph.KindCryptoAsset)
			})))
	case NIST80053:
		controls = append(controls,
			evaluatedControl("nist-800-53-au-evidence", "Audit-event generation, review, and protection evidence is exportable", idx, credentialAudit, monitoring),
			evaluatedControl("nist-800-53-ac-ia-evidence", "NHI access and authenticator lifecycle evidence is mapped", idx, credentialInventory, ownedCredentials, accessReview),
			residualControl("nist-800-53-operator-tailoring-residual", "Control tailoring, system boundary, and assessment evidence remain operator responsibilities", idx, "operator attestation", "system security plan", "assessment package"),
		)
	case NISTCSF20:
		controls = append(controls,
			evaluatedControl("nist-csf-2.0-identify-protect-detect", "Identify, Protect, and Detect functions have NHI evidence mappings", idx, credentialInventory, ownedCredentials, activePolicy, monitoring),
			residualControl("nist-csf-2.0-govern-operator-residual", "Govern and organizational risk strategy remain operator program responsibilities", idx, "operator attestation", "risk management program"),
		)
	case SOC2:
		controls = append(controls,
			evaluatedControl("soc2-cc6-access-control", "Logical access controls for NHI credentials are evidenced", idx, credentialInventory, ownedCredentials, accessReview),
			evaluatedControl("soc2-cc7-monitoring-audit-evidence", "Security-event monitoring and investigation evidence is signed and exportable", idx, policyDecision, credentialAudit, monitoring),
			evaluatedControl("soc2-cc8-change-management-evidence", "Credential and policy change-management events are attributable", idx, activePolicy, approvedChange, credentialAudit),
			residualControl("soc2-attestation-residual", "Trust-services scope, management assertion, and independent CPA examination remain operator responsibilities", idx, "operator attestation", "trust-services category scope", "management assertion", "independent CPA SOC 2 examination report"),
		)
	case FedRAMP:
		controls = append(controls,
			evaluatedControl("fedramp-rev5-au-ac-ia-evidence", "FedRAMP Rev. 5 AU/AC/IA evidence is mapped from tenant controls", idx, credentialAudit, ownedCredentials, accessReview, activePolicy),
			residualControl("fedramp-rev5-authorization-residual", "ATO package, boundary tailoring, and assessor artifacts remain operator responsibilities", idx, "system security plan", "security assessment report", "plan of action and milestones"),
		)
	case CMMC20:
		controls = append(controls,
			evaluatedControl("cmmc-2.0-ac-ia-au-evidence", "CMMC access control, identification, authenticator, and audit evidence is mapped", idx, ownedCredentials, accessReview, approvedChange, credentialAudit),
			residualControl("cmmc-2.0-cui-scope-residual", "CUI scope, assessment level, and assessor package remain operator responsibilities", idx, "operator attestation", "CMMC assessment package"),
		)
	case FIPS140:
		controls = append(controls,
			evaluatedControl("fips-140-module-post", "Active FIPS module and fail-closed power-on self-test are evidenced", idx, customRequirement("active runtime FIPS POST", func(i *evidenceIndex) []EvidenceReference { return i.runtime["fips-post"] })),
			residualControl("fips-140-crypto-boundary", "Audited crypto-boundary artifact provenance is required for this deployment", idx, "signed build artifact and architecture-linter provenance"),
			evaluatedControl("fips-140-approved-algorithm-profile", "Approved-mode algorithms in the tenant inventory match the regulated deployment profile", idx,
				customRequirement("active runtime FIPS POST", func(i *evidenceIndex) []EvidenceReference { return i.runtime["fips-post"] }),
				customRequirement("tenant CBOM contains only approved-mode algorithms", (*evidenceIndex).fipsApprovedAssetRefs)),
			evaluatedControl("fips-140-non-fips-pqc-fence", "PQC, hybrid, and Ed25519 paths are absent from approved-mode tenant inventory", idx,
				customRequirement("active runtime FIPS POST", func(i *evidenceIndex) []EvidenceReference { return i.runtime["fips-post"] }),
				customRequirement("tenant CBOM contains only approved-mode algorithms", (*evidenceIndex).fipsApprovedAssetRefs)),
			evaluatedControl("fips-140-hsm-kms-validation-records", "External key-custody boundaries name deployment validation records", idx, custodyValidation),
			residualControl("fips-140-cmvp-certificate-residual", "NIST CMVP validation certificate for the deployed module remains an external artifact", idx, "operator attestation", "NIST CMVP certificate", "validated module configuration"),
		)
	case CommonCriteria:
		controls = append(controls,
			residualControl("common-criteria-security-target-evidence", "Security-target evidence map for the deployed TOE is required", idx, "tenant-specific security target", "evaluated TOE boundary"),
			evaluatedControl("common-criteria-configuration-management-evidence", "Configuration and lifecycle changes are attributable and signed", idx, activePolicy, approvedChange, credentialAudit),
			residualControl("common-criteria-evaluation-residual", "External lab evaluation and certificate remain operator responsibilities", idx, "external evaluation lab report", "Common Criteria certificate", "evaluated configuration guide"),
		)
	case CABFBR:
		controls = append(controls,
			evaluatedControl("cabf-br-profile-lint", "TLS server-certificate profiles have tenant execution evidence", idx, profileDecision, caIssuance),
			evaluatedControl("cabf-br-ca-audit-trail", "CA issuance, profile decision, and revocation evidence is attributable and signed", idx, caIssuance, profileDecision, caRevocation),
			evaluatedControl("cabf-br-key-protection", "CA private-key custody has tenant transition and ceremony evidence", idx, custody, eventRequirement("CA custody ceremony or authority transition", "ca.ceremony.approved", "ca.authority.imported", "ca.authority.rotated", "ca.authority.rekeyed")),
			residualControl("cabf-br-public-trust-residual", "Public-trust policy operation, CP/CPS publication, and independent audit remain operator responsibilities", idx, "operator attestation", "external practitioner report", "CA/Browser Forum policy program"),
		)
	case WebTrust:
		controls = append(controls,
			evaluatedControl("webtrust-ca-lifecycle", "CA certificate lifecycle operations are attributable and audit-trailed", idx, caIssuance, caRevocation),
			evaluatedControl("webtrust-ca-key-protection", "CA private-key custody has tenant transition and ceremony evidence", idx, custody, eventRequirement("CA custody ceremony or authority transition", "ca.ceremony.approved", "ca.authority.imported", "ca.authority.rotated", "ca.authority.rekeyed")),
			residualControl("webtrust-cps-and-independent-audit", "CP/CPS publication and independent WebTrust practitioner opinion remain operator responsibilities", idx, "operator attestation", "external practitioner report"),
		)
	case ETSI:
		controls = append(controls,
			evaluatedControl("etsi-en-319-411-ca-operations", "CA operations evidence supports ETSI EN 319 411 control review", idx, caIssuance, profileDecision, caRevocation),
			evaluatedControl("etsi-en-319-411-key-management", "Key management posture is evidenced by tenant custody and cryptographic inventory", idx, cryptoInventory, custody),
			residualControl("etsi-conformity-assessment-residual", "Qualified trust-service status and external conformity assessment remain operator responsibilities", idx, "operator attestation", "external conformity assessment"),
		)
	case EIDAS:
		controls = append(controls,
			evaluatedControl("eidas-trust-service-security-evidence", "Trust-service security and lifecycle evidence is mapped from tenant facts", idx, caIssuance, caRevocation, ownedCredentials, accessReview),
			residualControl("eidas-qualified-status-residual", "Qualified trust-service status and conformity assessment remain operator responsibilities", idx, "supervisory body evidence", "qualified status attestation", "external conformity assessment"),
		)
	case NIS2:
		controls = append(controls,
			evaluatedControl("nis2-article-21-risk-measures", "Cybersecurity risk-management evidence for NHI assets is mapped", idx, credentialInventory, ownedCredentials, activePolicy, monitoring),
			residualControl("nis2-governance-reporting-residual", "Management-body accountability, incident notification, and national transposition duties remain operator responsibilities", idx, "operator attestation", "incident notification process", "national transposition evidence"),
		)
	}
	return controls
}

func productEvidencesFor(controls []Control) []string {
	seen := map[string]bool{}
	var out []string
	for _, control := range controls {
		if control.Status != "evidenced" {
			continue
		}
		for _, ref := range control.EvidenceRefs {
			if seen[ref.Ref] {
				continue
			}
			seen[ref.Ref] = true
			out = append(out, ref.Ref)
		}
	}
	sort.Strings(out)
	return out
}

func validEvidenceWindow(window EvidenceWindow) bool {
	return !window.From.IsZero() && !window.Through.IsZero() && !window.Through.Before(window.From)
}

func normalizedTenantID(tenantID string) string { return strings.TrimSpace(tenantID) }
