// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

// Evidence report templates (A252): lifecycle, access, rotation, incident
// response and qualification evidence. Each replays one window of the tenant's
// event log through a fixed set of event types, counts what happened by type,
// tallies closed outcome values, names up to 25 opaque subject IDs per
// section, reads the current state as counts, and says what it could not
// observe. Scheduled runs are signed and verify offline like every scheduled
// report. A report never carries an event body, a certificate, a secret, a
// token or a person's name.

const (
	lifecycleEvidenceReportType        = "lifecycle_evidence"
	accessEvidenceReportType           = "access_evidence"
	rotationEvidenceReportType         = "rotation_evidence"
	incidentResponseEvidenceReportType = "incident_response_evidence"
	qualificationEvidenceReportType    = "qualification_evidence"

	evidenceSubjectLimit      = 25
	evidenceDefaultWindow     = 7 * 24 * time.Hour
	evidenceMaxOnDemandWindow = 92 * 24 * time.Hour
)

type evidenceSectionSpec struct {
	name     string
	types    []string
	prefixes []string
}

type evidenceTemplate struct {
	kind       string
	title      string
	sections   []evidenceSectionSpec
	unobserved []string
}

var evidenceWindowNote = "The window covers events recorded from window_from up to window_through; work that began earlier shows only its later events."

var evidenceTemplates = map[string]evidenceTemplate{
	lifecycleEvidenceReportType: {
		kind: lifecycleEvidenceReportType, title: "Certificate lifecycle evidence",
		sections: []evidenceSectionSpec{
			{name: "issued", types: []string{"identity.issued", "issuance.request.issued"}},
			{name: "renewed", types: []string{"identity.renewed", "agent.cert.renewed"}},
			{name: "renewal problems", types: []string{"identity.renewal_failed", "identity.renewal_paused", "identity.renewal_resumed", "identity.renewal_recovered"}},
			{name: "deployed and verified", types: []string{"identity.deployed", "identity.undeployed", "endpoint.verification.observed"}},
			{name: "revoked", types: []string{"identity.revoked", "certificate.revoked", "certificate.revocation.batch.applied"}},
			{name: "retired or superseded", types: []string{"identity.retired", "certificate.superseded"}},
			{name: "recorded from outside trstctl", types: []string{"certificate.recorded"}},
			{name: "key compromise", types: []string{"certificate.subject_key.compromised"}},
		},
		unobserved: []string{
			"Certificates issued outside trstctl appear only after discovery or an import records them.",
			"A deployment counts as verified only where an endpoint verification observed the served certificate; any other delivery is a receipt.",
		},
	},
	accessEvidenceReportType: {
		kind: accessEvidenceReportType, title: "Access evidence",
		sections: []evidenceSectionSpec{
			{name: "members", types: []string{"tenant.member.upserted", "tenant.member.offboarded"}},
			{name: "roles", types: []string{"access.role.upserted", "access.role.deleted"}},
			{name: "API tokens", types: []string{"api_token.created", "api_token.revoked"}},
			{name: "access changes", types: []string{"access.change_request.created", "access.change_request.decided"}},
			{name: "agent access", prefixes: []string{"access.bundle."}},
			{name: "privileged sessions", prefixes: []string{"pam.session."}},
			{name: "provider access", types: []string{"tenant.provider_access.consented", "tenant.provider_access.policy_set"}},
		},
		unobserved: []string{
			"Sign-ins and credential use outside trstctl are not observed; API-token use is recorded per client network and hour, not per request.",
			"People appear only as counts and opaque IDs; the audit log names them.",
			"Identity-provider accounts that were never provisioned or never signed in are not seen.",
		},
	},
	rotationEvidenceReportType: {
		kind: rotationEvidenceReportType, title: "Rotation evidence",
		sections: []evidenceSectionSpec{
			{name: "certificates", types: []string{"identity.renewed", "identity.renewal_failed", "lifecycle.rotation.recorded"}},
			{name: "secrets", types: []string{"secret.rotated", "secret.rotation_schedule.ran", "secret.static_rotation.queued", "secret.static_rotation.advanced"}},
			{name: "keys", prefixes: []string{"tenant.key_domain.rotation_", "deployment.kek.rotation_"},
				types: []string{"ca.authority.rotated", "ca.ocsp_responder.rotated", "breakglass.ca.rotated", "workload.attester_trust_source.rotated", "mdm.scep_challenge.rotated"}},
			{name: "leases", types: []string{"dynsecret.lease.renewed"}},
		},
		unobserved: []string{
			"Adoption of a rotated secret is known only where its consumers acknowledged it or a readback confirmed it; a receipt-only destination shows its run status, not adoption.",
			"Rotations done directly at a provider, outside trstctl, are not seen.",
		},
	},
	incidentResponseEvidenceReportType: {
		kind: incidentResponseEvidenceReportType, title: "Incident response evidence",
		sections: []evidenceSectionSpec{
			{name: "incident executions", types: []string{"incident.execution.recorded"}},
			{name: "fleet reissuance", types: []string{"incident.fleet_reissuance.recorded"}},
			{name: "key compromise", types: []string{"certificate.subject_key.compromised", "identity.key_compromise_ca_effect_completed", "identity.key_compromise_effect_retried"}},
			{name: "CA revocation", types: []string{"ca.authority.revoked", "ca.certificate.revoked"}},
			{name: "decoys", prefixes: []string{"honeytoken."}},
			{name: "rogue certificates", prefixes: []string{"rogue."}},
			{name: "break-glass", prefixes: []string{"breakglass."}},
		},
		unobserved: []string{
			"Incidents handled outside trstctl are not seen.",
			"Containment on a target without readback is recorded as requested, not as confirmed.",
		},
	},
	qualificationEvidenceReportType: {
		kind: qualificationEvidenceReportType, title: "Qualification evidence",
		sections: []evidenceSectionSpec{
			{name: "rehearsals", types: []string{"rehearsal.run.started", "rehearsal.run.completed"}},
			{name: "restore drills", types: []string{"backup.restore_drill.recorded"}},
			{name: "endpoint recovery checks", prefixes: []string{"endpoint.recovery_check."}},
			{name: "revocation health", types: []string{"revocation.health.observed"}},
			{name: "CA ceremonies", prefixes: []string{"ca.ceremony."}},
			{name: "post-quantum pilots", prefixes: []string{"pqc."}},
			{name: "certificate transparency", prefixes: []string{"ct."}},
		},
		unobserved: []string{
			"Read-only qualification checks (protocol qualification previews) record nothing, so they are not counted.",
			"Only drills, rehearsals and checks this deployment ran are counted; evidence from other systems is not imported.",
		},
	},
}

// EvidenceReport is one evidence template rendered over one window.
type EvidenceReport struct {
	Format             string            `json:"format"`
	Kind               string            `json:"kind"`
	Title              string            `json:"title"`
	WindowFrom         time.Time         `json:"window_from"`
	WindowThrough      time.Time         `json:"window_through"`
	SourceHeadSequence uint64            `json:"source_head_sequence"`
	Scope              []string          `json:"scope"`
	Sections           []EvidenceSection `json:"sections"`
	CurrentState       map[string]int    `json:"current_state"`
	Unobserved         []string          `json:"unobserved"`
}

// EvidenceSection is what one section's event types recorded in the window.
type EvidenceSection struct {
	Name       string                    `json:"name"`
	Events     int                       `json:"events"`
	ByType     []scheduledAuditTypeCount `json:"by_type"`
	Outcomes   map[string]int            `json:"outcomes"`
	SubjectIDs []string                  `json:"subject_ids"`
	Truncated  bool                      `json:"truncated"`
}

func (s evidenceSectionSpec) matches(eventType string) bool {
	for _, t := range s.types {
		if t == eventType {
			return true
		}
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(eventType, p) {
			return true
		}
	}
	return false
}

func (t evidenceTemplate) scope() []string {
	var out []string
	for _, s := range t.sections {
		out = append(out, s.types...)
		for _, p := range s.prefixes {
			out = append(out, p+"*")
		}
	}
	sort.Strings(out)
	return out
}

// evidenceOutcomeKeys and evidenceSubjectKeys are the only payload fields a
// report reads. An outcome is kept only as a closed lowercase word and a
// subject only as a UUID, so free text and names never enter a report.
var (
	evidenceOutcomeKeys = []string{"status", "outcome", "verdict", "result"}
	evidenceSubjectKeys = []string{"id", "identity_id", "certificate_id", "run_id", "execution_id", "bundle_id", "schedule_id",
		"token_id", "session_id", "scenario_id", "target_id", "request_id"}
	evidenceOutcomeWord = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)
)

func evidenceFields(data []byte) (outcome, subject string) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return "", ""
	}
	str := func(key string) string {
		var v string
		if raw, ok := fields[key]; ok && json.Unmarshal(raw, &v) == nil {
			return v
		}
		return ""
	}
	for _, key := range evidenceOutcomeKeys {
		if v := str(key); evidenceOutcomeWord.MatchString(v) {
			outcome = v
			break
		}
	}
	for _, key := range evidenceSubjectKeys {
		if v := str(key); v != "" {
			if id, err := googleuuid.Parse(v); err == nil && id != googleuuid.Nil {
				subject = id.String()
				break
			}
		}
	}
	return outcome, subject
}

// buildEvidenceReport renders kind over [from, through].
func (a *API) buildEvidenceReport(ctx context.Context, tenantID, kind string, from, through time.Time) (EvidenceReport, error) {
	tmpl, ok := evidenceTemplates[kind]
	if !ok {
		return EvidenceReport{}, errStatus(http.StatusNotFound, "unknown evidence report "+kind)
	}
	if a.log == nil {
		return EvidenceReport{}, errors.New("evidence report: event log is not configured")
	}
	report := EvidenceReport{
		Format: "trstctl.report." + kind + ".v1", Kind: kind, Title: tmpl.title,
		WindowFrom: from.UTC(), WindowThrough: through.UTC(), Scope: tmpl.scope(),
		Unobserved: append([]string{evidenceWindowNote}, tmpl.unobserved...),
	}
	type tally struct {
		byType   map[string]int
		outcomes map[string]int
		subjects []string
		seen     map[string]bool
		more     bool
	}
	tallies := make([]tally, len(tmpl.sections))
	for i := range tallies {
		tallies[i] = tally{byType: map[string]int{}, outcomes: map[string]int{}, seen: map[string]bool{}}
	}
	err := a.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := a.log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		report.SourceHeadSequence = head
		if head == 0 {
			return nil
		}
		return a.log.ReplayThrough(readCtx, 1, head, func(e events.Event) error {
			if e.TenantID != tenantID || e.Time.Before(from) || e.Time.After(through) {
				return nil
			}
			for i, section := range tmpl.sections {
				if !section.matches(e.Type) {
					continue
				}
				t := &tallies[i]
				t.byType[e.Type]++
				outcome, subject := evidenceFields(e.Data)
				if outcome != "" {
					t.outcomes[outcome]++
				}
				if subject != "" && !t.seen[subject] {
					if len(t.subjects) < evidenceSubjectLimit {
						t.seen[subject] = true
						t.subjects = append(t.subjects, subject)
					} else {
						t.more = true
					}
				}
			}
			return nil
		})
	})
	if err != nil {
		return EvidenceReport{}, err
	}
	for i, section := range tmpl.sections {
		t := tallies[i]
		out := EvidenceSection{Name: section.name, Outcomes: t.outcomes, SubjectIDs: t.subjects, Truncated: t.more,
			ByType: []scheduledAuditTypeCount{}}
		if out.SubjectIDs == nil {
			out.SubjectIDs = []string{}
		}
		types := make([]string, 0, len(t.byType))
		for typ := range t.byType {
			types = append(types, typ)
		}
		sort.Strings(types)
		for _, typ := range types {
			out.ByType = append(out.ByType, scheduledAuditTypeCount{Type: typ, Count: t.byType[typ]})
			out.Events += t.byType[typ]
		}
		if out.Events == 0 {
			report.Unobserved = append(report.Unobserved, "No "+section.name+" events were recorded in the window.")
		}
		report.Sections = append(report.Sections, out)
	}
	state, err := a.store.EvidenceCurrentState(ctx, tenantID, kind, through)
	if err != nil {
		return EvidenceReport{}, err
	}
	report.CurrentState = state
	return report, nil
}

// getEvidenceReport renders one evidence template on demand, unsigned, for
// review before it is scheduled.
func (a *API) getEvidenceReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	through := time.Now().UTC()
	if raw := r.URL.Query().Get("through"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "through must be an RFC 3339 time"))
			return
		}
		through = t.UTC()
	}
	from := through.Add(-evidenceDefaultWindow)
	if raw := r.URL.Query().Get("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "from must be an RFC 3339 time"))
			return
		}
		from = t.UTC()
	}
	if !from.Before(through) || through.Sub(from) > evidenceMaxOnDemandWindow {
		a.writeError(w, errStatus(http.StatusBadRequest, "from must be before through, at most 92 days earlier"))
		return
	}
	report, err := a.buildEvidenceReport(r.Context(), tenantID, r.PathValue("kind"), from, through)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, report)
}

// scheduledEvidenceReport is one scheduled run's payload: the period that ends
// at the due edge.
func (a *API) scheduledEvidenceReport(ctx context.Context, tenantID, kind string, due time.Time, interval time.Duration) (json.RawMessage, error) {
	report, err := a.buildEvidenceReport(ctx, tenantID, kind, due.Add(-interval), due)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func evidenceReportSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	counts := &Schema{Type: "object", AdditionalProperties: integer()}
	byType := &Schema{Type: "object", Properties: map[string]*Schema{"type": str(), "count": integer()}, Required: []string{"type", "count"}}
	section := &Schema{Type: "object", Properties: map[string]*Schema{"name": str(), "events": integer(), "by_type": list(byType),
		"outcomes": counts, "subject_ids": list(str()), "truncated": {Type: "boolean"}},
		Required: []string{"name", "events", "by_type", "outcomes", "subject_ids", "truncated"}}
	return map[string]*Schema{
		"EvidenceReport": {Type: "object", Properties: map[string]*Schema{
			"format": str(), "kind": {Type: "string", Enum: []string{lifecycleEvidenceReportType, accessEvidenceReportType, rotationEvidenceReportType,
				incidentResponseEvidenceReportType, qualificationEvidenceReportType}},
			"title": str(), "window_from": timestamp(), "window_through": timestamp(), "source_head_sequence": integer(),
			"scope": list(str()), "sections": list(section), "current_state": counts, "unobserved": list(str()),
		}, Required: []string{"format", "kind", "title", "window_from", "window_through", "source_head_sequence", "scope", "sections", "current_state", "unobserved"}},
	}
}
