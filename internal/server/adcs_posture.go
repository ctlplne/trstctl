// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Recording an in-domain relay's AD CS observation (epic F1).
//
// The relay reads the directory and reports; this turns that report into the
// read model the Posture console shows. It runs on the report path rather than
// as a projection over the event log because what an operator needs here is the
// CURRENT state of a domain's templates — "what does this directory look like
// now" — and replaying every observation ever made to answer that would be
// slower and no more true.

// recordADCSPosture stores one relay observation.
//
// It replaces the domain's rows rather than merging them, because a template
// DELETED from the directory has to disappear from the console. A merge would
// leave a dangerous template on the page forever after someone removed it —
// the worst way for a posture surface to be wrong, because it punishes the fix.
func (s *Server) recordADCSPosture(ctx context.Context, tenantID, agentName, _, reportJSON string) {
	if s.store == nil {
		return
	}
	var report struct {
		Inventory struct {
			Templates []adcs.Template `json:"templates"`
		} `json:"inventory"`
		Findings          []adcs.Finding `json:"findings"`
		DirectoryVerified bool           `json:"directory_verified"`
	}
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		// A relay that reported something this cannot read is a version skew,
		// not an empty domain. Writing an empty posture would tell an operator
		// their template list is clean, which is the failure this whole epic
		// exists to prevent.
		return
	}
	if len(report.Inventory.Templates) == 0 {
		// Same reasoning: a domain with no templates at all does not happen in
		// practice, so an empty inventory is far more likely a failed read that
		// reported success. Refusing to write it keeps a real posture on screen
		// rather than replacing it with a comforting blank.
		return
	}

	// The domain is derived from the templates' own publishing CAs when it can
	// be, so one forest's several domains stay separate on the page. Templates
	// named "User" in two domains are not the same template, and merging them
	// would hide a dangerous one behind a safe namesake.
	domain := adcsDomainFor(report.Inventory.Templates)

	byTemplate := map[string][]adcs.Finding{}
	for _, finding := range report.Findings {
		byTemplate[finding.Template] = append(byTemplate[finding.Template], finding)
	}

	// F2: what changed since the last sweep, in security terms. This runs BEFORE
	// the replace, because after it the previous state is gone — and the whole
	// value of a template inventory over time is noticing the moment somebody
	// turned on supplies-subject, not the fact that it is on now.
	s.recordADCSDrift(ctx, tenantID, domain, agentName, report.Inventory.Templates)

	rows := make([]store.ADCSTemplatePosture, 0, len(report.Inventory.Templates))
	for _, tpl := range report.Inventory.Templates {
		findings := byTemplate[tpl.Name]
		encoded, err := json.Marshal(findings)
		if err != nil {
			continue
		}
		// The template is stored as observed so the NEXT sweep can diff against
		// what the directory really said (F2), not against a reconstruction
		// that would report every flag as newly set.
		observed, err := json.Marshal(tpl)
		if err != nil {
			continue
		}
		rows = append(rows, store.ADCSTemplatePosture{
			Domain:           domain,
			Template:         tpl.Name,
			DisplayName:      tpl.DisplayName,
			SchemaVersion:    tpl.SchemaVersion,
			PublishedBy:      tpl.PublishedBy,
			WorstSeverity:    worstADCSSeverity(findings),
			FindingCount:     len(findings),
			Findings:         encoded,
			ObservedTemplate: observed,
		})
	}
	_ = s.store.ReplaceADCSTemplatePosture(ctx, tenantID, domain, agentName, rows, time.Now().UTC())
}

// adcsDomainFor labels the observation.
//
// A forest holds several domains and their template sets are separate. The
// publishing CA's name is the best label available from what the directory
// returned; when nothing published anything, the observation is labelled
// explicitly as unattributed rather than being silently merged into another
// domain's row set.
func adcsDomainFor(templates []adcs.Template) string {
	for _, tpl := range templates {
		for _, ca := range tpl.PublishedBy {
			if ca = strings.TrimSpace(ca); ca != "" {
				return ca
			}
		}
	}
	return "unattributed"
}

// worstADCSSeverity reduces a template's findings to the one word the console
// sorts on. Empty means no findings, which is a real state and must not read as
// unknown.
func worstADCSSeverity(findings []adcs.Finding) string {
	worst := ""
	rank := map[adcs.Severity]int{adcs.SeverityMedium: 1, adcs.SeverityHigh: 2, adcs.SeverityCritical: 3}
	best := 0
	for _, f := range findings {
		if r := rank[f.Severity]; r > best {
			best, worst = r, string(f.Severity)
		}
	}
	return worst
}

// adcsPostureView serves the observed template posture to the API.
func (s *Server) adcsPostureView(ctx context.Context, tenantID string) ([]api.ADCSTemplate, error) {
	if s.store == nil {
		return nil, nil
	}
	rows, err := s.store.ListADCSTemplatePosture(ctx, tenantID, 500)
	if err != nil {
		return nil, err
	}
	out := make([]api.ADCSTemplate, 0, len(rows))
	for _, row := range rows {
		var findings []api.ADCSTemplateFinding
		if len(row.Findings) > 0 {
			// A row whose findings do not decode still shows the template: the
			// template's existence and its attributes are facts worth keeping
			// on the page even when the verdict cannot be read.
			_ = json.Unmarshal(row.Findings, &findings)
		}
		if findings == nil {
			findings = []api.ADCSTemplateFinding{}
		}
		published := row.PublishedBy
		if published == nil {
			published = []string{}
		}
		out = append(out, api.ADCSTemplate{
			Domain: row.Domain, Template: row.Template, DisplayName: row.DisplayName,
			SchemaVersion: row.SchemaVersion, PublishedBy: published,
			WorstSeverity: row.WorstSeverity, Findings: findings,
			ObservedBy: row.ObservedBy, ObservedAt: row.ObservedAt,
		})
	}
	return out, nil
}

// recordADCSDrift compares this sweep against the stored one and records the
// semantic difference (epic F2).
//
// Only a change for the WORSE produces an alerting event. An operator who has
// just hardened a template does not need waking for it, and a tool that alerts
// on improvement teaches people to mute it — after which it will not reach them
// on the day it matters. Better and neutral changes are still recorded, because
// an incident timeline needs them.
func (s *Server) recordADCSDrift(ctx context.Context, tenantID, domain, agentName string, current []adcs.Template) {
	if s.store == nil || s.log == nil {
		return
	}
	previousRows, err := s.store.ListADCSTemplatePosture(ctx, tenantID, 1000)
	if err != nil {
		return
	}
	previous := make([]adcs.Template, 0, len(previousRows))
	for _, row := range previousRows {
		if row.Domain != domain {
			continue
		}
		// The template as the directory reported it last time. A row written
		// before 0105 has none, and is SKIPPED rather than reconstructed:
		// diffing against a template whose flags all read false would report it
		// as having just turned dangerous, which is precisely the false alarm
		// this epic must not produce. One quiet sweep to re-baseline is the
		// right cost.
		if len(row.ObservedTemplate) == 0 || string(row.ObservedTemplate) == "{}" {
			continue
		}
		var tpl adcs.Template
		if err := json.Unmarshal(row.ObservedTemplate, &tpl); err != nil {
			continue
		}
		previous = append(previous, tpl)
	}
	drift := adcs.DiffTemplates(previous, current)
	if len(drift.Changes) == 0 && len(drift.Lifecycle) == 0 {
		return
	}
	payload := map[string]any{
		"domain": domain, "agent": agentName,
		"changes": drift.Changes, "lifecycle": drift.Lifecycle,
		"worsened": drift.Worsened(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	eventType := "adcs.template.drift"
	if drift.Worsened() {
		// A distinct type so the notify matrix can route the alerting case
		// without having to reason about the payload.
		eventType = "adcs.template.drift.worsened"
	}
	_, _ = s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: encoded})
}
