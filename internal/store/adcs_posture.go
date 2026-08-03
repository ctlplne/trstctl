// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// AD CS template posture read model (epic F1).
//
// An in-domain relay reads the directory; this is where what it found becomes
// something an operator can look at tomorrow, rather than only in the job report
// from the run that produced it.

// ADCSTemplatePosture is one template's observed posture.
type ADCSTemplatePosture struct {
	TenantID      string
	Domain        string
	Template      string
	DisplayName   string
	SchemaVersion int
	PublishedBy   []string
	// WorstSeverity is "" when the template has no findings, which is a real
	// and common state — it must not read as unknown.
	WorstSeverity string
	FindingCount  int
	// Findings is the analysis output verbatim, so the console can show what an
	// attacker could do and what removes it without the store needing to model
	// a vocabulary that grows.
	Findings json.RawMessage
	// ObservedBy and ObservedAt say which relay looked and when. An operator
	// reading a dangerous template needs to know whether this is yesterday's
	// answer.
	ObservedBy string
	ObservedAt time.Time
}

// ReplaceADCSTemplatePosture writes one relay observation of one domain.
//
// It replaces the domain's rows rather than merging them, because a template
// that has been DELETED from the directory must disappear from the console. A
// merge would leave a dangerous template on the page forever after someone
// removed it, which is the worst way for a posture surface to be wrong: it
// would punish the fix.
func (s *Store) ReplaceADCSTemplatePosture(ctx context.Context, tenantID, domain, observedBy string, rows []ADCSTemplatePosture, at time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM adcs_template_posture WHERE tenant_id = $1 AND domain = $2`,
			tenantID, domain); err != nil {
			return err
		}
		for _, row := range rows {
			findings := row.Findings
			if len(findings) == 0 {
				findings = json.RawMessage("[]")
			}
			published := row.PublishedBy
			if published == nil {
				published = []string{}
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO adcs_template_posture
				     (tenant_id, domain, template, display_name, schema_version,
				      published_by, worst_severity, finding_count, findings,
				      observed_by, observed_at)
				 VALUES ($1, $2, $3, $4, $5, $6::text[], $7, $8, $9::jsonb, $10, $11)`,
				tenantID, domain, row.Template, row.DisplayName, row.SchemaVersion,
				published, row.WorstSeverity, row.FindingCount, string(findings),
				observedBy, at.UTC()); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListADCSTemplatePosture returns a tenant's observed templates, most dangerous
// first — which is the order an operator wants and the order the index serves.
func (s *Store) ListADCSTemplatePosture(ctx context.Context, tenantID string, limit int) ([]ADCSTemplatePosture, error) {
	if limit <= 0 {
		limit = 200
	}
	var out []ADCSTemplatePosture
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			// Severity ranked deliberately rather than alphabetically: sorted as
			// text, "critical" would come before "high" by luck and "medium"
			// before both, which is the wrong order presented confidently.
			`SELECT tenant_id::text, domain, template, display_name, schema_version,
			        published_by, worst_severity, finding_count, findings,
			        observed_by, observed_at
			   FROM adcs_template_posture
			  WHERE tenant_id = $1
			  ORDER BY CASE worst_severity
			             WHEN 'critical' THEN 0
			             WHEN 'high'     THEN 1
			             WHEN 'medium'   THEN 2
			             ELSE 3
			           END, domain, template
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row ADCSTemplatePosture
			var findings []byte
			if err := rows.Scan(&row.TenantID, &row.Domain, &row.Template, &row.DisplayName,
				&row.SchemaVersion, &row.PublishedBy, &row.WorstSeverity, &row.FindingCount,
				&findings, &row.ObservedBy, &row.ObservedAt); err != nil {
				return err
			}
			row.Findings = json.RawMessage(findings)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}
