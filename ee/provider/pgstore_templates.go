// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var _ TemplateStore = (*PGStore)(nil)

const templateSelect = `SELECT template_id, version, name, baseline, digest, recorded_by, recorded_at
	FROM provider_tenant_templates WHERE tenant_id = '` + providerAuthorityTenant + `'`

const bindingSelect = `SELECT tenant_id::text, template_id, version, digest, complete, results, applied_by, applied_at
	FROM provider_tenant_template_bindings`

// TenantTemplateVersions lists one template's versions, oldest first.
func (p *PGStore) TenantTemplateVersions(ctx context.Context, templateID string) ([]TenantTemplate, error) {
	rows, err := p.store.SystemPool().Query(ctx, templateSelect+` AND template_id = $1 ORDER BY version`, templateID)
	if err != nil {
		return nil, err
	}
	return scanTemplates(rows)
}

// TenantTemplates lists the latest version of every template.
func (p *PGStore) TenantTemplates(ctx context.Context) ([]TenantTemplate, error) {
	rows, err := p.store.SystemPool().Query(ctx, `SELECT DISTINCT ON (template_id) template_id, version, name, baseline, digest, recorded_by, recorded_at
		FROM provider_tenant_templates WHERE tenant_id = '`+providerAuthorityTenant+`'
		ORDER BY template_id, version DESC`)
	if err != nil {
		return nil, err
	}
	return scanTemplates(rows)
}

// TenantTemplateBinding is a customer's last template application, or nil.
func (p *PGStore) TenantTemplateBinding(ctx context.Context, tenantID string) (*TemplateApplication, error) {
	rows, err := p.store.SystemPool().Query(ctx, bindingSelect+` WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	bindings, err := scanBindings(rows)
	if err != nil || len(bindings) == 0 {
		return nil, err
	}
	return &bindings[0], nil
}

// TenantTemplateBindings lists the customers bound to a template.
func (p *PGStore) TenantTemplateBindings(ctx context.Context, templateID string) ([]TemplateApplication, error) {
	rows, err := p.store.SystemPool().Query(ctx, bindingSelect+` WHERE template_id = $1 ORDER BY tenant_id`, templateID)
	if err != nil {
		return nil, err
	}
	return scanBindings(rows)
}

func scanTemplates(rows pgx.Rows) ([]TenantTemplate, error) {
	defer rows.Close()
	out := []TenantTemplate{}
	for rows.Next() {
		var t TenantTemplate
		var baseline []byte
		var recordedAt time.Time
		if err := rows.Scan(&t.ID, &t.Version, &t.Name, &baseline, &t.Digest, &t.RecordedBy, &recordedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(baseline, &t.Baseline); err != nil {
			return nil, errors.New("provider: a recorded template baseline does not decode")
		}
		t.RecordedAt = recordedAt.UTC().Format(timeLayout)
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanBindings(rows pgx.Rows) ([]TemplateApplication, error) {
	defer rows.Close()
	out := []TemplateApplication{}
	for rows.Next() {
		var a TemplateApplication
		var results []byte
		var appliedAt time.Time
		if err := rows.Scan(&a.TenantID, &a.TemplateID, &a.Version, &a.Digest, &a.Complete, &results, &a.AppliedBy, &appliedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(results, &a.Results); err != nil {
			return nil, errors.New("provider: a recorded template application does not decode")
		}
		a.AppliedAt = appliedAt.UTC().Format(timeLayout)
		out = append(out, a)
	}
	return out, rows.Err()
}
