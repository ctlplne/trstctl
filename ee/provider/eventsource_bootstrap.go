// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/events"
)

type authorityCoverage struct {
	tenants                 map[string]bool
	operators               map[string]bool
	delegations             map[string]bool
	nonBootstrapDelegations map[string]bool
	delegationRevocations   map[string]bool
	quotas                  map[string]bool
	brands                  map[string]bool
	grants                  map[string]bool
}

func newAuthorityCoverage() authorityCoverage {
	return authorityCoverage{
		tenants: map[string]bool{}, operators: map[string]bool{}, delegations: map[string]bool{},
		nonBootstrapDelegations: map[string]bool{}, delegationRevocations: map[string]bool{}, quotas: map[string]bool{},
		brands: map[string]bool{}, grants: map[string]bool{},
	}
}

// Bootstrap captures rows written by releases before AUD-62 as immutable
// result events BEFORE boot replay resets the provider projections. Coverage is
// tracked per entity from complete events, so a crash halfway through resumes
// the uncovered rows; a normal restart appends nothing.
func (r *AuthorityRuntime) Bootstrap(ctx context.Context) error {
	if r == nil || r.Projection == nil || r.Projection.store == nil || r.Mutations == nil || r.Mutations.log == nil {
		return fmt.Errorf("provider: authority bootstrap requires store, log, projection, and mutation sink")
	}
	return withAuthorityFence(ctx, r.Projection.store, func(ctx context.Context) error {
		// Capture all legacy rows before replay changes any of them. Capturing a
		// revoked grant must not briefly project its earlier granted state.
		captureCtx := context.WithValue(ctx, authorityBootstrapCaptureContext{}, true)
		if err := r.captureLegacyAuthority(captureCtx); err != nil {
			return err
		}
		if err := r.recoverPendingSuspensions(captureCtx); err != nil {
			return err
		}
		return r.Projection.recoverOrdered(captureCtx, r.Mutations.log)
	})
}

// A process may stop after the SQL denial commits but before JetStream ACKs.
// Reconcile each exact event ID before replay; never release the denial merely
// because the source event is absent.
func (r *AuthorityRuntime) recoverPendingSuspensions(ctx context.Context) error {
	var afterTenant, afterEvent string
	for {
		keys, err := r.Projection.store.PendingProviderSuspendKeysSystem(ctx, afterTenant, afterEvent, 100)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
		for _, key := range keys {
			command, err := r.Projection.store.ProviderSuspendCommand(ctx, key[0], key[1])
			if err != nil {
				return err
			}
			retained, found, err := r.Mutations.log.EventByID(ctx, key[1])
			if err != nil {
				return err
			}
			if !found {
				retained, err = r.Mutations.log.Append(ctx, command.Event)
				if err != nil {
					return fmt.Errorf("provider: recover pending suspension %s: %w", key[1], err)
				}
			}
			if retained.ID != command.Event.ID || retained.Type != command.Event.Type ||
				retained.TenantID != command.Event.TenantID || !retained.Time.Equal(command.Event.Time) ||
				!bytes.Equal(retained.Data, command.Event.Data) ||
				!reflect.DeepEqual(retained.Actor, command.Event.Actor) {
				return fmt.Errorf("provider: suspension %s source differs from first command", key[1])
			}
		}
		last := keys[len(keys)-1]
		afterTenant, afterEvent = last[0], last[1]
	}
}

func (r *AuthorityRuntime) captureLegacyAuthority(ctx context.Context) error {
	coverage := newAuthorityCoverage()
	if err := r.Mutations.log.Replay(ctx, 0, func(event events.Event) error {
		if !providerAuthorityEvent(event.Type) {
			return nil
		}
		var payload AuthorityEvent
		if err := json.Unmarshal(event.Data, &payload); err != nil || !payload.hasState() {
			// Pre-AUD-62 audit-only events are intentionally not coverage: they do
			// not contain enough state to rebuild a row.
			return nil
		}
		if payload.Tenant != nil {
			coverage.tenants[payload.Tenant.ID] = true
		}
		if payload.Operator != nil {
			coverage.operators[payload.Operator.ID] = true
		}
		markDelegation := func(delegation DelegationMutation) {
			key := delegationCoverageKey(delegation)
			coverage.delegations[key] = true
			if payload.Audit.Subject != "system:provider-authority-bootstrap" {
				coverage.nonBootstrapDelegations[key] = true
			}
			if event.Type == EventDelegationRevoked {
				coverage.delegationRevocations[key] = true
			}
		}
		if payload.Delegation != nil {
			markDelegation(*payload.Delegation)
		}
		for _, delegation := range payload.Delegations {
			markDelegation(delegation)
		}
		if payload.Quota != nil {
			coverage.quotas[payload.Quota.TenantID] = true
		}
		if payload.Brand != nil {
			coverage.brands[payload.Brand.TenantID] = true
		}
		if payload.Grant != nil {
			coverage.grants[payload.Grant.ID] = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("provider: inspect authority history: %w", err)
	}
	if err := r.bootstrapTenants(ctx, coverage); err != nil {
		return err
	}
	if err := r.bootstrapOperators(ctx, coverage); err != nil {
		return err
	}
	if err := r.bootstrapDelegations(ctx, coverage); err != nil {
		return err
	}
	if err := r.bootstrapQuotas(ctx, coverage); err != nil {
		return err
	}
	if err := r.bootstrapBrands(ctx, coverage); err != nil {
		return err
	}
	return r.bootstrapBreakGlass(ctx, coverage)
}

func (r *AuthorityRuntime) bootstrapOperators(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time fixed-tenant Provider-directory capture before projection reset.
	rows, err := r.Projection.store.SystemPool().Query(ctx, `SELECT id, external_id, user_name, email,
		display_name, role, active, source, created_at, updated_at, deprovisioned_at
		FROM provider_operators WHERE tenant_id = $1 ORDER BY id`, providerAuthorityTenant)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		operator, scanErr := scanOperatorIdentity(rows)
		if scanErr != nil {
			return scanErr
		}
		if coverage.operators[operator.ID] {
			continue
		}
		typ := EventOperatorUpserted
		if !operator.Active {
			typ = EventOperatorOffboarded
		}
		if _, err := r.Mutations.Append(ctx, "bootstrap:operator:"+operator.ID, typ, providerAuthorityTenant,
			AuthorityEvent{Operator: &operator, EffectiveAt: operator.UpdatedAt,
				Audit: AuditEvent{Type: typ, Subject: "system:provider-authority-bootstrap", At: operator.UpdatedAt}}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r *AuthorityRuntime) bootstrapTenants(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time provider-global upgrade capture before projection reset.
	rows, err := r.Projection.store.SystemPool().Query(ctx, `SELECT tenant_id::text, slug, name, status, created_at, updated_at
		FROM provider_tenants ORDER BY tenant_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tenant Tenant
		var status string
		if err := rows.Scan(&tenant.ID, &tenant.Slug, &tenant.Name, &status, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
			return err
		}
		tenant.Status = TenantStatus(status)
		if coverage.tenants[tenant.ID] {
			continue
		}
		typ := AuditTenantProvisioned
		switch tenant.Status {
		case TenantSuspended:
			typ = AuditTenantSuspended
		case TenantOffboarded:
			typ = AuditTenantOffboarded
		case TenantOffboarding, TenantOffboardFailed:
			return fmt.Errorf("provider: unfinished customer erasure %s has no retained request", tenant.ID)
		}
		if _, err := r.Mutations.Append(ctx, "bootstrap:tenant:"+tenant.ID, typ, tenant.ID, AuthorityEvent{
			Tenant: &tenant, EffectiveAt: tenant.UpdatedAt,
			Audit: AuditEvent{Type: typ, TenantID: tenant.ID, Subject: "system:provider-authority-bootstrap", At: tenant.UpdatedAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r *AuthorityRuntime) bootstrapDelegations(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time provider-global upgrade capture before projection reset.
	rows, err := r.Projection.store.SystemPool().Query(ctx, `SELECT operator_id, customer_tenant_id, operation, granted_by,
		source, expires_at, granted_at, revoked_at, revoked_by
		FROM provider_operator_delegations WHERE tenant_id = $1
		ORDER BY operator_id, customer_tenant_id, operation`, providerAuthorityTenant)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mutation DelegationMutation
		var expiresAt *time.Time
		var revokedAt *time.Time
		var revokedBy string
		var at time.Time
		if err := rows.Scan(&mutation.OperatorID, &mutation.CustomerID, &mutation.Operation,
			&mutation.GrantedBy, &mutation.Source, &expiresAt, &at, &revokedAt, &revokedBy); err != nil {
			return err
		}
		if expiresAt != nil {
			mutation.ExpiresAt = expiresAt.UTC()
		}
		key := delegationCoverageKey(mutation)
		if coverage.nonBootstrapDelegations[key] {
			continue
		}
		if !coverage.delegations[key] {
			if _, err := r.Mutations.Append(ctx, "bootstrap:delegation:"+key,
				EventDelegationGranted, mutation.CustomerID, AuthorityEvent{
					Delegation: &mutation, EffectiveAt: at,
					Audit: AuditEvent{Type: EventDelegationGranted, TenantID: mutation.CustomerID,
						Subject: "system:provider-authority-bootstrap", At: at},
				}); err != nil {
				return err
			}
		}
		if revokedAt != nil && !coverage.delegationRevocations[key] {
			actor := strings.TrimSpace(revokedBy)
			if actor == "" {
				actor = "system:provider-authority-bootstrap"
			}
			if _, err := r.Mutations.Append(ctx, "bootstrap:delegation-revoked:"+key,
				EventDelegationRevoked, mutation.CustomerID, AuthorityEvent{
					Delegation: &mutation, EffectiveAt: revokedAt.UTC(),
					Audit: AuditEvent{Type: EventDelegationRevoked, TenantID: mutation.CustomerID,
						OperatorID: actor, Subject: "system:provider-authority-bootstrap", At: revokedAt.UTC()},
				}); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (r *AuthorityRuntime) bootstrapQuotas(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time cross-tenant upgrade capture; every projected row retains its tenant_id.
	rows, err := r.Projection.store.SystemPool().Query(ctx, `SELECT tenant_id::text, max_agents, max_tenants,
		max_certificates_stored, max_secrets_stored, COALESCE(updated_by, ''), updated_at
		FROM provider_tenant_quotas ORDER BY tenant_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var q billing.Quota
		var agents, tenants, certificates, secrets sql.NullInt64
		var at time.Time
		if err := rows.Scan(&q.TenantID, &agents, &tenants, &certificates, &secrets, &q.UpdatedBy, &at); err != nil {
			return err
		}
		q.MaxAgents, q.MaxTenants = nullableInt(agents), nullableInt(tenants)
		q.MaxCertificatesStored, q.MaxSecretsStored = nullableInt(certificates), nullableInt(secrets)
		if coverage.quotas[q.TenantID] {
			continue
		}
		if _, err := r.Mutations.Append(ctx, "bootstrap:quota:"+q.TenantID, EventTenantQuotaSet, q.TenantID,
			AuthorityEvent{Quota: &q, EffectiveAt: at,
				Audit: AuditEvent{Type: EventTenantQuotaSet, TenantID: q.TenantID,
					Subject: "system:provider-authority-bootstrap", At: at}}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r *AuthorityRuntime) bootstrapBrands(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time cross-tenant upgrade capture; every projected row retains its tenant_id.
	rows, err := r.Projection.store.SystemPool().Query(ctx, `SELECT tenant_id::text, product_name, logo_data_uri,
		login_message, token_overrides, email_from_name, email_footer, custom_domain, updated_at
		FROM tenant_branding ORDER BY tenant_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var brand TenantBrand
		var tokens []byte
		var at time.Time
		if err := rows.Scan(&brand.TenantID, &brand.ProductName, &brand.LogoDataURI, &brand.LoginMessage,
			&tokens, &brand.EmailFromName, &brand.EmailFooter, &brand.CustomDomain, &at); err != nil {
			return err
		}
		if coverage.brands[brand.TenantID] {
			continue
		}
		overrides := map[string]string{}
		if len(tokens) > 0 {
			if err := json.Unmarshal(tokens, &overrides); err != nil {
				return fmt.Errorf("provider: decode brand token overrides for %s: %w", brand.TenantID, err)
			}
		}
		if _, err := r.Mutations.Append(ctx, "bootstrap:brand:"+brand.TenantID, EventTenantBrandSet, brand.TenantID,
			AuthorityEvent{Brand: &brand, BrandTokenOverrides: overrides, EffectiveAt: at,
				Audit: AuditEvent{Type: EventTenantBrandSet, TenantID: brand.TenantID,
					Subject: "system:provider-authority-bootstrap", At: at}}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r *AuthorityRuntime) bootstrapBreakGlass(ctx context.Context, coverage authorityCoverage) error {
	//trstctl:system-query — one-time provider-global upgrade capture before projection reset.
	rows, err := r.Projection.store.SystemPool().Query(ctx, breakGlassSelect+` ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		grant, err := scanBreakGlassGrant(rows)
		if err != nil {
			return err
		}
		if coverage.grants[grant.ID] {
			continue
		}
		if _, err := r.Mutations.Append(ctx, "bootstrap:breakglass:"+grant.ID, AuditBreakGlassRequested, grant.TenantID,
			AuthorityEvent{Grant: &grant, EffectiveAt: grant.RequestedAt,
				Audit: AuditEvent{Type: AuditBreakGlassRequested, TenantID: grant.TenantID,
					GrantID: grant.ID, Subject: "system:provider-authority-bootstrap", At: grant.RequestedAt}}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func delegationCoverageKey(d DelegationMutation) string {
	return strings.TrimSpace(d.OperatorID) + "\x1f" + strings.TrimSpace(d.CustomerID) + "\x1f" + string(d.Operation)
}

func nullableInt(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	v := int(value.Int64)
	return &v
}
