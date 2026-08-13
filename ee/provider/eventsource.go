// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	EventDelegationGranted  = "provider.delegation.granted"
	EventDelegationRevoked  = "provider.delegation.revoked"
	EventOperatorUpserted   = "provider.operator.upserted"
	EventOperatorOffboarded = "provider.operator.offboarded"
	EventTenantQuotaSet     = "provider.tenant.quota.set"
	EventTenantBrandSet     = "provider.tenant.brand.set"
)

var (
	// ErrMutationConflict means one stable mutation key named two different
	// authenticated commands. Replaying the first command or running the second
	// would both be unsafe, so the mutation is refused before projection.
	ErrMutationConflict = errors.New("provider: idempotency key was already used for a different mutation")
	// ErrMutationPersistence marks event-commit or projection failures after
	// transport validation. The HTTP layer returns 500 and leaves the durable
	// idempotency claim replayable instead of caching the failure as a 4xx.
	ErrMutationPersistence = errors.New("provider: durable mutation did not converge")

	providerMutationNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.com/provider/mutation"))
)

// DelegationMutation is the exact authority row created or removed by a
// provider delegation event. One operation is one row so revoking suspend
// authority cannot accidentally revoke read authority with it.
type DelegationMutation struct {
	OperatorID string    `json:"operator_id"`
	CustomerID string    `json:"customer_id"`
	Operation  Operation `json:"operation"`
	GrantedBy  string    `json:"granted_by,omitempty"`
	Source     string    `json:"source,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// AuthorityEvent is the version-1 result envelope for every Provider authority
// mutation. The event type selects exactly one state member; Audit is the who,
// what, when, and why view of that SAME immutable event. There is no second
// best-effort audit append that can disagree with the business state.
type AuthorityEvent struct {
	Tenant              *Tenant               `json:"tenant,omitempty"`
	Operator            *OperatorIdentity     `json:"operator,omitempty"`
	Delegation          *DelegationMutation   `json:"delegation,omitempty"`
	Delegations         []DelegationMutation  `json:"delegations,omitempty"`
	Quota               *billing.Quota        `json:"quota,omitempty"`
	Brand               *TenantBrand          `json:"brand,omitempty"`
	BrandTokenOverrides map[string]string     `json:"brand_token_overrides,omitempty"`
	Grant               *BreakGlassGrant      `json:"break_glass_grant,omitempty"`
	Snapshot            *TenantSnapshot       `json:"tenant_snapshot,omitempty"`
	Drill               *IsolationDrillReport `json:"isolation_drill,omitempty"`
	EffectiveAt         time.Time             `json:"effective_at,omitempty"`
	RequestBinding      string                `json:"request_binding,omitempty"`
	Audit               AuditEvent            `json:"audit"`
}

// MutationSink is the command-side boundary used by Service. Production wires
// EventMutationSink; tests may supply a deterministic recorder.
type MutationSink interface {
	Append(context.Context, string, string, string, AuthorityEvent) (eventspec.Event, error)
}

type mutationKeyContext struct{}
type mutationBindingContext struct{}

// ContextWithMutationKey carries the transport's required Idempotency-Key to
// the provider command side. It stays out of payload structs so a caller cannot
// replace it through JSON.
func ContextWithMutationKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, mutationKeyContext{}, strings.TrimSpace(key))
}

func mutationKeyFromContext(ctx context.Context) string {
	key, _ := ctx.Value(mutationKeyContext{}).(string)
	return strings.TrimSpace(key)
}

func contextWithMutationBinding(ctx context.Context, binding string) context.Context {
	return context.WithValue(ctx, mutationBindingContext{}, strings.TrimSpace(binding))
}

func mutationBindingFromContext(ctx context.Context) string {
	binding, _ := ctx.Value(mutationBindingContext{}).(string)
	return strings.TrimSpace(binding)
}

// AuthorityRuntime is the one production object graph shared by inline
// mutations, boot replay, and the live event tail.
type AuthorityRuntime struct {
	Projection        *AuthorityProjection
	Mutations         *EventMutationSink
	ProjectionOptions []projections.Option
}

func NewAuthorityRuntime(st *corestore.Store, log *events.Log) *AuthorityRuntime {
	projection := NewAuthorityProjection(st)
	return &AuthorityRuntime{
		Projection:        projection,
		Mutations:         NewEventMutationSink(log, projection),
		ProjectionOptions: []projections.Option{projections.WithEventProjection(projection)},
	}
}

// EventMutationSink appends the immutable result first, then updates the
// relational view through the same projection used by replay. If projection
// fails after append, the caller sees an error but the source event remains;
// startup replay or an identical retry completes the view without another
// event.
type EventMutationSink struct {
	log        *events.Log
	projection *AuthorityProjection
}

func NewEventMutationSink(log *events.Log, projection *AuthorityProjection) *EventMutationSink {
	return &EventMutationSink{log: log, projection: projection}
}

// Append records one stable-keyed provider mutation and synchronously projects
// it for read-your-write API behavior. The event ID depends only on tenant and
// raw idempotency key: reusing a key for another route reaches the canonical
// first event and the byte-for-byte command comparison returns a conflict.
func (s *EventMutationSink) Append(
	ctx context.Context,
	idempotencyKey string,
	typ string,
	tenantID string,
	payload AuthorityEvent,
) (eventspec.Event, error) {
	if s == nil || s.log == nil || s.projection == nil {
		return eventspec.Event{}, errors.New("provider: durable event mutation sink is not configured")
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	tenantID = strings.TrimSpace(tenantID)
	if idempotencyKey == "" || tenantID == "" || strings.TrimSpace(typ) == "" {
		return eventspec.Event{}, errors.New("provider: mutation requires idempotency key, tenant, and event type")
	}
	if payload.Audit.Type == "" {
		payload.Audit.Type = typ
	}
	if payload.Audit.TenantID == "" {
		payload.Audit.TenantID = tenantID
	}
	if payload.RequestBinding == "" {
		payload.RequestBinding = mutationBindingFromContext(ctx)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("provider: encode %s: %w", typ, err)
	}
	eventID := uuid.NewSHA1(providerMutationNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
	eventTime := payload.EffectiveAt
	if eventTime.IsZero() {
		eventTime = payload.Audit.At
	}
	wanted := events.Event{ID: eventID, Type: typ, TenantID: tenantID, Time: eventTime, Data: data}
	canonical, err := s.log.Append(ctx, wanted)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("%w: append %s: %v", ErrMutationPersistence, typ, err)
	}
	if canonical.ID != wanted.ID || canonical.Type != wanted.Type || canonical.TenantID != wanted.TenantID {
		return eventspec.Event{}, ErrMutationConflict
	}
	if !bytes.Equal(canonical.Data, wanted.Data) {
		var prior AuthorityEvent
		if payload.RequestBinding == "" || json.Unmarshal(canonical.Data, &prior) != nil ||
			prior.RequestBinding != payload.RequestBinding {
			return eventspec.Event{}, ErrMutationConflict
		}
	}
	if err := s.projection.Apply(ctx, canonical); err != nil {
		return eventspec.Event{}, fmt.Errorf("%w: project %s: %v", ErrMutationPersistence, typ, err)
	}
	return canonical, nil
}

// AuthorityProjection owns the six PostgreSQL views of Provider authority.
// It is registered through core's feature-neutral EventProjection seam, keeping
// MPL core free of EE imports while making normal startup and explicit replay
// rebuild the licensed views from the same log.
type AuthorityProjection struct {
	store *corestore.Store

	mu        sync.Mutex
	watermark uint64

	// applyHook is a package-private crash seam. Production leaves it nil.
	applyHook func(context.Context, events.Event) error
}

func NewAuthorityProjection(st *corestore.Store) *AuthorityProjection {
	return &AuthorityProjection{store: st}
}

func (p *AuthorityProjection) Name() string { return "provider.authority" }

func (p *AuthorityProjection) ReplayWatermark() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watermark
}

// Reset erases only derived provider views. The immutable event history is not
// touched. SystemPool is deliberate: this projection rebuilds every customer's
// view before any one tenant context exists.
func (p *AuthorityProjection) Reset(ctx context.Context) error {
	if p == nil || p.store == nil {
		return errors.New("provider: authority projection store is not configured")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ResetTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResetTx joins core's atomic full-rebuild transaction. It is also used by
// Reset through a short system-pool transaction for boot replay.
func (p *AuthorityProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil {
		return errors.New("provider: authority projection store is not configured")
	}
	for _, statement := range []string{
		//trstctl:system-query — edition projection reset rebuilds every provider customer before a tenant is selected; each table remains tenant-filtered on normal reads.
		`DELETE FROM provider_operator_delegations WHERE tenant_id = '` + providerAuthorityTenant + `'`,
		//trstctl:system-query — the fixed Provider authority tenant is restored only from immutable Provider events.
		`DELETE FROM provider_operators WHERE tenant_id = '` + providerAuthorityTenant + `'`,
		//trstctl:system-query — same full-replay reset; this is a trusted projection writer, never a tenant route.
		`DELETE FROM provider_breakglass_grants`,
		//trstctl:system-query — same full-replay reset; the replay restores tenant_id on every row.
		`DELETE FROM provider_tenant_quotas`,
		//trstctl:system-query — same full-replay reset; the replay restores tenant_id on every row.
		`DELETE FROM tenant_branding`,
		//trstctl:system-query — same full-replay reset of the provider-global registry.
		`DELETE FROM provider_tenants`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.watermark = 0
	p.mu.Unlock()
	return nil
}

func (p *AuthorityProjection) Apply(ctx context.Context, event eventspec.Event) error {
	if p == nil || p.store == nil {
		return errors.New("provider: authority projection store is not configured")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ApplyTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApplyTx folds one event using the caller's transaction. Rebuild uses this to
// keep EE and core projections all-or-nothing; normal inline/tail application
// reaches it through Apply's short system-pool transaction.
func (p *AuthorityProjection) ApplyTx(ctx context.Context, tx pgx.Tx, event eventspec.Event) error {
	if p == nil || p.store == nil {
		return errors.New("provider: authority projection store is not configured")
	}
	if p.applyHook != nil {
		if err := p.applyHook(ctx, event); err != nil {
			return err
		}
	}
	if !providerAuthorityEvent(event.Type) {
		p.advance(event.Sequence)
		return nil
	}
	if event.SchemaVersion != 0 && event.SchemaVersion != eventspec.DefaultSchemaVersion {
		return fmt.Errorf("provider: unsupported %s schema version %d", event.Type, event.SchemaVersion)
	}
	var payload AuthorityEvent
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return fmt.Errorf("provider: decode %s: %w", event.Type, err)
	}
	// Legacy provider events were audit-only payloads appended after a direct
	// table mutation. They cannot rebuild state, but they must not brick an
	// upgraded deployment. Bootstrap emits complete result events before this
	// projection is registered; audit-only history is therefore ignored here.
	if !payload.hasState() {
		p.advance(event.Sequence)
		return nil
	}
	if err := validateAuthorityEvent(event, payload); err != nil {
		return err
	}
	if err := applyAuthorityEventTx(ctx, tx, event, payload); err != nil {
		return err
	}
	p.advance(event.Sequence)
	return nil
}

func (p *AuthorityProjection) advance(sequence uint64) {
	p.mu.Lock()
	if sequence > p.watermark {
		p.watermark = sequence
	}
	p.mu.Unlock()
}

func (p AuthorityEvent) hasState() bool {
	return p.Tenant != nil || p.Operator != nil || p.Delegation != nil || len(p.Delegations) > 0 ||
		p.Quota != nil || p.Brand != nil || p.Grant != nil
}

func authorityEventTime(event eventspec.Event, payload AuthorityEvent) time.Time {
	if !payload.EffectiveAt.IsZero() {
		return payload.EffectiveAt.UTC()
	}
	if !payload.Audit.At.IsZero() {
		return payload.Audit.At.UTC()
	}
	return event.Time.UTC()
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func providerAuthorityEvent(typ string) bool {
	switch typ {
	case AuditTenantProvisioned, AuditTenantSuspended, AuditTenantOffboarded,
		EventOperatorUpserted, EventOperatorOffboarded,
		EventDelegationGranted, EventDelegationRevoked, EventTenantQuotaSet, EventTenantBrandSet,
		AuditBreakGlassRequested, AuditBreakGlassConsented, AuditBreakGlassDenied, AuditBreakGlassAccessed:
		return true
	default:
		return false
	}
}

func validateAuthorityEvent(event eventspec.Event, payload AuthorityEvent) error {
	if payload.Audit.Type != "" && payload.Audit.Type != event.Type {
		return fmt.Errorf("provider: %s audit type mismatch %q", event.Type, payload.Audit.Type)
	}
	if payload.Audit.TenantID != "" && payload.Audit.TenantID != event.TenantID {
		return fmt.Errorf("provider: %s audit tenant mismatch %q/%q", event.Type, event.TenantID, payload.Audit.TenantID)
	}
	for name, tenantID := range map[string]string{
		"tenant": func() string {
			if payload.Tenant == nil {
				return ""
			}
			return payload.Tenant.ID
		}(),
		"delegation": func() string {
			if payload.Delegation == nil {
				return ""
			}
			return payload.Delegation.CustomerID
		}(),
		"quota": func() string {
			if payload.Quota == nil {
				return ""
			}
			return payload.Quota.TenantID
		}(),
		"brand": func() string {
			if payload.Brand == nil {
				return ""
			}
			return payload.Brand.TenantID
		}(),
		"break-glass grant": func() string {
			if payload.Grant == nil {
				return ""
			}
			return payload.Grant.TenantID
		}(),
		"tenant snapshot": func() string {
			if payload.Snapshot == nil {
				return ""
			}
			return payload.Snapshot.TenantID
		}(),
	} {
		if tenantID != "" && tenantID != event.TenantID {
			return fmt.Errorf("provider: %s %s tenant mismatch %q/%q", event.Type, name, event.TenantID, tenantID)
		}
	}
	for _, delegation := range payload.Delegations {
		if delegation.CustomerID != event.TenantID {
			return fmt.Errorf("provider: %s delegation tenant mismatch %q/%q",
				event.Type, event.TenantID, delegation.CustomerID)
		}
	}
	if payload.Operator != nil && event.TenantID != providerAuthorityTenant {
		return fmt.Errorf("provider: %s operator authority tenant mismatch %q", event.Type, event.TenantID)
	}
	return nil
}

func applyAuthorityEventTx(ctx context.Context, tx pgx.Tx, event eventspec.Event, payload AuthorityEvent) error {
	effectiveAt := authorityEventTime(event, payload)
	switch event.Type {
	case EventOperatorUpserted, EventOperatorOffboarded:
		if payload.Operator == nil {
			return fmt.Errorf("provider: %s needs operator state", event.Type)
		}
		operator := payload.Operator
		//trstctl:system-query — exact fixed-tenant Provider operator projection; no customer-selected tenant enters this statement.
		if _, err := tx.Exec(ctx, `INSERT INTO provider_operators
			(tenant_id, id, external_id, user_name, email, display_name, role, active, source,
			 created_at, updated_at, deprovisioned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (tenant_id, id) DO UPDATE SET external_id = EXCLUDED.external_id,
			user_name = EXCLUDED.user_name, email = EXCLUDED.email, display_name = EXCLUDED.display_name,
			role = EXCLUDED.role, active = EXCLUDED.active, source = EXCLUDED.source,
			created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at,
			deprovisioned_at = EXCLUDED.deprovisioned_at`, providerAuthorityTenant,
			operator.ID, operator.ExternalID, operator.UserName, operator.Email, operator.DisplayName,
			string(operator.Role), operator.Active, operator.Source, operator.CreatedAt.UTC(),
			operator.UpdatedAt.UTC(), nullTime(operator.DeprovisionedAt)); err != nil {
			return err
		}
		if !operator.Active {
			//trstctl:system-query — one provider-global leaver revokes only that operator's still-live customer authority.
			if _, err := tx.Exec(ctx, `UPDATE provider_operator_delegations
				SET revoked_at = COALESCE(revoked_at, $3), revoked_by = CASE WHEN revoked_at IS NULL THEN $4 ELSE revoked_by END
				WHERE tenant_id = $1 AND operator_id = $2 AND revoked_at IS NULL`,
				providerAuthorityTenant, operator.ID, effectiveAt, payload.Audit.OperatorID); err != nil {
				return err
			}
		}
	case AuditTenantProvisioned, AuditTenantSuspended, AuditTenantOffboarded:
		if payload.Tenant == nil {
			return fmt.Errorf("provider: %s needs tenant state", event.Type)
		}
		tenant := payload.Tenant
		//trstctl:system-query — provider-global registry projection, explicitly keyed by the event tenant.
		if _, err := tx.Exec(ctx, `INSERT INTO provider_tenants
			(tenant_id, slug, name, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id) DO UPDATE SET slug = EXCLUDED.slug, name = EXCLUDED.name,
			status = EXCLUDED.status, created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			tenant.ID, tenant.Slug, tenant.Name, string(tenant.Status), tenant.CreatedAt.UTC(), tenant.UpdatedAt.UTC()); err != nil {
			return err
		}
		if event.Type == AuditTenantOffboarded {
			//trstctl:system-query — offboarding retires authority over this exact customer but keeps the historical row.
			_, err := tx.Exec(ctx, `UPDATE provider_operator_delegations
				SET revoked_at = COALESCE(revoked_at, $3), revoked_by = CASE WHEN revoked_at IS NULL THEN 'system:customer-offboard' ELSE revoked_by END
				WHERE tenant_id = $1 AND customer_tenant_id = $2 AND revoked_at IS NULL`,
				providerAuthorityTenant, event.TenantID, effectiveAt)
			return err
		}
	case EventDelegationGranted:
		delegations := authorityDelegations(payload)
		if len(delegations) == 0 {
			return errors.New("provider: delegation grant event needs delegation state")
		}
		for _, d := range delegations {
			//trstctl:system-query — provider authority projection, keyed by exact operator/customer/operation.
			if _, err := tx.Exec(ctx, `INSERT INTO provider_operator_delegations
				(tenant_id, operator_id, customer_tenant_id, operation, granted_by, granted_at, source, expires_at,
				 revoked_at, revoked_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, '')
				ON CONFLICT (tenant_id, operator_id, customer_tenant_id, operation) DO UPDATE SET
				granted_by = EXCLUDED.granted_by, granted_at = EXCLUDED.granted_at,
				source = EXCLUDED.source, expires_at = EXCLUDED.expires_at,
				revoked_at = NULL, revoked_by = ''`,
				providerAuthorityTenant, d.OperatorID, d.CustomerID, string(d.Operation), d.GrantedBy, effectiveAt,
				normalizeDelegationSource(d.Source), nullTime(d.ExpiresAt)); err != nil {
				return err
			}
		}
	case EventDelegationRevoked:
		delegations := authorityDelegations(payload)
		if len(delegations) == 0 {
			return errors.New("provider: delegation revoke event needs delegation state")
		}
		for _, d := range delegations {
			//trstctl:system-query — provider authority projection, retiring the exact event-named grant while retaining evidence.
			if _, err := tx.Exec(ctx, `UPDATE provider_operator_delegations
				SET revoked_at = COALESCE(revoked_at, $5), revoked_by = CASE WHEN revoked_at IS NULL THEN $6 ELSE revoked_by END
				WHERE tenant_id = $1 AND operator_id = $2 AND customer_tenant_id = $3 AND operation = $4`,
				providerAuthorityTenant, d.OperatorID, d.CustomerID, string(d.Operation), effectiveAt, payload.Audit.OperatorID); err != nil {
				return err
			}
		}
	case EventTenantQuotaSet:
		if payload.Quota == nil {
			return errors.New("provider: quota event needs quota state")
		}
		q := payload.Quota
		_, err := tx.Exec(ctx, `INSERT INTO provider_tenant_quotas
			(tenant_id, max_agents, max_tenants, max_certificates_stored, max_secrets_stored, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7)
			ON CONFLICT (tenant_id) DO UPDATE SET max_agents = EXCLUDED.max_agents,
			max_tenants = EXCLUDED.max_tenants, max_certificates_stored = EXCLUDED.max_certificates_stored,
			max_secrets_stored = EXCLUDED.max_secrets_stored, updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`, q.TenantID, q.MaxAgents, q.MaxTenants,
			q.MaxCertificatesStored, q.MaxSecretsStored, q.UpdatedBy, effectiveAt)
		return err
	case EventTenantBrandSet:
		if payload.Brand == nil {
			return errors.New("provider: brand event needs brand state")
		}
		b := payload.Brand
		tokens, err := json.Marshal(payload.BrandTokenOverrides)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO tenant_branding
			(tenant_id, product_name, logo_data_uri, login_message, token_overrides,
			 email_from_name, email_footer, custom_domain, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id) DO UPDATE SET product_name = EXCLUDED.product_name,
			logo_data_uri = EXCLUDED.logo_data_uri, login_message = EXCLUDED.login_message,
			token_overrides = EXCLUDED.token_overrides, email_from_name = EXCLUDED.email_from_name,
			email_footer = EXCLUDED.email_footer, custom_domain = EXCLUDED.custom_domain,
			updated_at = EXCLUDED.updated_at`, b.TenantID, b.ProductName, b.LogoDataURI,
			b.LoginMessage, tokens, b.EmailFromName, b.EmailFooter, b.CustomDomain, effectiveAt)
		return err
	case AuditBreakGlassRequested, AuditBreakGlassConsented, AuditBreakGlassDenied, AuditBreakGlassAccessed:
		if payload.Grant == nil {
			return fmt.Errorf("provider: %s needs break-glass state", event.Type)
		}
		g := payload.Grant
		//trstctl:system-query — provider break-glass projection, keyed by the exact grant and event tenant.
		_, err := tx.Exec(ctx, `INSERT INTO provider_breakglass_grants
			(id, tenant_id, operator_id, operator_email, reason, requested_at, expires_at,
			 consented_at, consented_by, denied_at, denied_by, revoked_at, use_count,
			 consented_at_2, consented_by_2)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, nullif($15, ''))
			ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id,
			operator_id = EXCLUDED.operator_id, operator_email = EXCLUDED.operator_email,
			reason = EXCLUDED.reason, requested_at = EXCLUDED.requested_at, expires_at = EXCLUDED.expires_at,
			consented_at = EXCLUDED.consented_at, consented_by = EXCLUDED.consented_by,
			denied_at = EXCLUDED.denied_at, denied_by = EXCLUDED.denied_by,
			revoked_at = EXCLUDED.revoked_at, use_count = EXCLUDED.use_count,
			consented_at_2 = EXCLUDED.consented_at_2, consented_by_2 = EXCLUDED.consented_by_2`,
			g.ID, g.TenantID, g.OperatorID, g.OperatorEmail, g.Reason, g.RequestedAt.UTC(), g.ExpiresAt.UTC(),
			nullTime(g.ConsentedAt), g.ConsentedBy, nullTime(g.DeniedAt), g.DeniedBy,
			nullTime(g.RevokedAt), g.UseCount, nullTime(g.SecondConsentedAt), g.SecondConsentedBy)
		return err
	}
	if operation, ok := delegationOperationForEvent(event.Type); ok && payload.Audit.OperatorID != "" && event.TenantID != providerAuthorityTenant {
		//trstctl:system-query — last use is derived from the exact successful immutable customer action and updates only its exact active authority row.
		if _, err := tx.Exec(ctx, `UPDATE provider_operator_delegations
			SET last_used_at = $5
			WHERE tenant_id = $1 AND operator_id = $2 AND customer_tenant_id = $3 AND operation = $4
			  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $5)`,
			providerAuthorityTenant, payload.Audit.OperatorID, event.TenantID, string(operation), effectiveAt); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDelegationSource(source string) string {
	if source = strings.TrimSpace(source); source != "" {
		return source
	}
	return "legacy_local_command"
}

func delegationOperationForEvent(eventType string) (Operation, bool) {
	switch eventType {
	case AuditTenantProvisioned, EventTenantQuotaSet, EventTenantBrandSet:
		return OpProvision, true
	case AuditTenantSuspended:
		return OpSuspend, true
	case AuditTenantOffboarded:
		return OpOffboard, true
	case AuditBreakGlassRequested, AuditBreakGlassAccessed:
		return OpBreakGlass, true
	default:
		return "", false
	}
}

func authorityDelegations(payload AuthorityEvent) []DelegationMutation {
	if len(payload.Delegations) > 0 {
		return payload.Delegations
	}
	if payload.Delegation != nil {
		return []DelegationMutation{*payload.Delegation}
	}
	return nil
}
