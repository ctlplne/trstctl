// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// OwnerKind enumerates who can own a credential.
type OwnerKind string

const (
	OwnerUser     OwnerKind = "user"
	OwnerTeam     OwnerKind = "team"
	OwnerWorkload OwnerKind = "workload"
	OwnerService  OwnerKind = "service"
	OwnerVendor   OwnerKind = "vendor"
	// DefaultOwnershipAttestationCadence is the production default used when an
	// operator does not set lifecycle.ownership_attestation_cadence.
	DefaultOwnershipAttestationCadence = 90 * 24 * time.Hour
)

// Owner is a credential owner (User | Team | Workload | Service | Vendor).
type Owner struct {
	ID        string
	TenantID  string
	Kind      OwnerKind
	Name      string
	Email     string
	CreatedAt time.Time

	// The application/service model (epic I1). Every field is optional and
	// EMPTY MEANS UNKNOWN, never "none": an estate that predates this model has
	// owners nobody can retroactively classify, and treating blank as a
	// deliberate answer would hide exactly the rows the unowned queue exists to
	// surface.
	ApplicationID string
	Service       string
	BusinessUnit  string
	Environment   string
	// EscalationChain is the STORED chain, distinct from the computed approver
	// snapshot. The snapshot answers "who could approve this right now"; the
	// chain answers "who do I wake, and in what order" — responsibility rather
	// than permission, and the approver graph cannot answer it.
	EscalationChain json.RawMessage
	// OwnershipVerifiedAt is when a human last attested this ownership is still
	// true. Nil means NEVER attested, which is more urgent than attested-long-ago
	// and must not collapse into it.
	OwnershipVerifiedAt *time.Time
	// OwnershipVerifiedBy is the authenticated principal who made the last
	// attestation. ModelDigest binds that decision to the readiness-critical
	// application/environment coordinates; changing either clears all three.
	OwnershipVerifiedBy  string
	OwnershipModelDigest string
	// These two fields suppress duplicate stale-attestation notifications. The
	// `for` timestamp is the verification that was stale when the immutable
	// request event was emitted; a new attestation therefore creates a new edge.
	OwnershipReattestationRequestedAt  *time.Time
	OwnershipReattestationRequestedFor *time.Time

	// Where this ownership claim came from (I2). OwnershipSource empty means
	// UNKNOWN — the row predates provenance — and is never read as "manual": an
	// unrecorded origin is not evidence that a human said so.
	OwnershipSource           string
	OwnershipSourceRef        string
	OwnershipSourceObservedAt *time.Time
}

// OwnershipAttested reports whether this owner has ever been attested.
//
// A method rather than a bare nil check at each call site, because the two
// states it separates are the whole point of the queue: an owner nobody has ever
// confirmed is a different problem from one confirmed a year ago, and a
// truthiness test on a timestamp quietly merges them.
func (o Owner) OwnershipAttested() bool { return o.OwnershipVerifiedAt != nil }

// OwnershipComplete reports whether this owner carries the application model.
//
// Used by the unowned queue. It asks for the two fields that make an owner
// ACTIONABLE during an incident — which application, and which environment —
// rather than demanding every field, because a rule nobody can satisfy gets
// switched off.
func (o Owner) OwnershipComplete() bool {
	return strings.TrimSpace(o.ApplicationID) != "" && strings.TrimSpace(o.Environment) != ""
}

// OwnershipAttestationDueAt is the first instant at which the last human
// decision is no longer current. A nil result means there is no attestation or
// no configured cadence, and callers must not read that as current.
func (o Owner) OwnershipAttestationDueAt(cadence time.Duration) *time.Time {
	if o.OwnershipVerifiedAt == nil || cadence <= 0 {
		return nil
	}
	due := o.OwnershipVerifiedAt.UTC().Add(cadence)
	return &due
}

// OwnershipCurrent reports whether a complete owner has a still-current human
// attestation. The boundary is inclusive on the stale side: at the exact due
// instant the operator owes a new decision.
func (o Owner) OwnershipCurrent(now time.Time, cadence time.Duration) bool {
	due := o.OwnershipAttestationDueAt(cadence)
	if !o.OwnershipComplete() || due == nil || !now.UTC().Before(*due) ||
		strings.TrimSpace(o.OwnershipVerifiedBy) == "" || strings.TrimSpace(o.OwnershipModelDigest) == "" {
		return false
	}
	digest, err := OwnerModelDigest(o)
	return err == nil && o.OwnershipModelDigest == digest
}

// OwnerModelDigest binds an attestation to the two fields OwnershipComplete
// treats as readiness authority. Service taxonomy and escalation routing can be
// maintained without forcing a new ownership decision; moving the credential to
// a different application or environment cannot.
func OwnerModelDigest(o Owner) (string, error) {
	canonical, err := json.Marshal(struct {
		ApplicationID string `json:"application_id"`
		Environment   string `json:"environment"`
	}{
		ApplicationID: strings.TrimSpace(o.ApplicationID),
		Environment:   strings.TrimSpace(o.Environment),
	})
	if err != nil {
		return "", fmt.Errorf("store: encode owner application model: %w", err)
	}
	return "sha256:" + crypto.SHA256Hex(canonical), nil
}

// OwnerEscalationChain validates and copies the stored JSON chain.
func OwnerEscalationChain(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	var chain []string
	if err := json.Unmarshal(raw, &chain); err != nil {
		return nil, fmt.Errorf("store: escalation_chain must be an array of strings: %w", err)
	}
	if len(chain) > 32 {
		return nil, errors.New("store: escalation_chain cannot contain more than 32 recipients")
	}
	for i := range chain {
		chain[i] = strings.TrimSpace(chain[i])
		if chain[i] == "" {
			return nil, errors.New("store: escalation_chain recipients cannot be empty")
		}
		if len(chain[i]) > 320 {
			return nil, errors.New("store: escalation_chain recipient is too long")
		}
	}
	return chain, nil
}

// UpsertOwner inserts or updates an owner in its tenant context (RLS-enforced).
func (s *Store) UpsertOwner(ctx context.Context, o Owner) error {
	return s.WithTenant(ctx, o.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email,
			                     application_id, service, business_unit, environment,
			                     escalation_chain, ownership_verified_at, ownership_verified_by,
			                     ownership_model_digest, ownership_reattestation_requested_at,
			                     ownership_reattestation_requested_for)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			 ON CONFLICT (tenant_id, id) DO UPDATE
			    SET kind = EXCLUDED.kind, name = EXCLUDED.name, email = EXCLUDED.email,
			        application_id = EXCLUDED.application_id, service = EXCLUDED.service,
			        business_unit = EXCLUDED.business_unit, environment = EXCLUDED.environment,
			        escalation_chain = EXCLUDED.escalation_chain,
			        -- An attestation is never UNSET by an ordinary upsert. Losing
			        -- it would silently move an owner back into the unattested
			        -- queue, and an operator would re-confirm something that was
			        -- already confirmed — training them to click through it.
			        ownership_verified_at = COALESCE(EXCLUDED.ownership_verified_at, owners.ownership_verified_at),
			        ownership_verified_by = COALESCE(EXCLUDED.ownership_verified_by, owners.ownership_verified_by),
			        ownership_model_digest = COALESCE(EXCLUDED.ownership_model_digest, owners.ownership_model_digest),
			        ownership_reattestation_requested_at = COALESCE(EXCLUDED.ownership_reattestation_requested_at, owners.ownership_reattestation_requested_at),
			        ownership_reattestation_requested_for = COALESCE(EXCLUDED.ownership_reattestation_requested_for, owners.ownership_reattestation_requested_for)`,
			o.ID, o.TenantID, string(o.Kind), o.Name, o.Email,
			nullableText(o.ApplicationID), nullableText(o.Service), nullableText(o.BusinessUnit),
			nullableText(o.Environment), nullableJSON(o.EscalationChain), o.OwnershipVerifiedAt,
			nullableText(o.OwnershipVerifiedBy), nullableText(o.OwnershipModelDigest),
			o.OwnershipReattestationRequestedAt, o.OwnershipReattestationRequestedFor)
		return err
	})
}

// CreateOwner inserts a new owner with a server-generated id and returns it
// populated with that id and created_at. Tenant-scoped (RLS-enforced).
func (s *Store) CreateOwner(ctx context.Context, o Owner) (Owner, error) {
	err := s.WithTenant(ctx, o.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email,
			                     application_id, service, business_unit, environment, escalation_chain)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
			 RETURNING id::text, created_at`,
			o.TenantID, string(o.Kind), o.Name, o.Email,
			nullableText(o.ApplicationID), nullableText(o.Service), nullableText(o.BusinessUnit),
			nullableText(o.Environment), nullableJSON(o.EscalationChain)).Scan(&o.ID, &o.CreatedAt)
	})
	return o, err
}

// UpdateOwner replaces an owner's mutable fields. It returns pgx.ErrNoRows (see
// IsNotFound) when no such owner exists in the tenant.
func (s *Store) UpdateOwner(ctx context.Context, o Owner) error {
	return s.WithTenant(ctx, o.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE owners
			    SET kind = $3, name = $4, email = $5,
			        application_id = $6, service = $7, business_unit = $8, environment = $9,
			        escalation_chain = $10,
			        ownership_verified_at = COALESCE($11, owners.ownership_verified_at),
			        ownership_verified_by = COALESCE($12, owners.ownership_verified_by),
			        ownership_model_digest = COALESCE($13, owners.ownership_model_digest),
			        ownership_reattestation_requested_at = COALESCE($14, owners.ownership_reattestation_requested_at),
			        ownership_reattestation_requested_for = COALESCE($15, owners.ownership_reattestation_requested_for)
			  WHERE tenant_id = $1 AND id = $2`,
			o.TenantID, o.ID, string(o.Kind), o.Name, o.Email,
			nullableText(o.ApplicationID), nullableText(o.Service), nullableText(o.BusinessUnit),
			nullableText(o.Environment), nullableJSON(o.EscalationChain), o.OwnershipVerifiedAt,
			nullableText(o.OwnershipVerifiedBy), nullableText(o.OwnershipModelDigest),
			o.OwnershipReattestationRequestedAt, o.OwnershipReattestationRequestedFor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// DeleteOwner removes an owner. It returns pgx.ErrNoRows when absent.
func (s *Store) DeleteOwner(ctx context.Context, tenantID, id string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM owners WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// ListOwnersPage returns up to limit owners with id greater than afterID
// (keyset pagination; pass ZeroUUID for the first page).
func (s *Store) ListOwnersPage(ctx context.Context, tenantID, afterID string, limit int) ([]Owner, error) {
	var out []Owner
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at,
			        coalesce(application_id, ''), coalesce(service, ''),
			        coalesce(business_unit, ''), coalesce(environment, ''),
			        escalation_chain, ownership_verified_at,
			        coalesce(ownership_verified_by, ''), coalesce(ownership_model_digest, ''),
			        ownership_reattestation_requested_at, ownership_reattestation_requested_for,
			        coalesce(ownership_source, ''), coalesce(ownership_source_ref, ''),
			        ownership_source_observed_at
			   FROM owners WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
			tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				o    Owner
				kind string
			)
			if err := rows.Scan(&o.ID, &o.TenantID, &kind, &o.Name, &o.Email, &o.CreatedAt,
				&o.ApplicationID, &o.Service, &o.BusinessUnit, &o.Environment,
				&o.EscalationChain, &o.OwnershipVerifiedAt, &o.OwnershipVerifiedBy, &o.OwnershipModelDigest,
				&o.OwnershipReattestationRequestedAt, &o.OwnershipReattestationRequestedFor,
				&o.OwnershipSource, &o.OwnershipSourceRef, &o.OwnershipSourceObservedAt); err != nil {
				return err
			}
			o.Kind = OwnerKind(kind)
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// ListOwnersByNames resolves only the owner names present in one bounded CMDB
// page. The old reconcile loaded the first 500 owner UUIDs, so a matching owner
// at UUID position 501 was permanently invisible no matter how many CMDB pages
// were fetched (AUD-46). This query is bounded by the page and tenant-filtered.
func (s *Store) ListOwnersByNames(ctx context.Context, tenantID string, names []string) ([]Owner, error) {
	seen := make(map[string]bool, len(names))
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		normalized = append(normalized, name)
	}
	if len(normalized) == 0 {
		return []Owner{}, nil
	}
	if len(normalized) > 500 {
		return nil, fmt.Errorf("store: owner-name lookup exceeds the 500-record CMDB page bound")
	}
	var out []Owner
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at,
			        coalesce(application_id, ''), coalesce(service, ''),
			        coalesce(business_unit, ''), coalesce(environment, ''),
			        escalation_chain, ownership_verified_at,
			        coalesce(ownership_verified_by, ''), coalesce(ownership_model_digest, ''),
			        ownership_reattestation_requested_at, ownership_reattestation_requested_for,
			        coalesce(ownership_source, ''), coalesce(ownership_source_ref, ''),
			        ownership_source_observed_at
			   FROM owners
			  WHERE tenant_id = $1 AND lower(btrim(name)) = ANY($2::text[])
			  ORDER BY id`, tenantID, normalized)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var owner Owner
			var kind string
			if err := rows.Scan(&owner.ID, &owner.TenantID, &kind, &owner.Name, &owner.Email, &owner.CreatedAt,
				&owner.ApplicationID, &owner.Service, &owner.BusinessUnit, &owner.Environment,
				&owner.EscalationChain, &owner.OwnershipVerifiedAt, &owner.OwnershipVerifiedBy, &owner.OwnershipModelDigest,
				&owner.OwnershipReattestationRequestedAt, &owner.OwnershipReattestationRequestedFor,
				&owner.OwnershipSource, &owner.OwnershipSourceRef, &owner.OwnershipSourceObservedAt); err != nil {
				return err
			}
			owner.Kind = OwnerKind(kind)
			out = append(out, owner)
		}
		return rows.Err()
	})
	return out, err
}

// GetOwner loads an owner in its tenant context.
func (s *Store) GetOwner(ctx context.Context, tenantID, id string) (Owner, error) {
	var (
		o    Owner
		kind string
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at,
			        coalesce(application_id, ''), coalesce(service, ''),
			        coalesce(business_unit, ''), coalesce(environment, ''),
			        escalation_chain, ownership_verified_at,
			        coalesce(ownership_verified_by, ''), coalesce(ownership_model_digest, ''),
			        ownership_reattestation_requested_at, ownership_reattestation_requested_for,
			        coalesce(ownership_source, ''), coalesce(ownership_source_ref, ''),
			        ownership_source_observed_at
			   FROM owners WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&o.ID, &o.TenantID, &kind, &o.Name, &o.Email, &o.CreatedAt,
				&o.ApplicationID, &o.Service, &o.BusinessUnit, &o.Environment,
				&o.EscalationChain, &o.OwnershipVerifiedAt, &o.OwnershipVerifiedBy, &o.OwnershipModelDigest,
				&o.OwnershipReattestationRequestedAt, &o.OwnershipReattestationRequestedFor,
				&o.OwnershipSource, &o.OwnershipSourceRef, &o.OwnershipSourceObservedAt)
	})
	o.Kind = OwnerKind(kind)
	return o, err
}

// ListOwners returns all owners for a tenant.
func (s *Store) ListOwners(ctx context.Context, tenantID string) ([]Owner, error) {
	var out []Owner
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at,
			        coalesce(application_id, ''), coalesce(service, ''),
			        coalesce(business_unit, ''), coalesce(environment, ''),
			        escalation_chain, ownership_verified_at,
			        coalesce(ownership_verified_by, ''), coalesce(ownership_model_digest, ''),
			        ownership_reattestation_requested_at, ownership_reattestation_requested_for,
			        coalesce(ownership_source, ''), coalesce(ownership_source_ref, ''),
			        ownership_source_observed_at
			   FROM owners WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				o    Owner
				kind string
			)
			if err := rows.Scan(&o.ID, &o.TenantID, &kind, &o.Name, &o.Email, &o.CreatedAt,
				&o.ApplicationID, &o.Service, &o.BusinessUnit, &o.Environment,
				&o.EscalationChain, &o.OwnershipVerifiedAt, &o.OwnershipVerifiedBy, &o.OwnershipModelDigest,
				&o.OwnershipReattestationRequestedAt, &o.OwnershipReattestationRequestedFor,
				&o.OwnershipSource, &o.OwnershipSourceRef, &o.OwnershipSourceObservedAt); err != nil {
				return err
			}
			o.Kind = OwnerKind(kind)
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// nullableText maps an empty string to SQL NULL.
//
// The distinction is load-bearing for I1: NULL means nobody has said, an empty
// string would mean somebody said "nothing". The unowned queue is built entirely
// on telling those apart, so the boundary between Go's zero value and SQL's
// absence has to be explicit rather than incidental.
func nullableText(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

// nullableJSON maps an empty escalation chain to SQL NULL, for the same reason.
func nullableJSON(v json.RawMessage) any {
	if len(v) == 0 {
		return nil
	}
	return []byte(v)
}

// UnownedIdentity is a managed identity with no usable ownership (epic I1).
type UnownedIdentity struct {
	IdentityID string
	Name       string
	Status     string
	// Reason is a closed-set explanation, so a console can group and count.
	Reason string
}

// Closed set of reasons an identity lands in the unowned queue.
const (
	// UnownedNoOwner: the identity names no owner at all.
	UnownedNoOwner = "no_owner"
	// UnownedIncompleteOwner: an owner exists but carries no application or
	// environment, so during an incident it names a person and not a system —
	// which is half the answer and the wrong half for deciding blast radius.
	UnownedIncompleteOwner = "owner_missing_application_model"
	// UnownedUnattested: an owner nobody has ever confirmed. Distinct from an
	// owner confirmed long ago, which is a cadence problem rather than a gap.
	UnownedUnattested = "ownership_never_attested"
	// UnownedStale is an attributed owner confirmation older than the configured
	// cadence, so it cannot authorize another steady-state deployment.
	UnownedStale = "ownership_attestation_stale"
)

// ListUnownedIdentities is the high-priority queue this epic exists to expose.
//
// It reports four distinct problems rather than one boolean, because they need
// different actions: no owner is a data-entry gap, an incomplete owner is a
// classification gap, an unattested owner is a trust gap, and a stale owner is
// re-attestation work. Collapsing them into
// "unowned" would give an operator a single number they cannot act on.
func (s *Store) ListUnownedIdentities(ctx context.Context, tenantID string, limit int) ([]UnownedIdentity, error) {
	return s.ListUnownedIdentitiesAt(ctx, tenantID, time.Now().UTC(), DefaultOwnershipAttestationCadence, limit)
}

// ListUnownedIdentitiesAt uses the same clock and cadence as lifecycle
// admission. The visible queue and the deployment wall therefore cannot
// disagree about a stale attestation.
func (s *Store) ListUnownedIdentitiesAt(ctx context.Context, tenantID string, now time.Time, cadence time.Duration, limit int) ([]UnownedIdentity, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if cadence <= 0 {
		cadence = DefaultOwnershipAttestationCadence
	}
	now = now.UTC()
	out := make([]UnownedIdentity, 0, 500)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			// LEFT JOIN, so an identity whose owner row is missing entirely
			// still appears. An INNER JOIN would silently drop exactly the worst
			// case — an identity pointing at an owner that no longer exists.
			`SELECT i.id::text, i.name, i.status,
			        CASE
			          WHEN o.id IS NULL THEN $2
			          WHEN coalesce(o.application_id, '') = '' OR coalesce(o.environment, '') = '' THEN $3
			          WHEN o.ownership_verified_at IS NULL
			            OR coalesce(o.ownership_verified_by, '') = ''
			            OR coalesce(o.ownership_model_digest, '') = '' THEN $4
			          ELSE $5
			        END AS reason
			   FROM identities AS i
			   LEFT JOIN owners AS o ON o.tenant_id = i.tenant_id AND o.id = i.owner_id
			  WHERE i.tenant_id = $1
			    AND (o.id IS NULL
			         OR coalesce(o.application_id, '') = ''
			         OR coalesce(o.environment, '') = ''
			         OR o.ownership_verified_at IS NULL
			         OR coalesce(o.ownership_verified_by, '') = ''
			         OR coalesce(o.ownership_model_digest, '') = ''
			         OR o.ownership_verified_at + make_interval(secs => $7) <= $6)
			  ORDER BY i.created_at, i.id
			  LIMIT $8`,
			tenantID, UnownedNoOwner, UnownedIncompleteOwner, UnownedUnattested, UnownedStale,
			now, int(cadence/time.Second), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u UnownedIdentity
			if err := rows.Scan(&u.IdentityID, &u.Name, &u.Status, &u.Reason); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// ListOpenOwnershipConflicts returns unresolved disagreements, newest first.
func (s *Store) ListOpenOwnershipConflicts(ctx context.Context, tenantID string, limit int) ([]OwnershipConflict, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []OwnershipConflict
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, owner_id::text, field,
			        current_value, current_source, incoming_value, incoming_source,
			        incoming_ref, current_attested, detected_at
			   FROM owner_ownership_conflicts
			  WHERE tenant_id = $1 AND resolved_at IS NULL
			  ORDER BY detected_at DESC
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c OwnershipConflict
			if err := rows.Scan(&c.ID, &c.OwnerID, &c.Field, &c.CurrentValue, &c.CurrentSource,
				&c.IncomingValue, &c.IncomingSource, &c.IncomingRef, &c.CurrentAttested, &c.DetectedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// OwnershipConflict is one field two sources disagree about.
type OwnershipConflict struct {
	ID             string
	OwnerID        string
	Field          string
	CurrentValue   string
	CurrentSource  string
	IncomingValue  string
	IncomingSource string
	IncomingRef    string
	// CurrentAttested records whether the stored side was human-attested when
	// the disagreement was found. It is why the import declined, and without it
	// a reader cannot tell a refused change from an applied one.
	CurrentAttested bool
	DetectedAt      time.Time
}

// CMDBReconcileSchedule is a tenant's standing instruction to re-read ownership
// from its CMDB (I2). One per tenant: two would mean two pollers racing to
// reconcile the same owners, and whichever landed last would look like truth.
type CMDBReconcileSchedule struct {
	ID          string
	TenantID    string
	InstanceURL string
	TokenRef    string
	CIQuery     string
	// AllowPrivateEndpoint mirrors the ticket writer's field and is checked
	// against the same operator binding and the same egress:private permission.
	AllowPrivateEndpoint bool
	IntervalSeconds      int
	Enabled              bool
	// Execution says which vantage runs the sync (I2): "" or "control_plane"
	// for the control plane's own fetch, "relay" to dispatch a cmdb.sync job a
	// network relay inside the segment claims.
	Execution        string
	LastRunAt        *time.Time
	LastError        string
	CurrentSweepID   string
	SweepStartedAt   *time.Time
	LastAttemptAt    *time.Time
	AfterSysID       string
	ReadCount        int
	ExpectedCount    *int
	PagesCompleted   int
	CoverageComplete bool
	RemovedCount     int
	ChangedCount     int
}

// GetCMDBReconcileSchedule returns the tenant's schedule, or ok=false when the
// tenant has never configured one. Absent and disabled stay distinguishable:
// "never set up" and "deliberately paused" are different operator states.
func (s *Store) GetCMDBReconcileSchedule(ctx context.Context, tenantID string) (CMDBReconcileSchedule, bool, error) {
	var out CMDBReconcileSchedule
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, instance_url, token_ref, ci_query,
			        allow_private_endpoint, interval_seconds, enabled, coalesce(execution, ''), last_run_at, last_error,
			        coalesce(current_sweep_id::text, ''), sweep_started_at, last_attempt_at,
			        after_sys_id, read_count, expected_count, pages_completed, coverage_complete,
			        removed_count, changed_count
			   FROM cmdb_reconcile_schedules WHERE tenant_id = $1`, tenantID)
		switch err := row.Scan(&out.ID, &out.TenantID, &out.InstanceURL, &out.TokenRef, &out.CIQuery,
			&out.AllowPrivateEndpoint, &out.IntervalSeconds, &out.Enabled, &out.Execution, &out.LastRunAt, &out.LastError,
			&out.CurrentSweepID, &out.SweepStartedAt, &out.LastAttemptAt, &out.AfterSysID,
			&out.ReadCount, &out.ExpectedCount, &out.PagesCompleted, &out.CoverageComplete,
			&out.RemovedCount, &out.ChangedCount); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}

// TenantsWithEnabledCMDBSchedules enumerates the tenants with an enabled CMDB
// schedule so the leader-only ticker can sweep each under its own RLS context.
func (s *Store) TenantsWithEnabledCMDBSchedules(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants have an enabled CMDB reconcile schedule so the leader-only scheduler can sweep each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM cmdb_reconcile_schedules WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CMDBScheduleDue reports whether the tenant needs a new sweep or has an
// incomplete cursor to resume. Only a terminal page supplies LastRunAt; a
// failed current job remains pending under the agent/outbox retry backoff.
func (s *Store) CMDBScheduleDue(ctx context.Context, tenantID string, now time.Time) (CMDBReconcileSchedule, bool, error) {
	sched, found, err := s.GetCMDBReconcileSchedule(ctx, tenantID)
	if err != nil || !found || !sched.Enabled {
		return CMDBReconcileSchedule{}, false, err
	}
	if sched.IntervalSeconds <= 0 {
		return CMDBReconcileSchedule{}, false, nil
	}
	if sched.CurrentSweepID != "" && !sched.CoverageComplete {
		return sched, true, nil
	}
	if sched.LastRunAt != nil && now.Sub(*sched.LastRunAt) < time.Duration(sched.IntervalSeconds)*time.Second {
		return CMDBReconcileSchedule{}, false, nil
	}
	return sched, true, nil
}
