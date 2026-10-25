// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Owner decision 2026-10-24 (A120/A130/A132): a per-tenant switch over
// control-plane key generation. The control plane generates a subject private
// key for a requester on three deprecated paths (identity issuance without a
// CSR and its renewals, PKI-secret issuance by common name including the
// Vault-compatible pki/issue route, the compatibility Workload API socket).
// New tenants start with it off; a tenant that predates the switch is decided
// once from its own use; an operator can change it at any time. Every change is
// a tenant.control_plane_keygen.set event, projected here.

// Control-plane key generation decision sources.
const (
	ControlPlaneKeygenSourceRegistration = "registration"
	ControlPlaneKeygenSourceUpgrade      = "upgrade"
	ControlPlaneKeygenSourceOperator     = "operator"
)

// ControlPlaneKeygenEvidence is what kept a pre-switch tenant on: its own use
// of a control-plane key generator before the switch existed.
type ControlPlaneKeygenEvidence struct {
	// ControlPlaneCertificates counts certificates whose recorded custody says
	// the control plane generated the key.
	ControlPlaneCertificates int64 `json:"control_plane_certificates"`
	// UnrecordedServedCertificates counts certificates this control plane
	// issued (identity and PKI-secret paths) with no recorded custody, issued
	// before per-certificate custody existed; any of them could have had a
	// server-generated key, so they keep a tenant on.
	UnrecordedServedCertificates int64 `json:"unrecorded_served_certificates"`
	// WorkloadAPISocket is true when the compatibility Workload API socket is
	// configured for this tenant.
	WorkloadAPISocket bool `json:"workload_api_socket"`
	// DeprecationEvents counts the tenant's retained records of a generator
	// run: issuance.server_side_keygen, and spiffe.workload_api.local_socket_used
	// for an X.509-SVID.
	DeprecationEvents int64 `json:"deprecation_events"`
}

// Used reports whether any evidence shows the tenant using control-plane key
// generation.
func (e ControlPlaneKeygenEvidence) Used() bool {
	return e.ControlPlaneCertificates > 0 || e.UnrecordedServedCertificates > 0 || e.WorkloadAPISocket ||
		e.DeprecationEvents > 0
}

// ControlPlaneKeygenPolicy is a tenant's decision.
type ControlPlaneKeygenPolicy struct {
	TenantID string
	Enabled  bool
	Source   string
	Reason   string
	SetBy    string
	SetAt    time.Time
	Evidence *ControlPlaneKeygenEvidence
}

// ApplyControlPlaneKeygenSetTx projects tenant.control_plane_keygen.set. The
// latest decision stands.
func (s *Store) ApplyControlPlaneKeygenSetTx(ctx context.Context, tx pgx.Tx, p ControlPlaneKeygenPolicy) error {
	if p.TenantID == "" {
		return errors.New("store: control-plane key generation decision needs a tenant")
	}
	switch p.Source {
	case ControlPlaneKeygenSourceRegistration, ControlPlaneKeygenSourceUpgrade, ControlPlaneKeygenSourceOperator:
	default:
		return errors.New("store: control-plane key generation decision has an unknown source")
	}
	var evidence []byte
	if p.Evidence != nil {
		var err error
		if evidence, err = json.Marshal(p.Evidence); err != nil {
			return err
		}
	}
	if p.Source == ControlPlaneKeygenSourceUpgrade {
		// The upgrade decides only a tenant nobody has decided yet: an
		// operator's change recorded before it, even in the same moment, stands.
		_, err := tx.Exec(ctx, `INSERT INTO tenant_control_plane_keygen (tenant_id, enabled, source, reason, set_by, set_at, evidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id) DO NOTHING`,
			p.TenantID, p.Enabled, p.Source, p.Reason, p.SetBy, p.SetAt.UTC(), evidence)
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_control_plane_keygen (tenant_id, enabled, source, reason, set_by, set_at, evidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, source = EXCLUDED.source,
		  reason = EXCLUDED.reason, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at, evidence = EXCLUDED.evidence`,
		p.TenantID, p.Enabled, p.Source, p.Reason, p.SetBy, p.SetAt.UTC(), evidence)
	return err
}

// ControlPlaneKeygenFor reads the tenant's decision; found=false means the
// tenant predates the switch and has not been decided yet (it keeps the
// behavior it had: control-plane key generation allowed).
func (s *Store) ControlPlaneKeygenFor(ctx context.Context, tenantID string) (ControlPlaneKeygenPolicy, bool, error) {
	var out ControlPlaneKeygenPolicy
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var evidence []byte
		err := tx.QueryRow(ctx, `SELECT tenant_id::text, enabled, source, reason, set_by, set_at, evidence
			FROM tenant_control_plane_keygen WHERE tenant_id = $1`, tenantID).
			Scan(&out.TenantID, &out.Enabled, &out.Source, &out.Reason, &out.SetBy, &out.SetAt, &evidence)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(evidence) > 0 {
			var e ControlPlaneKeygenEvidence
			if err := json.Unmarshal(evidence, &e); err != nil {
				return err
			}
			out.Evidence = &e
		}
		found = true
		return nil
	})
	return out, found, err
}

// ControlPlaneKeygenAllowed reads the tenant's decision. A tenant with none
// predates the switch and keeps the behavior it had: allowed.
func (s *Store) ControlPlaneKeygenAllowed(ctx context.Context, tenantID string) (bool, error) {
	policy, found, err := s.ControlPlaneKeygenFor(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return !found || policy.Enabled, nil
}

// ActiveControlPlaneKeyCertificates counts the tenant's active certificates
// whose recorded custody says the control plane generated the key: their
// renewals generate a key in the control plane again.
func (s *Store) ActiveControlPlaneKeyCertificates(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM certificates
			WHERE tenant_id = $1 AND status = 'active' AND key_origin = 'control_plane'`, tenantID).Scan(&n)
	})
	return n, err
}

// TenantsWithoutControlPlaneKeygenDecision lists registered tenants with no
// decision yet: tenants that predate the switch.
func (s *Store) TenantsWithoutControlPlaneKeygenDecision(ctx context.Context) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader's one-time upgrade decision lists only tenant IDs without a recorded decision, then reads each tenant's evidence back inside that tenant's RLS context.
		`SELECT t.tenant_id::text FROM tenants t
		  WHERE NOT EXISTS (SELECT 1 FROM tenant_control_plane_keygen k WHERE k.tenant_id = t.tenant_id)
		  ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

// ControlPlaneKeygenEvidenceFor counts a tenant's own use of control-plane key
// generation in its certificate inventory: certificates whose custody, recorded
// or derived, says the control plane generated the key, and certificates from a
// path that could have generated it whose origin is still unrecorded. The
// caller adds the deprecation events and the compatibility socket
// configuration, which the inventory does not hold.
func (s *Store) ControlPlaneKeygenEvidenceFor(ctx context.Context, tenantID string) (ControlPlaneKeygenEvidence, error) {
	var out ControlPlaneKeygenEvidence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			  count(*) FILTER (WHERE key_origin = 'control_plane'),
			  count(*) FILTER (WHERE key_origin = '' AND (source IN ('issued', 'discovery:k8s_ingress_gateway')
			    OR issuance_idempotency_key LIKE 'issue:%' OR issuance_idempotency_key LIKE 'renew:%'
			    OR issuance_idempotency_key LIKE 'k8s-auto:%'))
			FROM certificates WHERE tenant_id = $1`, tenantID).
			Scan(&out.ControlPlaneCertificates, &out.UnrecordedServedCertificates)
	})
	return out, err
}
