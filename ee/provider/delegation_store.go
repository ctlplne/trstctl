// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"
	"strings"

	corestore "trstctl.com/trstctl/internal/store"
)

// Persistence for per-customer delegation (epic L1).
//
// delegation.go decides the rule. Nothing read it: the set was constructed
// nowhere, stored nowhere, and consulted by no served route, so every provider
// route still authorised any authenticated operator against any customer. A
// rule with no enforcement point is the defect this backlog exists to remove.

// DelegationSource supplies the delegations in force.
//
// An interface rather than a concrete store so the Service has ONE refusal
// path: a source that errors and a source that is absent must both refuse, and
// the caller must not be able to tell the difference by getting served.
type DelegationSource interface {
	Delegations(ctx context.Context) (*DelegationSet, error)
}

// PGDelegationSource reads delegations from PostgreSQL.
type PGDelegationSource struct {
	store *corestore.Store
}

// NewPGDelegationSource returns a durable source, or nil when there is no
// database. A nil source refuses every operator — see Service.authorize.
func NewPGDelegationSource(st *corestore.Store) *PGDelegationSource {
	if st == nil {
		return nil
	}
	return &PGDelegationSource{store: st}
}

// Delegations loads the whole grant table.
//
// Loaded in full rather than queried per (operator, customer) because the
// refusal must not depend on a row's absence being distinguishable from a query
// failing: one shape of error, one shape of answer.
func (p *PGDelegationSource) Delegations(ctx context.Context) (*DelegationSet, error) {
	if p == nil || p.store == nil {
		return nil, fmt.Errorf("provider: no delegation store")
	}
	//trstctl:system-query — cross-tenant by design: the provider plane asks which customers an operator may touch BEFORE any tenant is selected, so there is no tenant context to scope to; the table is provider-plane grant data, not customer data, and no tenant-facing route reads it.
	rows, err := p.store.SystemPool().Query(ctx,
		`SELECT operator_id, customer_tenant_id, operation FROM provider_operator_delegations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delegation
	for rows.Next() {
		var operatorID, customerID, operation string
		if err := rows.Scan(&operatorID, &customerID, &operation); err != nil {
			return nil, err
		}
		out = append(out, Delegation{
			OperatorID: operatorID,
			CustomerID: customerID,
			Operations: []Operation{Operation(operation)},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return NewDelegationSet(out), nil
}

// Grant records one operator's authority over one customer.
//
// Granting is itself a provider-plane act and is not exposed on the tenant
// surface. It is idempotent so a replayed provisioning script cannot fail
// halfway and leave an operator with half their intended scope.
func (p *PGDelegationSource) Grant(ctx context.Context, d Delegation, grantedBy string) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("provider: no delegation store")
	}
	operator := strings.TrimSpace(d.OperatorID)
	customer := strings.TrimSpace(d.CustomerID)
	if operator == "" || customer == "" {
		// Storing a half-named grant would put a row in the table that reads
		// like access somebody has.
		return fmt.Errorf("provider: a delegation needs both an operator and a customer")
	}
	for _, op := range d.Operations {
		if strings.TrimSpace(string(op)) == "" {
			continue
		}
		//trstctl:system-query — cross-tenant by design: provider-plane grant data written outside any tenant context, for the same reason the read is.
		if _, err := p.store.SystemPool().Exec(ctx,
			`INSERT INTO provider_operator_delegations (operator_id, customer_tenant_id, operation, granted_by)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (operator_id, customer_tenant_id, operation) DO UPDATE SET granted_by = EXCLUDED.granted_by`,
			operator, customer, string(op), strings.TrimSpace(grantedBy)); err != nil {
			return err
		}
	}
	return nil
}

// Revoke removes one operator's grant of one operation over one customer.
func (p *PGDelegationSource) Revoke(ctx context.Context, operatorID, customerID string, op Operation) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("provider: no delegation store")
	}
	//trstctl:system-query — cross-tenant by design: provider-plane grant data, same rationale as the read.
	_, err := p.store.SystemPool().Exec(ctx,
		`DELETE FROM provider_operator_delegations
		 WHERE operator_id = $1 AND customer_tenant_id = $2 AND operation = $3`,
		strings.TrimSpace(operatorID), strings.TrimSpace(customerID), string(op))
	return err
}

// RevokeAllForCustomer drops every grant over one customer.
//
// Called when a customer is OFFBOARDED. A grant that outlives the tenancy it
// was over is a dangling authority row, and tenant ids here are derived from
// the slug — so reusing an offboarded customer's slug would hand the new
// tenancy to whoever held grants on the old one, silently.
func (p *PGDelegationSource) RevokeAllForCustomer(ctx context.Context, customerID string) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("provider: no delegation store")
	}
	//trstctl:system-query — cross-tenant by design: provider-plane grant data, cleared as part of destroying a customer; there is no tenant context to scope to because the tenancy is being erased.
	_, err := p.store.SystemPool().Exec(ctx,
		`DELETE FROM provider_operator_delegations WHERE customer_tenant_id = $1`,
		strings.TrimSpace(customerID))
	return err
}

// customerRevoker is the optional half of DelegationSource.
//
// PGDelegationSource implements it; StaticDelegations does not, because a set
// compiled into a config file cannot be edited from here. Offboarding under a
// static source therefore leaves the grant lines in that file — which is
// correct, since the file is the source of truth and rewriting it behind the
// operator's back would put the running state out of step with what they read.
// The operator has to delete the lines, and docs/editions.md says so.
type customerRevoker interface {
	RevokeAllForCustomer(ctx context.Context, customerID string) error
}

// StaticDelegations is a fixed set, for tests and for a configuration-file
// deployment that has not moved its grants into the database yet.
type StaticDelegations []Delegation

func (s StaticDelegations) Delegations(context.Context) (*DelegationSet, error) {
	return NewDelegationSet(s), nil
}
