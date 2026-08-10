// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"

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

// StaticDelegations is a fixed set, for tests and for a configuration-file
// deployment that has not moved its grants into the database yet.
type StaticDelegations []Delegation

func (s StaticDelegations) Delegations(context.Context) (*DelegationSet, error) {
	return NewDelegationSet(s), nil
}
