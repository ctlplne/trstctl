// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"fmt"
	"strings"
)

// Per-customer scoped delegation for provider operators (epic L1).
//
// Authentication answers WHO an operator is. It does not answer WHICH
// CUSTOMERS they may touch, and until this file existed the answer was "all of
// them": an authenticated operator with any role could provision, suspend, or
// offboard any tenant in the estate.
//
// That is the wrong shape for a provider plane. A managed-service provider's
// staff are partitioned by customer — the engineer who runs one bank's tenancy
// has no business suspending another's — and a plane that cannot express the
// partition forces every operator to hold the union of every customer's risk.
//
// The rule is FAIL CLOSED on both axes. An operator acts only on a customer
// explicitly delegated to them, and only through an operation explicitly
// granted. A missing delegation is a refusal, never a default-allow, because
// the failure mode of the opposite reading is one customer's operator reaching
// into another customer's tenancy — the single worst thing a provider plane can
// do.

// Operation names a provider-plane action that can be delegated separately.
//
// Separated rather than folded into the role because they carry different
// blast radii: provisioning creates, suspending interrupts a live service, and
// offboarding DESTROYS. An operator trusted to onboard is not automatically
// trusted to erase.
type Operation string

const (
	OpProvision  Operation = "provision"
	OpSuspend    Operation = "suspend"
	OpResume     Operation = "resume"
	OpOffboard   Operation = "offboard"
	OpBreakGlass Operation = "break-glass"
	OpRead       Operation = "read"
)

// Operations is every delegable operation, so the API enum, the console and the
// checker read one list rather than three that drift.
var Operations = []Operation{OpRead, OpProvision, OpSuspend, OpResume, OpOffboard, OpBreakGlass}

// Delegation is one operator's grant over one customer.
//
// CustomerID is a specific tenant. There is deliberately NO wildcard: a
// wildcard delegation is indistinguishable from the unscoped access this whole
// mechanism replaces, and it would be reached for on the first busy day.
type Delegation struct {
	OperatorID string
	CustomerID string
	Operations []Operation
}

// DelegationSet is the delegations in force, keyed by operator then customer.
type DelegationSet struct {
	byOperator map[string]map[string][]Operation
}

// NewDelegationSet indexes delegations for checking.
func NewDelegationSet(ds []Delegation) *DelegationSet {
	out := &DelegationSet{byOperator: map[string]map[string][]Operation{}}
	for _, d := range ds {
		op := strings.TrimSpace(d.OperatorID)
		cust := strings.TrimSpace(d.CustomerID)
		if op == "" || cust == "" {
			// A delegation missing either side grants nothing. Storing it would
			// put a row in the grant table that reads like access somebody has.
			continue
		}
		if out.byOperator[op] == nil {
			out.byOperator[op] = map[string][]Operation{}
		}
		out.byOperator[op][cust] = append(out.byOperator[op][cust], d.Operations...)
	}
	return out
}

// Authorize decides whether an operator may perform op against customerID.
//
// Both axes must be satisfied explicitly. The error says which one failed,
// because "forbidden" alone leaves an operator unable to tell a missing
// customer delegation from a missing operation grant — and those need different
// people to fix them.
func (s *DelegationSet) Authorize(operator Operator, customerID string, op Operation) error {
	if s == nil || len(s.byOperator) == 0 {
		return fmt.Errorf(
			"provider: no delegations are configured, so no operator may act on any customer. " +
				"An empty delegation set means NOTHING is permitted — reading it as \"everything\" " +
				"is how one customer's operator reaches into another's tenancy")
	}
	id := strings.TrimSpace(operator.ID)
	if id == "" {
		return fmt.Errorf("provider: an unidentified operator cannot be delegated anything")
	}
	cust := strings.TrimSpace(customerID)
	if cust == "" {
		return fmt.Errorf("provider: no customer named; a provider action must say which tenancy it touches")
	}
	perCustomer, ok := s.byOperator[id]
	if !ok {
		return fmt.Errorf("provider: operator %s has no customer delegations at all", operator.Email)
	}
	granted, ok := perCustomer[cust]
	if !ok {
		// The cross-customer refusal. This is the one that matters.
		return fmt.Errorf(
			"provider: operator %s is not delegated customer %s. Cross-customer action is refused "+
				"fail-closed: an operator's reach is the customers explicitly granted to them, "+
				"never every customer they can name", operator.Email, cust)
	}
	for _, g := range granted {
		if g == op {
			return nil
		}
	}
	return fmt.Errorf(
		"provider: operator %s is delegated customer %s but not the %q operation. Provisioning, "+
			"suspending and offboarding carry different blast radii — one creates, one interrupts "+
			"a live service, one destroys — so being trusted with one is not being trusted with "+
			"the others", operator.Email, cust, op)
}

// CustomersFor lists the customers an operator may act on, for the access
// console. Returns a copy so a caller cannot widen its own scope by mutating
// the returned slice.
func (s *DelegationSet) CustomersFor(operatorID string) []string {
	if s == nil {
		return nil
	}
	perCustomer := s.byOperator[strings.TrimSpace(operatorID)]
	out := make([]string, 0, len(perCustomer))
	for cust := range perCustomer {
		out = append(out, cust)
	}
	return out
}
