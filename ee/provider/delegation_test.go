// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"strings"
	"testing"
)

func opr(id, email string) Operator { return Operator{ID: id, Email: email, Role: OperatorOperator} }

// The acceptance criterion: cross-customer action is refused fail-closed.
func TestAnOperatorCannotActOnACustomerTheyWereNotDelegated(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "bank-a", Operations: []Operation{OpSuspend}},
	})
	if err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpSuspend); err != nil {
		t.Fatalf("a delegated operation was refused: %v", err)
	}
	err := s.Authorize(opr("op-1", "a@provider"), "bank-b", OpSuspend)
	if err == nil {
		t.Fatal("an operator suspended a customer they were never delegated.\n\n" +
			"That is one customer's operator reaching into another customer's tenancy — the " +
			"single worst thing a provider plane can do.")
	}
	if !strings.Contains(err.Error(), "not delegated customer") {
		t.Errorf("the refusal does not name the missing customer delegation: %v", err)
	}
}

// An empty delegation set must permit NOTHING. Reading it as "everything" is
// the unscoped access this mechanism replaces.
func TestAnEmptyDelegationSetPermitsNothing(t *testing.T) {
	t.Parallel()
	for _, s := range []*DelegationSet{NewDelegationSet(nil), nil} {
		if err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpRead); err == nil {
			t.Fatal("an empty delegation set permitted an action.\n\n" +
				"Empty must mean nothing is permitted. The opposite reading gives every " +
				"authenticated operator the union of every customer's risk.")
		}
	}
}

// Being delegated a customer is not being delegated every operation on it.
func TestDelegationIsPerOperationNotJustPerCustomer(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "bank-a", Operations: []Operation{OpRead, OpProvision}},
	})
	if err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpProvision); err != nil {
		t.Fatalf("a granted operation was refused: %v", err)
	}
	err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpOffboard)
	if err == nil {
		t.Fatal("an operator trusted to PROVISION was allowed to OFFBOARD.\n\n" +
			"One creates a tenancy and one destroys it. Folding them into a single " +
			"per-customer grant means onboarding access implies the ability to erase.")
	}
	if !strings.Contains(err.Error(), "blast radii") {
		t.Errorf("the refusal does not explain why the operations are separate: %v", err)
	}
}

// The two refusal reasons must be distinguishable: they need different people
// to fix them.
func TestAMissingCustomerAndAMissingOperationAreDifferentRefusals(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "bank-a", Operations: []Operation{OpRead}},
	})
	noCustomer := s.Authorize(opr("op-1", "a@provider"), "bank-b", OpRead)
	noOperation := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpOffboard)
	if noCustomer == nil || noOperation == nil {
		t.Fatal("expected both to be refused")
	}
	if noCustomer.Error() == noOperation.Error() {
		t.Fatal("a missing customer delegation and a missing operation grant read identically. " +
			"An operator cannot tell which to ask for, and \"forbidden\" alone sends them to the " +
			"wrong person")
	}
}

// A delegation missing either side grants nothing, and must not become a row
// that reads like access somebody has.
func TestAHalfEmptyDelegationGrantsNothing(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "", CustomerID: "bank-a", Operations: []Operation{OpOffboard}},
		{OperatorID: "op-1", CustomerID: "", Operations: []Operation{OpOffboard}},
	})
	if err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpOffboard); err == nil {
		t.Fatal("a delegation missing one side granted access. A half-empty grant row reads like " +
			"access somebody has, and here it would have granted the destructive operation")
	}
}

// An unidentified operator is delegated nothing, even if a delegation names an
// empty operator id.
func TestAnUnidentifiedOperatorIsDelegatedNothing(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "bank-a", Operations: []Operation{OpRead}},
	})
	if err := s.Authorize(Operator{}, "bank-a", OpRead); err == nil {
		t.Fatal("an operator with no id was authorized")
	}
	if err := s.Authorize(opr("op-1", "a@provider"), "", OpRead); err == nil {
		t.Fatal("an action naming no customer was authorized; it cannot be scoped to anything")
	}
}

// CustomersFor must not hand back a slice a caller can widen.
func TestCustomersForCannotBeUsedToWidenScope(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "bank-a", Operations: []Operation{OpRead}},
	})
	got := s.CustomersFor("op-1")
	if len(got) != 1 || got[0] != "bank-a" {
		t.Fatalf("customers = %v", got)
	}
	got[0] = "bank-b"
	if err := s.Authorize(opr("op-1", "a@provider"), "bank-b", OpRead); err == nil {
		t.Fatal("writing into the returned slice widened the operator's real scope")
	}
}

// There is deliberately no wildcard: it would be indistinguishable from the
// unscoped access this replaces.
func TestThereIsNoWildcardCustomer(t *testing.T) {
	t.Parallel()
	s := NewDelegationSet([]Delegation{
		{OperatorID: "op-1", CustomerID: "*", Operations: Operations},
	})
	if err := s.Authorize(opr("op-1", "a@provider"), "bank-a", OpOffboard); err == nil {
		t.Fatal("\"*\" was treated as a wildcard customer.\n\n" +
			"A wildcard delegation is indistinguishable from the unscoped access this mechanism " +
			"replaces, and it would be reached for on the first busy day.")
	}
}
