// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"os"
	"strings"
	"testing"
)

// L1: the delegation rule must be REACHED, not merely written.
//
// delegation.go and its unit tests existed for a full session while every
// served provider route still authorised any authenticated operator against any
// customer, because nothing constructed a set and nothing consulted one. That
// is the exact defect class this backlog exists to remove, and a rule is only
// as real as the call site that runs it.
func TestTheDelegationSourceIsWiredIntoTheBinary(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../cmd/trstctl/ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "eeprovider.NewPGDelegationSource(") {
		t.Fatal("ee_attach.go never constructs a delegation source.\n\n" +
			"Without one the provider handler is built with Delegations nil. That refuses fail-closed " +
			"rather than leaking, so nothing would break loudly — the plane would simply be " +
			"permanently unusable while the delegation code sat unused in the tree.")
	}
	if !strings.Contains(string(src), "Delegations: delegations") {
		t.Fatal("the delegation source is constructed but never passed to eeprovider.Config; " +
			"a source the handler does not hold is a source no request consults")
	}
}

// The grant table has to exist for the source to read.
func TestTheDelegationMigrationShipsWithTheSchema(t *testing.T) {
	t.Parallel()
	sql, err := os.ReadFile("../../internal/store/migrations/0125_provider_operator_delegations.sql")
	if err != nil {
		t.Fatalf("the delegation migration is missing, so the durable source queries a table that "+
			"does not exist: %v", err)
	}
	body := string(sql)
	if !strings.Contains(body, "provider_operator_delegations") {
		t.Fatal("the migration does not create provider_operator_delegations")
	}
	// The column is deliberately NOT named tenant_id: see the migration's own
	// comment. Renaming it would pull the table into the tenant RLS fence,
	// where the provider plane could not read it — the read happens before any
	// tenant is selected.
	if strings.Contains(body, "tenant_id uuid") || strings.Contains(body, "tenant_id  ") {
		t.Fatal("the grant table declares a tenant_id column. It would then be inventoried as a " +
			"tenant table requiring RLS, and under tenant RLS the provider plane could never read " +
			"it — the fail-closed check would refuse every operator, always.")
	}
	if !strings.Contains(body, "customer_tenant_id") {
		t.Fatal("the grant table does not name the customer a grant is over")
	}
}

// A nil source is a refusal, never an absence of opinion.
func TestANilDurableSourceRefusesRatherThanReturningAnEmptyAllowlist(t *testing.T) {
	t.Parallel()
	if got := NewPGDelegationSource(nil); got != nil {
		t.Fatal("a delegation source was constructed with no database; it would answer queries " +
			"against a store it does not have")
	}
	var src *PGDelegationSource
	if _, err := src.Delegations(t.Context()); err == nil {
		t.Fatal("an unbacked delegation source returned a set instead of an error.\n\n" +
			"An empty set and an unreadable store are different facts. Service.authorize refuses " +
			"on both, but returning a SET here would let a future caller treat 'no grants found' " +
			"as an authoritative answer drawn from a store that was never there.")
	}
}

// Granting refuses a half-named delegation rather than storing it.
func TestAHalfNamedGrantIsRefusedRatherThanStored(t *testing.T) {
	t.Parallel()
	var src *PGDelegationSource
	if err := src.Grant(t.Context(), Delegation{OperatorID: "op-1"}, "admin"); err == nil {
		t.Fatal("a delegation with no customer was accepted; a row naming only an operator reads " +
			"like access somebody has")
	}
}

// The grant command's vocabulary is closed.
//
// A typo'd operation stored as-is would authorise nothing, and the person who
// ran the command would see "granted" and be refused later with no way to
// connect the two.
func TestGrantRefusesAnOperationOutsideTheVocabulary(t *testing.T) {
	t.Parallel()
	if _, err := parseDelegatedOperations("suspend,offbaord"); err == nil {
		t.Fatal("a misspelled operation was accepted; the grant would read as authority the " +
			"operator does not have")
	}
	ops, err := parseDelegatedOperations("suspend, offboard ")
	if err != nil {
		t.Fatalf("a valid list was refused: %v", err)
	}
	if len(ops) != 2 || ops[0] != OpSuspend || ops[1] != OpOffboard {
		t.Fatalf("parsed %v, want [suspend offboard]", ops)
	}
}

// A grant with no operations is refused rather than stored.
func TestAGrantWithNoOperationsIsRefused(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", ",,"} {
		if _, err := parseDelegatedOperations(raw); err == nil {
			t.Fatalf("operations %q produced a grant; an empty grant is a row in the table that "+
				"reads like access somebody has", raw)
		}
	}
}

// The bootstrap path exists. Without it the delegation gate is unliftable and
// the provider plane is permanently refusing — safe, and useless.
func TestTheGrantCommandIsReachableFromTheBinary(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../cmd/trstctl/ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "eeprovider.RunGrantCommand(") {
		t.Fatal("nothing dispatches provider-grant.\n\n" +
			"The plane refuses every customer-scoped action until operators hold grants. With no " +
			"way to create one, that refusal can never be lifted and would be reported as the " +
			"provider plane being broken.")
	}
	main, err := os.ReadFile("../../cmd/trstctl/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "eeLocalCommand(") {
		t.Fatal("main never calls eeLocalCommand, so the subcommand is defined and unreachable")
	}
}
