// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// These destinations used to share case lines in deliver and reach their
// handlers through hop functions that picked one by elimination: anything that
// was not LDAP went to SCIM, anything that was not a legal hold to report
// expiry, anything not named to the migration appliance's issuance, and the
// email challenge through the DNS-01 hop. A destination added to one of those
// case lines but not to its hop would have run another destination's external
// action instead of failing.
var deliverOwnHandlers = []struct {
	destination string
	constant    string // the identifier deliver's case names
	handler     string // the call that case makes
	reached     string // what that handler answers on an unconfigured dispatcher
}{
	{orchestrator.DestinationMigrationApplianceIssue, "DestinationMigrationApplianceIssue", "d.handleMigrationApplianceIssue", "appliance migration issuance is not configured"},
	{orchestrator.DestinationAttackPathValidate, "DestinationAttackPathValidate", "d.handleAttackPathValidate", "attack-path validation is not configured"},
	{orchestrator.DestinationOAuthProviderAction, "DestinationOAuthProviderAction", "d.handleOAuthProviderAction", "OAuth provider actions are not configured"},
	{orchestrator.DestinationScanAnnotation, "DestinationScanAnnotation", "d.handleScanAnnotation", "scan annotations are not configured"},
	{destinationACMEEmailChallenge, "destinationACMEEmailChallenge", "d.deliverACMEEmailChallenge", "acme email challenges are not configured"},
	{orchestrator.DestinationSCIMWriteback, "DestinationSCIMWriteback", "d.scimWriteback.Deliver", "SCIM directory writeback is not configured"},
	{orchestrator.DestinationLDAPWriteback, "DestinationLDAPWriteback", "d.ldapWriteback.Deliver", "LDAP directory writeback is not configured"},
	{store.ComplianceReportArtifactExpiryDestination, "ComplianceReportArtifactExpiryDestination", "d.reportExpiry.Deliver", "report retention is not configured"},
	{store.ArchiveLegalHoldDestination, "ArchiveLegalHoldDestination", "d.archiveHolds.Deliver", "archive legal holds are not configured"},
}

func TestDeliverSendsEachDestinationToItsOwnHandler(t *testing.T) {
	d := &issuanceDispatcher{}
	for _, tc := range deliverOwnHandlers {
		err := d.deliver(context.Background(), orchestrator.Message{Destination: tc.destination, Payload: []byte(`{}`)})
		if err == nil || !strings.Contains(err.Error(), tc.reached) {
			t.Errorf("%s reached %v; want its own handler, which answers %q", tc.destination, err, tc.reached)
		}
	}
	// A destination nobody listed is refused rather than run by a neighbor's
	// handler.
	err := d.deliver(context.Background(), orchestrator.Message{Destination: "control_plane.unlisted", Payload: []byte(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "unsupported first-party outbox destination") {
		t.Fatalf("an unlisted destination: %v; want the unsupported-destination error", err)
	}

	// Each is named by a case of its own whose body calls its handler, so a
	// destination added beside it can never inherit its handler.
	file, err := parser.ParseFile(token.NewFileSet(), "issuance.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cases []*ast.CaseClause
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "deliver" || fn.Recv == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			if sw, ok := stmt.(*ast.SwitchStmt); ok && types.ExprString(sw.Tag) == "m.Destination" {
				for _, c := range sw.Body.List {
					cases = append(cases, c.(*ast.CaseClause))
				}
			}
		}
	}
	if len(cases) == 0 {
		t.Fatal("deliver's switch on m.Destination was not found in issuance.go")
	}
	for _, tc := range deliverOwnHandlers {
		var clause *ast.CaseClause
		for _, c := range cases {
			for _, e := range c.List {
				if name := types.ExprString(e); name == tc.constant || strings.HasSuffix(name, "."+tc.constant) {
					clause = c
				}
			}
		}
		if clause == nil {
			t.Errorf("deliver has no case for %s", tc.constant)
			continue
		}
		if len(clause.List) != 1 {
			names := make([]string, 0, len(clause.List))
			for _, e := range clause.List {
				names = append(names, types.ExprString(e))
			}
			t.Errorf("%s shares its case with %s; give it a case of its own", tc.constant, strings.Join(names, ", "))
		}
		calls := false
		ast.Inspect(&ast.BlockStmt{List: clause.Body}, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && types.ExprString(call.Fun) == tc.handler {
				calls = true
			}
			return true
		})
		if !calls {
			t.Errorf("the case for %s does not call %s directly", tc.constant, tc.handler)
		}
	}
}
