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
// expiry, anything not named to the migration appliance's issuance, anything
// that was neither a revocation publish nor a CRL publication to the probe
// request, and the email challenge through the DNS-01 hop. A destination added to one of those
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
	{"revocation.publish", `"revocation.publish"`, "d.handleRevoke", "revocation intent has no exact identity"},
	{store.CertificateCRLPublicationDestination, "CertificateCRLPublicationDestination", "d.handleCertificateCRLPublication", "requested certificate CRL authority is not served"},
	{orchestrator.DestinationRevocationProbeRequest, "DestinationRevocationProbeRequest", "d.handleRevocationProbeRequest", "revocation health probing is not configured"},
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
	want := make([]ownCase, 0, len(deliverOwnHandlers))
	for _, tc := range deliverOwnHandlers {
		want = append(want, ownCase{tc.constant, tc.handler})
	}
	assertOwnCases(t, "issuance.go", "deliver", "m.Destination", want)
}

// ownCase is a switch case that must name one value and call one handler.
type ownCase struct {
	constant string // the identifier (or literal) the case names
	handler  string // the call its body makes
}

// assertOwnCases checks that fn's switch on tag gives each wanted value a case
// of its own whose body calls its handler directly.
func assertOwnCases(t *testing.T, path, fn, tag string, want []ownCase) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cases []*ast.CaseClause
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Name.Name != fn || d.Recv == nil {
			continue
		}
		ast.Inspect(d.Body, func(n ast.Node) bool {
			if sw, ok := n.(*ast.SwitchStmt); ok && sw.Tag != nil && types.ExprString(sw.Tag) == tag {
				for _, c := range sw.Body.List {
					cases = append(cases, c.(*ast.CaseClause))
				}
			}
			return true
		})
	}
	if len(cases) == 0 {
		t.Fatalf("%s's switch on %s was not found in %s", fn, tag, path)
	}
	for _, w := range want {
		var clause *ast.CaseClause
		for _, c := range cases {
			for _, e := range c.List {
				if name := types.ExprString(e); name == w.constant || strings.HasSuffix(name, "."+w.constant) {
					clause = c
				}
			}
		}
		if clause == nil {
			t.Errorf("%s has no case for %s", fn, w.constant)
			continue
		}
		if len(clause.List) != 1 {
			names := make([]string, 0, len(clause.List))
			for _, e := range clause.List {
				names = append(names, types.ExprString(e))
			}
			t.Errorf("%s shares its case with %s; give it a case of its own", w.constant, strings.Join(names, ", "))
		}
		calls := false
		ast.Inspect(&ast.BlockStmt{List: clause.Body}, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && types.ExprString(call.Fun) == w.handler {
				calls = true
			}
			return true
		})
		if !calls {
			t.Errorf("the case for %s does not call %s directly", w.constant, w.handler)
		}
	}
}
