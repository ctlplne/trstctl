// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The custody table is a claim about code, so CI checks it against the code
// (epic B1).
//
// "Private keys never leave your environment" is the kind of sentence that is
// true when it is written and quietly false two releases later. docs/custody.md
// states, per credential kind, who generates the key and whether the control
// plane ever holds it. These tests keep that page tied to the surfaces it
// describes: every kind is listed, the paths that still generate keys in the
// control plane are named as such along with what replaces them, and the CSR
// path that removes one of them is actually wired.

// custodyKinds are the credential kinds the table must account for. Adding a
// credential kind to the product without adding a row here fails the build,
// which is the point: an unlisted kind is an unanswered custody question.
var custodyKinds = []string{
	"ACME leaf",
	"EST leaf",
	"SCEP leaf",
	"CMP leaf",
	"Identity leaf, `subject_csr_pem` supplied",
	"Identity leaf, no CSR, agent-executed target",
	"Identity leaf, no CSR, retained control-plane target",
	"CA root / intermediate",
	"Agent enrollment identity",
	"SSH host / user certificate",
	"SPIFFE X.509-SVID, host-agent Workload API",
	"SPIFFE X.509-SVID, control-plane compatibility Workload API",
	"PKI-as-a-secret",
	"Automated renewal successor, agent-executed target",
	"Automated renewal successor, recorded `subject_csr_pem`",
	"Automated renewal successor, no CSR and retained control-plane target",
	"Ephemeral workload credential",
}

// custodyControlPlaneKeygen are the paths that still generate a subject key
// inside the control plane. Each must be named on the page together with what
// replaces it — a disclosure with no successor is a confession, not a plan.
var custodyControlPlaneKeygen = map[string]string{
	"Identity leaf without a CSR":              "subject_csr_pem",
	"Control-plane compatibility Workload API": "host-agent Workload API",
	"PKI-as-a-secret with only a common name":  "csr_pem",
}

func TestCustodyTableCoversEveryCredentialKind(t *testing.T) {
	t.Parallel()
	custody := read(t, "custody.md")
	for _, kind := range custodyKinds {
		if !strings.Contains(custody, kind) {
			t.Errorf("docs/custody.md has no row for %q; a credential kind with no custody row is an unanswered question about where its key lives", kind)
		}
	}
}

func TestCustodyTableNamesEveryControlPlaneKeygenPathAndItsSuccessor(t *testing.T) {
	t.Parallel()
	custody := read(t, "custody.md")
	for path, successor := range custodyControlPlaneKeygen {
		if !strings.Contains(custody, path) {
			t.Errorf("docs/custody.md does not name the control-plane keygen path %q", path)
			continue
		}
		if !strings.Contains(custody, successor) {
			t.Errorf("docs/custody.md names %q but not what replaces it (%q); disclosing a custody gap without its successor is a confession, not a plan",
				path, successor)
		}
	}
}

// TestSPIFFECustodyRowsFollowBothProductionSockets derives the two table rows
// from the shipped composition roots, not from phrases that happen to occur in
// comments. B3 added a host-local server without deleting the control-plane
// compatibility socket. Collapsing those two runtimes into one row makes either
// "yes" or "no" a lie, depending on which socket the workload dialled.
func TestSPIFFECustodyRowsFollowBothProductionSockets(t *testing.T) {
	t.Parallel()

	agentSupervisor := goFunction(t, "../cmd/trstctl-agent/main.go", "runAgent")
	requireCall(t, agentSupervisor, "runAgentUntilRotation",
		"the production agent must supervise a fresh mTLS session after identity rotation")
	agentRun := goFunction(t, "../cmd/trstctl-agent/main.go", "runAgentUntilRotation")
	requireCall(t, agentRun, "startWorkloadAPI",
		"the production agent must compose the host-local Workload API")
	agentSocket := goFunction(t, "../cmd/trstctl-agent/workloadchannel.go", "startWorkloadAPI")
	requireCall(t, agentSocket, "workloadapi.New",
		"the host listener must be the agent Workload API implementation")
	hostFetch := goFunction(t, "../internal/agent/workloadapi/server.go", "FetchX509SVID")
	requireCallBefore(t, hostFetch, "crypto.GenerateLockedKey", "s.up.FetchWorkloadSVID",
		"the host must generate the SVID key before asking the control plane to sign its public half")

	controlPlaneBuild := goFunction(t, "../internal/server/protocol_mounts.go", "buildSPIFFE")
	requireCall(t, controlPlaneBuild, "spiffe.NewWorkloadAPIServer",
		"the retained control-plane compatibility socket must stay explicit while it exists")
	controlPlaneRun := goFunction(t, "../internal/server/protocol_ssh.go", "RunSPIFFE")
	requireCall(t, controlPlaneRun, "spiffe.ServeWorkloadAPI",
		"the compatibility Workload API must be reachable from the production server composition")

	custody := read(t, "custody.md")
	requireCustodyRow(t, custody, "SPIFFE X.509-SVID, host-agent Workload API", "host agent", "No")
	requireCustodyRow(t, custody, "SPIFFE X.509-SVID, control-plane compatibility Workload API", "control plane", "Yes", "deprecated")
	for _, stale := range []string{"the socket is brain-local today", "Moving the socket to the host agent"} {
		if strings.Contains(custody, stale) {
			t.Errorf("docs/custody.md still says %q even though the host-agent socket is assembled in production", stale)
		}
	}
}

// TestRenewalCustodyRowsFollowTheProductionBranch pins the load-bearing order:
// handleRenew asks whether the target executes on the agent before the fallback
// mint can run. It also follows the queued work to the host executor that makes
// the key. A census-only docs test missed both facts while stale prose stayed
// green.
func TestRenewalCustodyRowsFollowTheProductionBranch(t *testing.T) {
	t.Parallel()

	handleIssue := goFunction(t, "../internal/server/issuance.go", "handleIssue")
	requireCallBefore(t, handleIssue, "d.enqueueHostRenewal", "d.mintServedLeafForTrigger",
		"a no-CSR first issuance for an agent-executed target must branch before the fallback mint")
	handleRenew := goFunction(t, "../internal/server/issuance.go", "handleRenew")
	requireCallBefore(t, handleRenew, "d.dispatchHostRenewal", "d.mintServedLeafForRenewal",
		"agent-executed renewal must branch before any control-plane fallback mint")
	dispatch := goFunction(t, "../internal/server/host_renewal_enqueue.go", "dispatchHostRenewal")
	requireCallBefore(t, dispatch, "d.hostRenewalTargetFor", "d.enqueueHostRenewal",
		"the endpoint.renew job must be selected from the target's executor")
	hostExecutor := goFunction(t, "../internal/agent/relay/hostrenew.go", "runHostRenew")
	requireCall(t, hostExecutor, "crypto.GenerateHostSubjectKey",
		"the queued renewal must terminate in key generation on the serving host")

	custody := read(t, "custody.md")
	requireCustodyRow(t, custody, "Identity leaf, no CSR, agent-executed target", "host agent", "No")
	requireCustodyRow(t, custody, "Identity leaf, no CSR, retained control-plane target", "control plane", "Yes", "deprecated")
	requireCustodyRow(t, custody, "Automated renewal successor, agent-executed target", "host agent", "No")
	requireCustodyRow(t, custody, "Automated renewal successor, recorded `subject_csr_pem`", "requester", "No")
	requireCustodyRow(t, custody, "Automated renewal successor, no CSR and retained control-plane target", "control plane", "Yes", "deprecated")
	for _, stale := range []string{
		"Host-executed renewal is the next piece of work",
		"The four that still say yes",
		"private key is **destroyed, not delivered**",
	} {
		if strings.Contains(custody, stale) {
			t.Errorf("docs/custody.md retains the pre-B2 claim %q", stale)
		}
	}
	if !strings.Contains(custody, "three retained control-plane generators") {
		t.Error("docs/custody.md must state the current generator count; renewal reuses the deprecated no-CSR identity fallback rather than adding a fourth generator")
	}
}

// TestCSRFirstIssuanceIsActuallyWired stops the table from describing a path the
// code does not have. The row that says "no" for a caller-supplied CSR is only
// true if the served surface accepts one and the mint signs it.
func TestCSRFirstIssuanceIsActuallyWired(t *testing.T) {
	t.Parallel()
	for _, want := range []struct{ file, token, why string }{
		{"../internal/api/handlers.go", "SubjectCSRPEM", "the transition request must accept a caller-supplied CSR"},
		{"../internal/api/handlers.go", "validateSubjectCSRPEM", "a malformed CSR must be rejected at the API edge, not in the outbox worker"},
		{"../internal/orchestrator/orchestrator.go", "TransitionWithSubjectCSR", "the CSR must reach the issuance dispatcher on the transition"},
		{"../internal/server/issuance.go", "mintServedLeafFromCSR", "the mint must sign the caller's request instead of generating a key"},
		{"../internal/server/issuance.go", "issuance.server_side_keygen", "the legacy keygen path must record its own deprecation"},
	} {
		body := read(t, want.file)
		if !strings.Contains(body, want.token) {
			t.Errorf("%s does not contain %q: %s", want.file, want.token, want.why)
		}
	}
}

// TestCSRFirstMintReturnsNoKeyMaterial pins the property the custody row depends
// on: the CSR path constructs no private key, so there is nothing to leak,
// wipe, or accidentally encode into a deploy intent.
func TestCSRFirstMintReturnsNoKeyMaterial(t *testing.T) {
	t.Parallel()
	body := read(t, "../internal/server/issuance.go")
	start := strings.Index(body, "func (d *issuanceDispatcher) mintServedLeafFromCSR(")
	if start < 0 {
		t.Fatal("mintServedLeafFromCSR is gone; the custody table's CSR row depends on it")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("cannot delimit mintServedLeafFromCSR")
	}
	fn := body[start : start+end]
	for _, banned := range []string{"GenerateLockedKey", "PrivateKeyPEM", "KeyPEM:"} {
		if strings.Contains(fn, banned) {
			t.Errorf("mintServedLeafFromCSR references %q; the CSR path must not create or return subject key material — that is the whole custody difference", banned)
		}
	}
}

// TestLimitationsNoLongerClaimsTheIdentityAPIHasNoCSRInput keeps the served-state
// page from carrying a limitation that has been fixed. A stale limitation is as
// misleading as a missing one, just in the other direction.
func TestLimitationsNoLongerClaimsTheIdentityAPIHasNoCSRInput(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	if strings.Contains(limitations, "direct identity API intentionally has no CSR input at all") {
		t.Error("docs/limitations.md still says the direct identity API has no CSR input; it accepts subject_csr_pem now")
	}
	if !strings.Contains(limitations, "subject_csr_pem") {
		t.Error("docs/limitations.md must record the CSR-first issuance path")
	}
}

// goFunction parses the named production function and returns its AST. These
// guards intentionally fail if composition moves: the custody page then needs
// to be re-proved against the new root instead of remaining green on keywords.
func goFunction(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s has no production function %s; re-prove the custody claim at its new composition root", file, name)
	return nil
}

func requireCall(t *testing.T, fn *ast.FuncDecl, want, why string) {
	t.Helper()
	if len(callPositions(fn, want)) == 0 {
		t.Errorf("%s does not call %s: %s", fn.Name.Name, want, why)
	}
}

func requireCallBefore(t *testing.T, fn *ast.FuncDecl, first, second, why string) {
	t.Helper()
	firstAt := callPositions(fn, first)
	secondAt := callPositions(fn, second)
	if len(firstAt) == 0 || len(secondAt) == 0 {
		t.Errorf("%s calls %s at %v and %s at %v: %s", fn.Name.Name, first, firstAt, second, secondAt, why)
		return
	}
	if firstAt[0] >= secondAt[0] {
		t.Errorf("%s calls %s after %s: %s", fn.Name.Name, first, second, why)
	}
}

func callPositions(fn *ast.FuncDecl, want string) []token.Pos {
	var positions []token.Pos
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && callName(call.Fun) == want {
			positions = append(positions, call.Pos())
		}
		return true
	})
	return positions
}

func callName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := callName(value.X)
		if prefix == "" {
			return value.Sel.Name
		}
		return prefix + "." + value.Sel.Name
	case *ast.CallExpr:
		return callName(value.Fun)
	default:
		return ""
	}
}

func requireCustodyRow(t *testing.T, body, label string, claims ...string) {
	t.Helper()
	prefix := "| " + label + " |"
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, claim := range claims {
			if !strings.Contains(line, claim) {
				t.Errorf("custody row %q does not say %q: %s", label, claim, line)
			}
		}
		return
	}
	t.Errorf("docs/custody.md has no exact row for %q", label)
}
