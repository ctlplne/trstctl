// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type negativeProofReference struct {
	Test           string
	RequiredTokens []string
}

type highRiskVerdictProof struct {
	Verdict       string
	NegativeTests []negativeProofReference
	Console       string
	ConsoleTokens []string
}

// These are the three cross-surface claims that exposed AUD-57. Merely naming
// their production writer is insufficient: each must retain an assembled
// negative proof and an operator-visible console rendering. References are
// declaration-checked below, so renaming or deleting a proof fails CI.
var highRiskVerdictProofs = []highRiskVerdictProof{
	{
		Verdict: "OutboxReconciliationConflict.status",
		NegativeTests: []negativeProofReference{
			{
				Test: "internal/server/outbox_reconciliation_conflict_served_test.go:TestBuildQuarantinesHistoricalOutboxConflictAndServesRecoveryIncidentAUD97",
				RequiredTokens: []string{
					"!bytes.Equal(retained, oldPayload)",
					"unrelatedRows != 1",
					"http.StatusForbidden",
					`"identity_id"`,
				},
			},
		},
		Console: "web/src/pages/incidents/OutboxRecoveryPanel.tsx:OutboxRecoveryPanel",
		ConsoleTokens: []string{
			"conflict.status",
			"conflict.source_event_id",
			"conflict.existing_payload_sha256",
			"conflict.candidate_payload_sha256",
		},
	},
	{
		Verdict: "FleetReissuanceBatch.status",
		NegativeTests: []negativeProofReference{
			{
				Test: "internal/server/incident_fleet_reissuance_served_test.go:TestServedFleetReissuanceIsDurableCanaryFirstAcrossPauseHaltResumeAndRestart",
				RequiredTokens: []string{
					"later batch was published before canary verification",
					"failed canary published batch 2",
					`run.Status != "halted"`,
				},
			},
		},
		Console: "web/src/pages/incidents/FleetReissuanceParts.tsx:FleetReissuanceTable",
		ConsoleTokens: []string{
			"run.status",
			"run.health_gates",
			"run.halted_reason",
		},
	},
	{
		Verdict: "DRDrill.outcome",
		NegativeTests: []negativeProofReference{
			{
				Test: "internal/server/backup_test.go:TestScheduledRestoreDrillRestoresFullDeliveredSetAndRecoveredRuntime",
				RequiredTokens: []string{
					"ArtifactsRestored",
					"att.StoreHealthy",
					"Remove one required delivered",
				},
			},
			{
				Test:           "internal/backup/drill_test.go:TestEventOnlyReplayCannotAttestFullRestore",
				RequiredTokens: []string{"event-only replay claimed the full backup set restored"},
			},
			{
				Test:           "internal/backup/drill_test.go:TestUnhealthyRecoveredRuntimeCannotAttestRestore",
				RequiredTokens: []string{"unhealthy recovered signer outcome"},
			},
		},
		Console: "web/src/components/DRPosturePanel.tsx:DRPosturePanel",
		ConsoleTokens: []string{
			"last_drill.outcome",
			`last_drill.outcome === "restored"`,
			"last_drill.artifacts_restored",
			"last_drill.detail",
		},
	},
	{
		Verdict: "MDMTraceStep.outcome",
		NegativeTests: []negativeProofReference{
			{
				Test:           "internal/server/mdm_served_test.go:TestServedDeviceTraceDoesNotInferSuccessFromCorrelationIDs",
				RequiredTokens: []string{"trace inferred", "correlation IDs alone"},
			},
			{
				Test:           "internal/server/mdm_poller_served_test.go:TestServedMDMPollerProvesExactIntuneCertificateInstallation",
				RequiredTokens: []string{"wrong-serial correlation", "CertificatesByRAPolicy"},
			},
			{
				Test:           "internal/server/mdm_poller_served_test.go:TestServedMDMPollerProvesJamfCertificateInstallationAndFailure",
				RequiredTokens: []string{"CERTIFICATES", "revoked"},
			},
			{
				Test:           "internal/server/mdm_served_test.go:TestServedDeviceTraceRetainsPreIssuanceChallengeFailure",
				RequiredTokens: []string{"challenge"},
			},
			{
				Test:           "internal/server/mdm_served_test.go:TestServedDeviceTraceMarksOfflineRenewalAsUnknownWithRemediation",
				RequiredTokens: []string{"bring the device online", "renewing"},
			},
		},
		Console: "web/src/components/MDMDevicesPanel.tsx:MDMDevicesPanel",
		ConsoleTokens: []string{
			"api.mdmDeviceTrace",
			"trace.data.trace.steps",
			"step.outcome",
			"step.detail",
			"trace.error",
		},
	},
}

func TestHighRiskVerdictsRetainNegativeProofAndConsoleEvidence(t *testing.T) {
	t.Parallel()
	bound := make(map[string]bool, len(servedEvidenceBindings))
	for _, binding := range servedEvidenceBindings {
		bound[binding.Schema+"."+binding.Field] = true
	}
	for _, proof := range highRiskVerdictProofs {
		if !bound[proof.Verdict] {
			t.Errorf("high-risk verdict %s has proof but no generated-contract evidence binding", proof.Verdict)
		}
		if len(proof.NegativeTests) == 0 {
			t.Errorf("high-risk verdict %s has no negative assembled proof", proof.Verdict)
		}
		for _, ref := range proof.NegativeTests {
			if failure := validateNegativeTestReference(ref); failure != "" {
				t.Errorf("high-risk verdict %s %s", proof.Verdict, failure)
			}
		}
		if failure := validateConsoleReference(proof.Console, proof.ConsoleTokens); failure != "" {
			t.Errorf("high-risk verdict %s %s", proof.Verdict, failure)
		}
	}
}

func validateNegativeTestReference(ref negativeProofReference) string {
	parts := strings.SplitN(ref.Test, ":", 2)
	if len(parts) != 2 || !strings.HasSuffix(parts[0], "_test.go") || !strings.HasPrefix(parts[1], "Test") {
		return "must name an exact Go test declaration, got " + strconv.Quote(ref.Test)
	}
	body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(parts[0])))
	if err != nil {
		return "names missing negative proof " + strconv.Quote(ref.Test) + ": " + err.Error()
	}
	for _, token := range ref.RequiredTokens {
		if !strings.Contains(string(body), token) {
			return "negative proof " + strconv.Quote(ref.Test) + " lost semantic assertion token " + strconv.Quote(token)
		}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, parts[0], body, 0)
	if err != nil {
		return "cannot parse negative proof " + strconv.Quote(ref.Test) + ": " + err.Error()
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != parts[1] {
			continue
		}
		if testBodyCanSkip(fn.Body) && !testBodyHasShortModeGuard(fn.Body) {
			return "negative proof " + strconv.Quote(ref.Test) + " can skip; assembled truth proofs must fail or pass"
		}
		return ""
	}
	return "names no test declaration " + strconv.Quote(parts[1]) + " in " + strconv.Quote(parts[0])
}

func testBodyCanSkip(body *ast.BlockStmt) bool {
	canSkip := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
			canSkip = true
			return false
		}
		return true
	})
	return canSkip
}

func testBodyHasShortModeGuard(body *ast.BlockStmt) bool {
	hasGuard := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, receiverOK := sel.X.(*ast.Ident)
		if receiverOK && ident.Name == "testing" && sel.Sel.Name == "Short" {
			hasGuard = true
			return false
		}
		return true
	})
	return hasGuard
}

func validateConsoleReference(reference string, requiredTokens []string) string {
	parts := strings.SplitN(reference, ":", 2)
	if len(parts) != 2 || (!strings.HasSuffix(parts[0], ".tsx") && !strings.HasSuffix(parts[0], ".ts")) {
		return "must name an exact production console symbol, got " + strconv.Quote(reference)
	}
	if strings.Contains(parts[0], "/__tests__/") || strings.HasSuffix(parts[0], ".test.tsx") || strings.HasSuffix(parts[0], ".test.ts") {
		return "points at test-only console source " + strconv.Quote(parts[0])
	}
	body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(parts[0])))
	if err != nil {
		return "names missing console source " + strconv.Quote(parts[0]) + ": " + err.Error()
	}
	declaration := regexp.MustCompile(`(?m)(?:export\s+)?function\s+` + regexp.QuoteMeta(parts[1]) + `\s*\(`)
	if !declaration.Match(body) {
		return "names no console declaration " + strconv.Quote(parts[1]) + " in " + strconv.Quote(parts[0])
	}
	for _, token := range requiredTokens {
		if !strings.Contains(string(body), token) {
			return "console " + strconv.Quote(reference) + " no longer renders required evidence token " + strconv.Quote(token)
		}
	}
	return ""
}

// consoleSuccessEvidenceValues is a deliberate review list for the shared
// console vocabulary. Adding a green status to statusVocab.ts is a truth claim,
// so it must arrive with a short statement of the fact that licenses green.
var consoleSuccessEvidenceValues = map[string]string{
	"agentStatus.online":             "a current agent heartbeat was observed",
	"certificateStatus.active":       "the certificate read model says active rather than revoked or superseded",
	"deliveryStatus.delivered":       "the connector receipt records target mutation; verification remains a distinct value",
	"deliveryStatus.dry_run_planned": "the relay contacted the target and returned a zero-write mutation plan",
	"deliveryStatus.rolled_back":     "the relay reported that it rebound the target to the predecessor object",
	"expiryBands.healthy":            "a parsed expiry is more than ninety days away",
	"lifecycleStatus.deployed":       "the event-sourced lifecycle records deployment",
	"lifecycleStatus.issued":         "the event-sourced lifecycle records issuance",
}

func TestConsoleSuccessLabelsAreEvidenceReviewed(t *testing.T) {
	t.Parallel()
	body := read(t, "../web/src/lib/statusVocab.ts")
	registryPattern := regexp.MustCompile(`^export const ([A-Za-z0-9_]+):`)
	valuePattern := regexp.MustCompile(`^  ([A-Za-z0-9_]+): \{$`)
	actual := map[string]bool{}
	registry, value := "", ""
	for _, line := range strings.Split(body, "\n") {
		if match := registryPattern.FindStringSubmatch(line); match != nil {
			registry, value = match[1], ""
			continue
		}
		if match := valuePattern.FindStringSubmatch(line); match != nil {
			value = match[1]
			continue
		}
		if strings.Contains(line, `tone: "success"`) && registry != "" && value != "" {
			actual[registry+"."+value] = true
		}
	}
	if len(actual) == 0 {
		t.Fatal("console success-label scan found no central vocabulary entries; parser has drifted")
	}
	for value := range actual {
		if strings.TrimSpace(consoleSuccessEvidenceValues[value]) == "" {
			t.Errorf("console success label %s has no reviewed evidence predicate; register the fact that licenses green", value)
		}
	}
	for value := range consoleSuccessEvidenceValues {
		if !actual[value] {
			t.Errorf("reviewed console success label %s no longer exists; remove or update the stale review entry", value)
		}
	}
	for _, dishonest := range []struct {
		Value          string
		RequiredLabel  string
		ForbiddenGreen string
	}{
		{"config_validated", "target.not.contacted", `tone: "success"`},
		{"rollback_recorded", "not.executed", `tone: "success"`},
	} {
		start := strings.Index(body, "  "+dishonest.Value+": {")
		if start < 0 {
			t.Errorf("console honesty value %s disappeared", dishonest.Value)
			continue
		}
		end := strings.Index(body[start+1:], "\n  }")
		if end < 0 {
			t.Errorf("console honesty value %s has an unparseable descriptor", dishonest.Value)
			continue
		}
		descriptor := body[start : start+1+end]
		if !strings.Contains(descriptor, dishonest.RequiredLabel) {
			t.Errorf("console honesty value %s lost operator limitation %q", dishonest.Value, dishonest.RequiredLabel)
		}
		if strings.Contains(descriptor, dishonest.ForbiddenGreen) {
			t.Errorf("console honesty value %s is green even though its label says the target action did not happen", dishonest.Value)
		}
	}
}
