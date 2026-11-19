// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryErrorResponsesSanitizeHistoricalRowsAUD71(t *testing.T) {
	t.Parallel()
	secret := "trst_" + strings.Repeat("s", 64)
	raw := "CT get-sth returned 503; Authorization: Bearer " + secret

	run := toDiscoveryRunResponse(store.DiscoveryRun{Error: raw})
	if !strings.Contains(run.Error, "503") || strings.Contains(run.Error, secret) {
		t.Fatalf("run error is not safely actionable: %q", run.Error)
	}

	monitoring := toDiscoveryMonitoringSource(store.DiscoveryMonitoringSource{LastRunError: raw})
	if !strings.Contains(monitoring.LastRunError, "503") || strings.Contains(monitoring.LastRunError, secret) {
		t.Fatalf("monitoring error is not safely actionable: %q", monitoring.LastRunError)
	}
}

func TestDiscoveryHistoricalCTRunUsesProjectedCounts(t *testing.T) {
	t.Parallel()
	const marker = "fixtureopaqdiagnostic"
	run := toDiscoveryRunResponse(store.DiscoveryRun{
		Targets: 3, Failed: 2, Error: "17 of 22 CT logs failed: provider returned 503; " + marker,
	})
	if !strings.Contains(run.Error, "2 of 3 CT logs failed") || !strings.Contains(run.Error, "HTTP 503") || strings.Contains(run.Error, marker) {
		t.Errorf("historical CT diagnosis lost its projected counts or exposed raw text: %q", run.Error)
	}
	monitor := toDiscoveryMonitoringSource(store.DiscoveryMonitoringSource{
		Kind: "ct_log", LastRunTargets: 3, LastRunFailed: 2,
		LastRunError: "17 of 22 CT logs failed: provider returned 503; " + marker,
	})
	if monitor.LastRunError != run.Error {
		t.Error("historical monitoring and run views disagree about the projected CT counts")
	}
}

func TestDiscoveryHistoricalAttackPathReasonOmitsProviderText(t *testing.T) {
	t.Parallel()
	const marker = "fixtureopaqueproviderdetail"
	metadata := json.RawMessage(`{"status":"unknown","reason":"the provider could not be read: HTTP 403 ` + marker + `"}`)
	finding := store.DiscoveryFinding{Kind: orchestrator.AttackPathFindingKind, Metadata: metadata}
	result := toDiscoveryFindingResponse(finding)
	view := nhiExposureAttackPathRow(finding)
	if strings.Contains(string(result.Metadata), marker) || strings.Contains(view.Reason, marker) ||
		!strings.Contains(string(result.Metadata), "HTTP 403 Forbidden") || !strings.Contains(view.Reason, "HTTP 403 Forbidden") {
		t.Error("retained evidence views must keep the provider status without its raw response")
	}
}

func TestDiscoveryTargetErrorResponsesClassifyHistoricalRows(t *testing.T) {
	t.Parallel()
	const fixture = "exampleopaqueval"
	run := toDiscoveryRunResponse(store.DiscoveryRun{TargetResults: []store.DiscoveryTargetResult{{
		Kind: "cloud_provider", Target: "fixture-target", Status: "failed",
		Error: "provider refused credential " + fixture,
	}}})
	if len(run.TargetResults) != 1 || run.TargetResults[0].Error == "" || strings.Contains(run.TargetResults[0].Error, fixture) {
		t.Fatal("a historical target result must keep a failure class without its provider-supplied detail")
	}
}

func TestDiscoveryHistoricalAttackPathMetadataHasNoOriginAuthority(t *testing.T) {
	t.Parallel()
	const origin = "https://fixture.example.test"
	for _, metadata := range []string{
		`{"reason":"the provider could not be read: ` + orchestrator.DiscoveryDestinationPinRefusal + `","credential_refused_origin":"` + origin + `"}`,
		`{"credential_refused_origin":"` + origin + `"}`,
	} {
		finding := store.DiscoveryFinding{Kind: orchestrator.AttackPathFindingKind, Metadata: json.RawMessage(metadata)}
		result := toDiscoveryFindingResponse(finding)
		view := nhiExposureAttackPathRow(finding)
		if strings.Contains(string(result.Metadata), origin) || strings.Contains(view.Reason, origin) {
			t.Error("historical finding metadata supplied an unverified diagnostic origin")
		}
	}
}

func TestDiscoveryCTCheckpointClassifiesHistoricalErrors(t *testing.T) {
	t.Parallel()
	const marker = "fixtureopaquevalue"
	var logs []ctMonitoringLogResponse
	addCTCheckpoint(&logs, store.CTCheckpoint{
		LogURL: "https://fixture.example.test", LastPollStatus: "failed",
		LastPollError: "provider replied with " + marker,
	})
	if len(logs) != 1 || logs[0].LastError == "" || strings.Contains(logs[0].LastError, marker) {
		t.Fatal("the CT monitoring response retained provider error text")
	}
}
