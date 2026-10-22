// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
)

func selfCheckJob(t *testing.T, intent relay.SelfCheckIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 9, Kind: relay.KindAgentSelfCheck, Attempt: 1, Payload: payload}
}

// A71: the post-upgrade self-check reports a signed receipt naming each
// exercised part; it passes on a build that matches the campaign and whose
// exec profile still resolves, and fails by name otherwise.
func TestSelfCheckExercisesTheBuildAndItsExecProfile(t *testing.T) {
	root := t.TempDir()
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: time.Second}},
	}
	ch := &fakeChannel{jobs: []relay.Job{selfCheckJob(t, relay.SelfCheckIntent{CampaignID: "c1", TargetVersion: "2.0.0"})}}
	if _, err := relay.RunOnceWithSelfUpgrade(t.Context(), ch, nil, profile, nil, &relay.SelfUpgrade{CurrentVersion: "2.0.0"}, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one executed self-check", ch.reports)
	}
	var report relay.SelfCheckReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || !report.Passed() || report.Version != "2.0.0" {
		t.Fatalf("report = %+v %v, want every check passed on 2.0.0", report, err)
	}
	names := []string{}
	for _, check := range report.Checks {
		names = append(names, check.Name)
	}
	if got := strings.Join(names, ","); got != "version,host_exec_profile,job_channel" {
		t.Fatalf("checks = %s", got)
	}

	// The wrong build, and a profile whose root vanished: failed, by name.
	ch = &fakeChannel{jobs: []relay.Job{selfCheckJob(t, relay.SelfCheckIntent{CampaignID: "c1", TargetVersion: "2.0.0"})}}
	broken := connector.LocalOpsConfig{AllowedRoots: []string{filepath.Join(root, "gone")}, Actions: profile.Actions}
	if _, err := relay.RunOnceWithSelfUpgrade(t.Context(), ch, nil, broken, nil, &relay.SelfUpgrade{CurrentVersion: "1.9.0"}, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failed self-check", ch.reports)
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || report.Passed() {
		t.Fatalf("failed report = %+v %v", report, err)
	}
	failed := map[string]string{}
	for _, check := range report.Checks {
		if !check.OK {
			failed[check.Name] = check.Detail
		}
	}
	if !strings.Contains(failed["version"], "campaign targets 2.0.0") || !strings.Contains(failed["host_exec_profile"], "is not a directory") {
		t.Fatalf("failed checks = %v", failed)
	}

	// An agent without the self-upgrade executor still answers; its version
	// is scored from its heartbeat.
	ch = &fakeChannel{jobs: []relay.Job{selfCheckJob(t, relay.SelfCheckIntent{CampaignID: "c1", TargetVersion: "2.0.0"})}}
	if _, err := relay.RunOnceWithSelfUpgrade(t.Context(), ch, nil, connector.LocalOpsConfig{}, nil, nil, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want an executed self-check with the version left to the heartbeat", ch.reports)
	}
}
