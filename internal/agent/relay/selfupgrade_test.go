// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
)

func upgradeJob(t *testing.T, intent fleet.UpgradeIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 7, Kind: relay.KindAgentUpgrade, Attempt: 1, Payload: payload}
}

// seedExecutable stands in for the running agent binary.
func seedExecutable(t *testing.T, content string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "trstctl-agent")
	if err := os.WriteFile(exe, []byte(content), 0o755); err != nil { // #nosec G306 -- the fixture IS an executable; 0755 is its required mode (CWE-276)
		t.Fatal(err)
	}
	return exe
}

func runUpgrade(t *testing.T, ch relay.Channel, su *relay.SelfUpgrade) {
	t.Helper()
	if _, err := relay.RunOnceSelfUpgradeOnly(t.Context(), ch, su, 4, 30); err != nil {
		t.Fatal(err)
	}
}

func TestSelfUpgradeAlreadyOnTargetReportsExecutedWithoutDownloading(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the artifact host was contacted for a version this agent already runs")
	}))
	defer srv.Close()
	exe := seedExecutable(t, "current-binary")
	ch := &fakeChannel{jobs: []relay.Job{upgradeJob(t, fleet.UpgradeIntent{
		TargetVersion: "2.0.0",
		Artifacts: []fleet.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH,
			URL: srv.URL, SHA256: strings.Repeat("a", 64)}},
	})}}
	runUpgrade(t, ch, &relay.SelfUpgrade{ExecutablePath: exe, CurrentVersion: "2.0.0"})
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one executed. A redelivered job after a completed upgrade "+
			"must close, not cycle", ch.reports)
	}
}

func TestSelfUpgradeRefusesDigestMismatchAndLeavesBinaryAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-the-published-build"))
	}))
	defer srv.Close()
	exe := seedExecutable(t, "current-binary")
	ch := &fakeChannel{jobs: []relay.Job{upgradeJob(t, fleet.UpgradeIntent{
		TargetVersion: "2.0.0",
		Artifacts: []fleet.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH,
			URL: srv.URL, SHA256: crypto.SHA256Hex([]byte("the-published-build"))}},
	})}}
	runUpgrade(t, ch, &relay.SelfUpgrade{ExecutablePath: exe, CurrentVersion: "1.0.0",
		Client:  srv.Client(),
		Restart: func() error { t.Error("restarted onto bytes that failed verification"); return nil }})

	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed ||
		!strings.Contains(ch.reports[0].detail, "digest did not match") {
		t.Fatalf("reports = %+v, want one failed naming the digest.\n\n"+
			"The digest is the ONLY thing standing between a compromised artifact host and every "+
			"agent in the ring; a generic failure phrase would send the operator to the wrong log", ch.reports)
	}
	got, err := os.ReadFile(exe) // #nosec G304 -- test reads its own tempdir fixture path (CWE-22)
	if err != nil || string(got) != "current-binary" {
		t.Fatalf("running binary = %q, %v; it must be untouched after a refused download", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(exe))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want just the binary — a refused artifact must not "+
			"leave staged temp files beside the executable", len(entries))
	}
}

func TestSelfUpgradeReportsThePlatformGapByName(t *testing.T) {
	exe := seedExecutable(t, "current-binary")
	ch := &fakeChannel{jobs: []relay.Job{upgradeJob(t, fleet.UpgradeIntent{
		TargetVersion: "2.0.0",
		Artifacts:     []fleet.Artifact{{OS: "plan9", Arch: "mips", URL: "https://dl.example/x", SHA256: strings.Repeat("a", 64)}},
	})}}
	runUpgrade(t, ch, &relay.SelfUpgrade{ExecutablePath: exe, CurrentVersion: "1.0.0"})
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed ||
		!strings.Contains(ch.reports[0].detail, "platform") {
		t.Fatalf("reports = %+v; the closed phrase must say the campaign published no build for "+
			"this platform — that is the gap the operator can act on", ch.reports)
	}
}

func TestSelfUpgradeStagesSwapsReportsThenRestarts(t *testing.T) {
	newBinary := []byte("new-binary-2.0.0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()
	exe := seedExecutable(t, "current-binary")
	ch := &fakeChannel{jobs: []relay.Job{upgradeJob(t, fleet.UpgradeIntent{
		TargetVersion: "2.0.0",
		Artifacts: []fleet.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH,
			URL: srv.URL, SHA256: crypto.SHA256Hex(newBinary)}},
	})}}
	reportsAtRestart := -1
	restarted := 0
	executed, err := relay.RunOnceSelfUpgradeOnly(t.Context(), ch, &relay.SelfUpgrade{
		ExecutablePath: exe, CurrentVersion: "1.0.0", Client: srv.Client(),
		Restart: func() error {
			restarted++
			reportsAtRestart = len(ch.reports)
			return nil
		},
	}, 4, 30)
	if err != nil || executed != 1 {
		t.Fatalf("executed = %d, %v", executed, err)
	}
	if restarted != 1 {
		t.Fatal("the agent never restarted; a staged binary nobody loads is not an upgrade")
	}
	if reportsAtRestart != 1 {
		t.Fatalf("at restart time %d reports had been sent, want 1.\n\n"+
			"Exec never returns: a restart before the report turns every successful upgrade into "+
			"silence, and silence is exactly what halts the ring", reportsAtRestart)
	}
	if ch.reports[0].outcome != relay.OutcomeExecuted ||
		!strings.Contains(ch.reports[0].detail, "2.0.0") {
		t.Fatalf("report = %+v, want executed naming the staged version", ch.reports[0])
	}
	got, err := os.ReadFile(exe) // #nosec G304 -- test reads its own tempdir fixture path (CWE-22)
	if err != nil || string(got) != string(newBinary) {
		t.Fatalf("binary after swap = %q, %v; want the downloaded build at the executable's own path", got, err)
	}
	old, err := os.ReadFile(exe + ".old") // #nosec G304 -- test reads its own tempdir fixture path (CWE-22)
	if err != nil || string(old) != "current-binary" {
		t.Fatalf(".old = %q, %v; the previous binary must survive beside the new one — it is the "+
			"rollback a human reaches for when the new build cannot start", old, err)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed binary mode %v is not executable; the next start would fail with EACCES", info.Mode())
	}
}

func TestSelfUpgradeRestartFailureKeepsTheExecutedReport(t *testing.T) {
	newBinary := []byte("new-binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	defer srv.Close()
	exe := seedExecutable(t, "current-binary")
	ch := &fakeChannel{jobs: []relay.Job{upgradeJob(t, fleet.UpgradeIntent{
		TargetVersion: "2.0.0",
		Artifacts: []fleet.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH,
			URL: srv.URL, SHA256: crypto.SHA256Hex(newBinary)}},
	})}}
	runUpgrade(t, ch, &relay.SelfUpgrade{ExecutablePath: exe, CurrentVersion: "1.0.0",
		Client:  srv.Client(),
		Restart: func() error { return os.ErrPermission }})
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v; the stage DID succeed and the report must say so — if this "+
			"process never comes back on the new version, the ring's grace handles it as silence, "+
			"which is the correct verdict for an agent that could not restart itself", ch.reports)
	}
}

// kindRecordingChannel proves what the loop ASKS for, which is the opt-in.
type kindRecordingChannel struct {
	asked [][]string
}

func (k *kindRecordingChannel) ClaimJobs(_ context.Context, kinds []string, _, _ int) ([]relay.Job, error) {
	k.asked = append(k.asked, append([]string(nil), kinds...))
	return nil, nil
}
func (k *kindRecordingChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	return nil, nil
}
func (k *kindRecordingChannel) ReportJobResult(context.Context, int64, int, string, string, string) (bool, error) {
	return true, nil
}

func TestUpgradeKindIsClaimedOnlyWithTheOptIn(t *testing.T) {
	ch := &kindRecordingChannel{}
	if _, err := relay.RunOnceWithPlugins(t.Context(), ch, nil, connector.LocalOpsConfig{}, nil, 4, 30); err != nil {
		t.Fatal(err)
	}
	for _, kind := range ch.asked[0] {
		if kind == relay.KindAgentUpgrade {
			t.Fatal("an agent with no self-upgrade opt-in asked for agent.upgrade; the flag is the " +
				"machine operator's consent and asking without it would claim a binary replacement " +
				"nobody on this host approved")
		}
	}
	if _, err := relay.RunOnceWithSelfUpgrade(t.Context(), ch, nil, connector.LocalOpsConfig{}, nil,
		&relay.SelfUpgrade{ExecutablePath: "/x", CurrentVersion: "1"}, 4, 30); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, kind := range ch.asked[1] {
		found = found || kind == relay.KindAgentUpgrade
	}
	if !found {
		t.Fatal("the opted-in loop never asked for agent.upgrade, so no campaign could ever reach this agent")
	}
}
