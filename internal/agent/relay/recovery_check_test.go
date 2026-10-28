// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
)

const (
	recoveryTarget  = "21021021-0210-4210-8210-210210210210"
	recoveryRevoked = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func writeRecoveryExecutable(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- the fixture IS an executable; 0755 is its required mode (CWE-276)
		t.Fatal(err)
	}
	return path
}

func recoveryProfile(t *testing.T, recoveryAction string) (connector.LocalOpsConfig, string) {
	t.Helper()
	dir := t.TempDir()
	stop := writeRecoveryExecutable(t, dir, "stop-listener", "#!/bin/sh\nexit 0\n")
	wrapper := writeRecoveryExecutable(t, dir, "nginx-recover", "#!/bin/sh\nexec /usr/sbin/nginx \"$@\"\n")
	return connector.LocalOpsConfig{
		AllowedRoots: []string{dir},
		Actions: []connector.LocalAction{
			{LogicalName: "stop-listener", LogicalArgs: []string{}, Command: stop},
			{LogicalName: "nginx", Command: wrapper, PassArgs: true},
		},
		Containments: []connector.LocalContainment{{TargetID: recoveryTarget, Address: "127.0.0.1:18443",
			Action: "stop-listener", RecoveryAction: recoveryAction}},
	}, wrapper
}

func recoveryIntent() RecoveryCheckIntent {
	return RecoveryCheckIntent{CheckID: "c2100000-0000-4000-8000-000000000001", TargetID: recoveryTarget,
		TargetRevision: "revision-1", RequiredAgentID: "agent-1", RevokedFingerprints: []string{recoveryRevoked}}
}

func probeAnswer(reached bool, fingerprint string) func(connector.LocalContainment) (transport.ProbeTranscript, error) {
	return func(binding connector.LocalContainment) (transport.ProbeTranscript, error) {
		tr := transport.ProbeTranscript{Address: binding.Address, Vantage: transport.VantageLocal, Reached: reached,
			ObservedFingerprint: fingerprint, ObservedAtUnix: 100}
		if !reached {
			tr.Error = "connection refused"
		}
		return tr, nil
	}
}

func TestRecoveryCheckIsClaimedAndAdvertisedWithItsHostProfile(t *testing.T) {
	if !slices.Contains(ClaimableKinds(), KindEndpointRecoveryCheck) {
		t.Fatal("the host agent never asks for endpoint.recovery_check")
	}
	for _, shipped := range ShippedJobKinds() {
		if shipped.Kind == KindEndpointRecoveryCheck {
			if !slices.Contains(shipped.Flags, "--host-exec-profile") || !slices.Contains(shipped.Roles, "host") {
				t.Fatalf("recovery check must advertise the host profile and host role: %+v", shipped)
			}
			return
		}
	}
	t.Fatal("the agent executes endpoint.recovery_check but its advertised shipped capabilities omit it")
}

// The host reports a pinned recovery action by digest only, the digest moves
// when the executable changes, and the listener state follows one probe.
func TestRecoveryCheckReportsThePinnedActionByDigestOnly(t *testing.T) {
	profile, wrapper := recoveryProfile(t, "nginx")
	if _, err := connector.NewLocalOps(profile); err != nil {
		t.Fatalf("a profile whose recovery action is another pinned action was refused: %v", err)
	}
	intent := recoveryIntent()
	got, failure := checkRecovery(intent, profile, probeAnswer(false, ""))
	if failure != "" || got.Recovery != RecoveryCheckPinned || got.RecoveryAction != "nginx" ||
		got.Listener != RecoveryListenerStopped || !sha256Hex(got.ExecutableSHA256) || !sha256Hex(got.ArgvSHA256) || !got.Ready() {
		t.Fatalf("pinned recovery with a stopped listener = %+v failure=%q", got, failure)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), filepath.Dir(wrapper)) || strings.Contains(string(encoded), "nginx-recover") {
		t.Fatalf("the report carries the action's path or file name: %s", encoded)
	}
	if err := ValidateRecoveryCheckReport(intent, got, got.Digest()); err != nil {
		t.Fatalf("receiver rejected a pinned report: %v", err)
	}

	writeRecoveryExecutable(t, filepath.Dir(wrapper), "nginx-recover", "#!/bin/sh\nexit 1\n")
	changed, _ := checkRecovery(intent, profile, probeAnswer(false, ""))
	if changed.ExecutableSHA256 == got.ExecutableSHA256 || changed.ArgvSHA256 != got.ArgvSHA256 {
		t.Fatalf("executable digest did not follow the file: before %s after %s", got.ExecutableSHA256, changed.ExecutableSHA256)
	}
	profile.Actions[1].Args = []string{"-c", "/etc/nginx/nginx.conf"}
	reargued, _ := checkRecovery(intent, profile, probeAnswer(false, ""))
	if reargued.ArgvSHA256 == got.ArgvSHA256 {
		t.Fatal("command-line digest did not follow the pinned arguments")
	}

	revoked, _ := checkRecovery(intent, profile, probeAnswer(true, recoveryRevoked))
	if revoked.Listener != RecoveryListenerServingRevoke || revoked.Ready() {
		t.Fatalf("a listener serving the revoked leaf = %+v", revoked)
	}
	other, _ := checkRecovery(intent, profile, probeAnswer(true, strings.Repeat("b", 64)))
	if other.Listener != RecoveryListenerServing || !other.Ready() {
		t.Fatalf("a listener serving another leaf = %+v", other)
	}
	unreadable, _ := checkRecovery(intent, profile, probeAnswer(true, ""))
	if unreadable.Listener != RecoveryListenerUnverified || unreadable.Ready() {
		t.Fatalf("a listener that served nothing readable = %+v", unreadable)
	}
	for _, report := range []RecoveryCheckReport{revoked, other, unreadable} {
		if err := ValidateRecoveryCheckReport(intent, report, report.Digest()); err != nil {
			t.Fatalf("receiver rejected %s: %v", report.Listener, err)
		}
	}
}

func TestRecoveryCheckWithoutAPinnedActionOrBinding(t *testing.T) {
	intent := recoveryIntent()
	profile, _ := recoveryProfile(t, "")
	got, failure := checkRecovery(intent, profile, probeAnswer(false, ""))
	if failure != "" || got.Recovery != RecoveryCheckNoRecoveryAction || got.ExecutableSHA256 != "" || got.Ready() {
		t.Fatalf("no recovery action = %+v failure=%q", got, failure)
	}
	if err := ValidateRecoveryCheckReport(intent, got, got.Digest()); err != nil {
		t.Fatalf("receiver rejected a report without a recovery action: %v", err)
	}

	other := intent
	other.TargetID = "21021021-0210-4210-8210-999999999999"
	probed := false
	unbound, failure := checkRecovery(other, profile, func(connector.LocalContainment) (transport.ProbeTranscript, error) {
		probed = true
		return transport.ProbeTranscript{}, nil
	})
	if failure != "" || probed || unbound.Recovery != RecoveryCheckNoBinding || unbound.Listener != RecoveryListenerNone || unbound.Probe != nil {
		t.Fatalf("a target the profile does not bind = %+v probed=%v", unbound, probed)
	}
	if err := ValidateRecoveryCheckReport(other, unbound, unbound.Digest()); err != nil {
		t.Fatalf("receiver rejected a no-binding report: %v", err)
	}

	missing, _ := recoveryProfile(t, "not-an-action")
	if _, failure := checkRecovery(intent, missing, probeAnswer(false, "")); failure != "host profile's recovery action is not one of its actions" {
		t.Fatalf("a recovery action outside the profile answered: %q", failure)
	}
}

func TestRecoveryCheckReportValidationIsStrict(t *testing.T) {
	intent := recoveryIntent()
	profile, _ := recoveryProfile(t, "nginx")
	good, _ := checkRecovery(intent, profile, probeAnswer(false, ""))
	for name, mutate := range map[string]func(*RecoveryCheckReport){
		"another target":      func(r *RecoveryCheckReport) { r.TargetID = "other" },
		"listener not probed": func(r *RecoveryCheckReport) { r.Listener = RecoveryListenerServing },
		"pinned without hash": func(r *RecoveryCheckReport) { r.ExecutableSHA256 = "" },
		"remote vantage probe": func(r *RecoveryCheckReport) {
			probe := *r.Probe
			probe.Vantage = transport.VantageRelay
			r.Probe = &probe
		},
		"unknown state": func(r *RecoveryCheckReport) { r.Recovery = "maybe" },
	} {
		bad := good
		mutate(&bad)
		if err := ValidateRecoveryCheckReport(intent, bad, bad.Digest()); err == nil {
			t.Errorf("%s: receiver accepted %+v", name, bad)
		}
	}
	if err := ValidateRecoveryCheckReport(intent, good, strings.Repeat("0", 64)); err == nil {
		t.Error("receiver accepted a report whose digest is not the signed one")
	}
	invalid := intent
	invalid.CheckID = ""
	if err := ValidateRecoveryCheckReport(invalid, good, good.Digest()); err == nil {
		t.Error("receiver accepted a report for an intent without a check id")
	}
}

func TestHostDeployActionNamesFollowTheConnector(t *testing.T) {
	names, err := HostDeployActionNames("nginx", json.RawMessage(`{"cert_path":"/etc/nginx/a.crt","key_path":"/etc/nginx/a.key"}`))
	if err != nil || !slices.Equal(names, []string{"nginx"}) {
		t.Fatalf("nginx deploy actions = %v err=%v", names, err)
	}
	names, err = HostDeployActionNames("haproxy", json.RawMessage(`{"crt_path":"/etc/haproxy/a.pem","config_path":"/etc/haproxy/haproxy.cfg"}`))
	if err != nil || !slices.Equal(names, []string{"haproxy", "systemctl"}) {
		t.Fatalf("haproxy deploy actions = %v err=%v", names, err)
	}
	if _, err := HostDeployActionNames("future-connector", nil); err == nil {
		t.Fatal("a connector without host deploy actions named some")
	}
}
