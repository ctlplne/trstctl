// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

// N1: the relay half of approving or denying a pending AD CS request. certutil
// -resubmit or -deny at the CA, then the request's row is read back before the
// relay reports; every argument vector is fixed.

// certutilDecideStandIn keeps the stand-in CA's state in dir: "issued" after
// -resubmit, "denied" after -deny. An "ignore" file makes the CA keep reading
// the request back as pending.
func certutilDecideStandIn(t *testing.T) (script, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	dir = t.TempDir()
	script = filepath.Join(dir, "certutil")
	body := `#!/bin/sh
S='` + dir + `'
[ "$1" = -config ] && [ "$2" = '` + revokeCA + `' ] || exit 2
printf '%s\n' "$@" >> "$S/argv"
case "$3" in
-resubmit) [ "$4" = 77 ] || exit 3; touch "$S/issued" ;;
-deny) [ "$4" = 77 ] || exit 3; touch "$S/denied" ;;
-view) d='9 -- Pending'; serial=''
  if [ ! -f "$S/ignore" ]; then
    if [ -f "$S/issued" ]; then d='20 -- Issued'; serial='1a00000077'; fi
    if [ -f "$S/denied" ]; then d='31 -- Denied'; fi
  fi
  printf '"Request ID","Serial Number","Request Disposition"\n"%s","%s","%s"\n' "${5#RequestID=}" "$serial" "$d" ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script, dir
}

func adcsDecideJob(t *testing.T, intent relay.ADCSDecideIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 42, Kind: relay.KindADCSDecide, Attempt: 1, Payload: payload}
}

func decideIntent(decision string) relay.ADCSDecideIntent {
	return relay.ADCSDecideIntent{ID: "adcs-decision:abc", CAConfig: revokeCA, RequestID: 77, Decision: decision, RequiredAgentID: "agent-1"}
}

func TestRelayADCSDecideApprovesOrDeniesAndReadsBack(t *testing.T) {
	for _, tc := range []struct {
		decision, verb, disposition, serial string
	}{
		{relay.ADCSDecisionApprove, "-resubmit", "issued", "1a00000077"},
		{relay.ADCSDecisionDeny, "-deny", "denied", ""},
	} {
		script, dir := certutilDecideStandIn(t)
		useCertutil(t, script)
		intent := decideIntent(tc.decision)
		ch := &fakeChannel{jobs: []relay.Job{adcsDecideJob(t, intent)}}
		executed, err := relay.RunOnce(t.Context(), ch, nil, 1, 60)
		if err != nil || executed != 1 || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
			t.Fatalf("%s: executed = %d, %v; reports %+v", tc.decision, executed, err, ch.reports)
		}
		var got relay.ADCSDecideReport
		if err := json.Unmarshal([]byte(ch.reports[0].detail), &got); err != nil {
			t.Fatal(err)
		}
		if got.Disposition != tc.disposition || got.Serial != tc.serial || relay.ValidateADCSDecideReport(intent, got) != nil {
			t.Fatalf("%s report = %+v", tc.decision, got)
		}
		argv := strings.Fields(readStandIn(t, filepath.Join(dir, "argv")))
		read := []string{"-config", revokeCA, "-view", "-restrict", "RequestID=77", "-out", "RequestID,SerialNumber,Request.Disposition", "csv"}
		want := append(append(append([]string{}, read...), "-config", revokeCA, tc.verb, "77"), read...)
		if strings.Join(argv, " ") != strings.Join(want, " ") {
			t.Fatalf("%s argv = %q, want %q", tc.decision, argv, want)
		}
	}
}

func TestRelayADCSDecideRefusesWhatItCannotProve(t *testing.T) {
	// The CA keeps the request pending: no report claims the decision.
	script, dir := certutilDecideStandIn(t)
	useCertutil(t, script)
	if err := os.WriteFile(filepath.Join(dir, "ignore"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{jobs: []relay.Job{adcsDecideJob(t, decideIntent(relay.ADCSDecisionApprove))}}
	if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil || len(ch.reports) != 1 ||
		ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, "read the request back as issued") {
		t.Fatalf("pending readback reports = %+v (%v)", ch.reports, err)
	}
	// A request the CA no longer holds as pending is not touched: -resubmit
	// would issue a request a manager already denied.
	script, dir = certutilDecideStandIn(t)
	useCertutil(t, script)
	if err := os.WriteFile(filepath.Join(dir, "denied"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ch = &fakeChannel{jobs: []relay.Job{adcsDecideJob(t, decideIntent(relay.ADCSDecisionApprove))}}
	if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil || len(ch.reports) != 1 ||
		ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, "not hold request 77 as pending (denied)") {
		t.Fatalf("denied request reports = %+v (%v)", ch.reports, err)
	}
	if argv := readStandIn(t, filepath.Join(dir, "argv")); strings.Contains(argv, "-resubmit") {
		t.Fatalf("a denied request was resubmitted: %q", argv)
	}
	// A payload that is not one decision runs nothing.
	bad := decideIntent("escalate")
	ch = &fakeChannel{jobs: []relay.Job{adcsDecideJob(t, bad)}}
	if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed {
		t.Fatalf("bad payload reports = %+v (%v)", ch.reports, err)
	}
	if argv := readStandIn(t, filepath.Join(dir, "argv")); strings.Contains(argv, "escalate") {
		t.Fatalf("a refused payload ran certutil: %q", argv)
	}
	// A report for another request or decision fails validation.
	intent := decideIntent(relay.ADCSDecisionDeny)
	for _, r := range []relay.ADCSDecideReport{
		{CAConfig: revokeCA, RequestID: 78, Decision: relay.ADCSDecisionDeny, Disposition: "denied"},
		{CAConfig: revokeCA, RequestID: 77, Decision: relay.ADCSDecisionApprove, Disposition: "issued", Serial: "01"},
		{CAConfig: revokeCA, RequestID: 77, Decision: relay.ADCSDecisionDeny, Disposition: "pending"},
	} {
		if relay.ValidateADCSDecideReport(intent, r) == nil {
			t.Fatalf("report %+v validated", r)
		}
	}
}
