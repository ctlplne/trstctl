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

// A162: the relay half of AD CS revocation. certutil revokes at the CA,
// publishes a new CRL, and the CA database row is read back before the relay
// reports; every argument vector is fixed.

const revokeCA = `ca01.corp.example\CORP-CA`

// certutilRevokeStandIn keeps the stand-in CA's state in dir: "revoked" after
// -revoke, "crl" after -CRL. A "fail-crl" file makes -CRL fail and an "ignore"
// file makes the CA keep reading the row back as issued.
func certutilRevokeStandIn(t *testing.T) (script, dir string) {
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
-revoke) printf '%s %s\n' "$4" "$5" > "$S/revoked" ;;
-CRL) [ -f "$S/fail-crl" ] && exit 1; touch "$S/crl" ;;
-view) d='20 -- Issued'
  if [ -f "$S/revoked" ] && [ ! -f "$S/ignore" ]; then d='21 -- Revoked'; fi
  printf '"Serial Number","Request Disposition"\n"%s","%s"\n' "${5#SerialNumber=}" "$d" ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script, dir
}

func adcsRevokeJob(t *testing.T, intent relay.ADCSRevokeIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 41, Kind: relay.KindADCSRevoke, Attempt: 1, Payload: payload}
}

func revokeIntent() relay.ADCSRevokeIntent {
	return relay.ADCSRevokeIntent{ID: "certificate.external-revoked:abc", CAConfig: revokeCA, Serial: "1a00000002", ReasonCode: 4, RequiredAgentID: "agent-1"}
}

func readStandIn(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp file (CWE-22).
	if err != nil {
		return ""
	}
	return string(raw)
}

func TestRelayADCSRevokeRevokesPublishesAndReadsBack(t *testing.T) {
	script, dir := certutilRevokeStandIn(t)
	useCertutil(t, script)
	ch := &fakeChannel{jobs: []relay.Job{adcsRevokeJob(t, revokeIntent())}}
	executed, err := relay.RunOnce(t.Context(), ch, nil, 1, 60)
	if err != nil || executed != 1 || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
		t.Fatalf("executed = %d, %v; reports %+v", executed, err, ch.reports)
	}
	if ch.redeemed != 0 {
		t.Fatalf("the revocation redeemed %d credentials; certutil runs as the relay's own identity", ch.redeemed)
	}
	want := strings.Join([]string{
		"-config", revokeCA, "-revoke", "1a00000002", "4",
		"-config", revokeCA, "-CRL",
		"-config", revokeCA, "-view", "-restrict", "SerialNumber=1a00000002", "-out", "SerialNumber,Request.Disposition", "csv",
	}, "\n") + "\n"
	if got := readStandIn(t, filepath.Join(dir, "argv")); got != want {
		t.Fatalf("certutil argv = %q, want %q", got, want)
	}
	var report relay.ADCSRevokeReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if err := relay.ValidateADCSRevokeReport(revokeIntent(), report); err != nil {
		t.Fatalf("the relay's own report does not validate: %v (%+v)", err, report)
	}
}

func TestRelayADCSRevokeRefusesWithoutRunningCertutil(t *testing.T) {
	script, dir := certutilRevokeStandIn(t)
	for name, tc := range map[string]struct {
		certutil string
		mutate   func(*relay.ADCSRevokeIntent)
		want     string
	}{
		"option-shaped serial":  {script, func(i *relay.ADCSRevokeIntent) { i.Serial = "-shutdown" }, "not an AD CS revocation"},
		"reason certutil lacks": {script, func(i *relay.ADCSRevokeIntent) { i.ReasonCode = 9 }, "not an AD CS revocation"},
		"no revocation id":      {script, func(i *relay.ADCSRevokeIntent) { i.ID = "" }, "not an AD CS revocation"},
		"no certutil":           {"", func(*relay.ADCSRevokeIntent) {}, "domain-joined Windows relay"},
	} {
		t.Run(name, func(t *testing.T) {
			useCertutil(t, tc.certutil)
			intent := revokeIntent()
			tc.mutate(&intent)
			ch := &fakeChannel{jobs: []relay.Job{adcsRevokeJob(t, intent)}}
			if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil {
				t.Fatal(err)
			}
			if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, tc.want) {
				t.Fatalf("reports = %+v", ch.reports)
			}
			if got := readStandIn(t, filepath.Join(dir, "argv")); got != "" {
				t.Fatalf("certutil ran for a refused revocation: %q", got)
			}
		})
	}
}

func TestRelayADCSRevokeReportsWhatTheCADidNot(t *testing.T) {
	for name, tc := range map[string]struct {
		marker, want string
	}{
		"CRL not published":         {"fail-crl", "could not publish a new CRL"},
		"row not read back revoked": {"ignore", "does not read the certificate back as revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			script, dir := certutilRevokeStandIn(t)
			if err := os.WriteFile(filepath.Join(dir, tc.marker), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			useCertutil(t, script)
			ch := &fakeChannel{jobs: []relay.Job{adcsRevokeJob(t, revokeIntent())}}
			if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil {
				t.Fatal(err)
			}
			if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, tc.want) {
				t.Fatalf("reports = %+v", ch.reports)
			}
		})
	}
}

func TestADCSRevokeReportMustMatchTheQueuedRevocation(t *testing.T) {
	good := relay.ADCSRevokeReport{CAConfig: revokeCA, Serial: "1A00000002", ReasonCode: 4, Disposition: "revoked", CRLPublished: true}
	if err := relay.ValidateADCSRevokeReport(revokeIntent(), good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*relay.ADCSRevokeReport){
		"another serial": func(r *relay.ADCSRevokeReport) { r.Serial = "1a00000003" },
		"another CA":     func(r *relay.ADCSRevokeReport) { r.CAConfig = `ca02.corp.example\EDGE-CA` },
		"another reason": func(r *relay.ADCSRevokeReport) { r.ReasonCode = 1 },
		"still issued":   func(r *relay.ADCSRevokeReport) { r.Disposition = "issued" },
		"no CRL":         func(r *relay.ADCSRevokeReport) { r.CRLPublished = false },
	} {
		bad := good
		mutate(&bad)
		if err := relay.ValidateADCSRevokeReport(revokeIntent(), bad); err == nil {
			t.Errorf("%s: the report validated", name)
		}
	}
}
