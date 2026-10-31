// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/adcsdb"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

// A162: the relay half of the CA database read. certutil runs with a fixed
// argument vector; only per-disposition counts return.

const certutilCSV = `"Issued Request ID","Request Disposition","Serial Number","Certificate Effective Date","Certificate Expiration Date","Issued Common Name","Certificate Template","Requester Name","Revocation Date"
"2","20 -- Issued","1a00000002","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web01.corp.example","WebServer","CORP\svc-web","EMPTY"
"3","21 -- Revoked","1a00000003","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web02.corp.example","WebServer","CORP\svc-web","10/15/2026 2:00 PM"
"4","9 -- Taken Under Submission","EMPTY","EMPTY","EMPTY","EMPTY","WebServer","CORP\alice","EMPTY"
"5","20 -- Issued","1a00000005","10/1/2026 9:00 AM","EMPTY","laptop-9.corp.example","Machine","CORP\LAPTOP-9$","EMPTY"
"EMPTY","30 -- Error","EMPTY","EMPTY","EMPTY","EMPTY","EMPTY","CORP\bob","EMPTY"
`

// certutilStandIn writes a POSIX stand-in for certutil.exe that records its
// argument vector and prints out (or exits with exitCode).
func certutilStandIn(t *testing.T, out string, exitCode int) (script, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	data := filepath.Join(dir, "view.csv")
	if err := os.WriteFile(data, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(dir, "certutil")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\n"
	if exitCode != 0 {
		body += "echo 'CertUtil: -view command FAILED' >&2\nexit " + strconv.Itoa(exitCode) + "\n"
	} else {
		body += "cat '" + data + "'\n"
	}
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script, argsFile
}

func useCertutil(t *testing.T, path string) {
	t.Helper()
	previous := relay.CertutilPath
	relay.CertutilPath = path
	t.Cleanup(func() { relay.CertutilPath = previous })
}

func adcsDatabaseJob(t *testing.T, caConfig string) relay.Job {
	t.Helper()
	payload, err := json.Marshal(relay.ADCSDatabaseIntent{ID: "collection-1", CAConfig: caConfig, RequiredAgentID: "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 31, Kind: relay.KindADCSDatabase, Attempt: 1, Payload: payload}
}

func TestRelayADCSDatabaseReadReturnsCountsOnly(t *testing.T) {
	script, argsFile := certutilStandIn(t, certutilCSV, 0)
	useCertutil(t, script)
	ch := &fakeChannel{jobs: []relay.Job{adcsDatabaseJob(t, `ca01.corp.example\CORP-CA`)}}
	executed, err := relay.RunOnce(t.Context(), ch, nil, 1, 60)
	if err != nil || executed != 1 || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
		t.Fatalf("executed = %d, %v; reports %+v", executed, err, ch.reports)
	}
	if ch.redeemed != 0 {
		t.Fatalf("the read redeemed %d credentials; certutil runs as the relay's own identity", ch.redeemed)
	}
	args, err := os.ReadFile(argsFile) // #nosec G304 -- test-owned temp file (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	want := "-config\nca01.corp.example\\CORP-CA\n-view\n-out\nRequestID,Request.Disposition,SerialNumber,NotBefore,NotAfter,CommonName,CertificateTemplate,Request.RequesterName,Request.RevokedWhen\ncsv\n"
	if string(args) != want {
		t.Fatalf("certutil argv = %q, want %q", args, want)
	}
	detail := ch.reports[0].detail
	for _, leaked := range []string{"web01", "svc-web", "alice", "LAPTOP-9", "1a00000002"} {
		if strings.Contains(detail, leaked) {
			t.Fatalf("the report carries %q from a database row: %s", leaked, detail)
		}
	}
	var got relay.ADCSDatabaseReport
	if err := json.Unmarshal([]byte(detail), &got); err != nil {
		t.Fatal(err)
	}
	wantSummary := adcsdb.DBSummary{Issued: 2, Pending: 1, Revoked: 1, Unparsed: 1, Total: 4}
	if got.CAConfig != `ca01.corp.example\CORP-CA` || got.Summary != wantSummary || got.RowsRead != 5 || got.RowsRejected != 1 {
		t.Fatalf("report = %+v", got)
	}
	if err := relay.ValidateADCSDatabaseReport(relay.ADCSDatabaseIntent{CAConfig: `ca01.corp.example\CORP-CA`}, got); err != nil {
		t.Fatalf("the relay's own report does not validate: %v", err)
	}
}

func TestRelayADCSDatabaseRefusesWithoutRunningCertutil(t *testing.T) {
	script, argsFile := certutilStandIn(t, certutilCSV, 0)
	for name, tc := range map[string]struct {
		certutil, ca, want string
	}{
		"option-shaped CA": {script, "-delete", "not a CA database read"},
		"CA without host":  {script, "CORP-CA", "not a CA database read"},
		"no certutil":      {"", `ca01.corp.example\CORP-CA`, "domain-joined Windows relay"},
	} {
		t.Run(name, func(t *testing.T) {
			useCertutil(t, tc.certutil)
			ch := &fakeChannel{jobs: []relay.Job{adcsDatabaseJob(t, tc.ca)}}
			if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil {
				t.Fatal(err)
			}
			if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, tc.want) {
				t.Fatalf("reports = %+v", ch.reports)
			}
			if _, err := os.Stat(argsFile); err == nil {
				t.Fatal("certutil ran for a read the relay refused")
			}
		})
	}
}

func TestRelayADCSDatabaseFailedCertutilIsAFailedRead(t *testing.T) {
	script, _ := certutilStandIn(t, "", 1)
	useCertutil(t, script)
	ch := &fakeChannel{jobs: []relay.Job{adcsDatabaseJob(t, `ca01.corp.example\CORP-CA`)}}
	if _, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, "certutil could not read") {
		t.Fatalf("reports = %+v", ch.reports)
	}
}

func TestADCSDatabaseReportMustMatchTheQueuedRead(t *testing.T) {
	intent := relay.ADCSDatabaseIntent{CAConfig: `ca01.corp.example\CORP-CA`}
	good := relay.ADCSDatabaseReport{CAConfig: intent.CAConfig, Summary: adcsdb.DBSummary{Issued: 2, Pending: 1, Total: 3, Unparsed: 1}, RowsRead: 4, RowsRejected: 1}
	if err := relay.ValidateADCSDatabaseReport(intent, good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*relay.ADCSDatabaseReport){
		"another CA":        func(r *relay.ADCSDatabaseReport) { r.CAConfig = `ca02.corp.example\EDGE-CA` },
		"total off":         func(r *relay.ADCSDatabaseReport) { r.Summary.Total = 9 },
		"rows off":          func(r *relay.ADCSDatabaseReport) { r.RowsRead = 3 },
		"negative":          func(r *relay.ADCSDatabaseReport) { r.Summary.Pending, r.Summary.Issued = -1, 4 },
		"unparsed > issued": func(r *relay.ADCSDatabaseReport) { r.Summary.Unparsed = 3 },
	} {
		bad := good
		mutate(&bad)
		if err := relay.ValidateADCSDatabaseReport(intent, bad); err == nil {
			t.Errorf("%s: the report validated", name)
		}
	}
}
