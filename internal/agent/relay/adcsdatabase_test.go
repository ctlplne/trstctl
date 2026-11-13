// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"fmt"
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
// argument vector; per-disposition counts return, and (N1-L2) the requests
// the CA holds for a manager's approval, as an operator needs them to decide.

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

// TestRelayADCSDatabaseReadReturnsCountsAndThePendingRequests: no
// certificate, serial, or issued, revoked or failed row's name or requester
// leaves the relay; the one pending request leaves with its id, template and
// requester (N1-L2).
func TestRelayADCSDatabaseReadReturnsCountsAndThePendingRequests(t *testing.T) {
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
	for _, leaked := range []string{"web01", "web02", "svc-web", "LAPTOP-9", "bob", "1a00000002", "1a00000005"} {
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
	wantPending := []relay.ADCSPendingRequest{{RequestID: 4, Template: "WebServer", Requester: `CORP\alice`}}
	if len(got.Pending) != 1 || got.Pending[0] != wantPending[0] || got.PendingTruncated || !got.PendingListed() {
		t.Fatalf("pending requests = %+v (truncated %v); want %+v", got.Pending, got.PendingTruncated, wantPending)
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

// TestADCSDatabaseReportPendingListIsCheckedN1L2: a report's pending list
// must agree with its counts, be newest first with unique ids and bounded
// printable fields, and be cut short only at the bound when more are pending.
func TestADCSDatabaseReportPendingListIsCheckedN1L2(t *testing.T) {
	intent := relay.ADCSDatabaseIntent{CAConfig: `ca01.corp.example\CORP-CA`}
	base := func(pending int, list []relay.ADCSPendingRequest, truncated bool) relay.ADCSDatabaseReport {
		return relay.ADCSDatabaseReport{CAConfig: intent.CAConfig, Summary: adcsdb.DBSummary{Pending: pending, Total: pending}, RowsRead: pending,
			Pending: list, PendingTruncated: truncated}
	}
	two := []relay.ADCSPendingRequest{{RequestID: 9, Template: "WebServer"}, {RequestID: 7, Requester: `CORP\bob`}}
	if err := relay.ValidateADCSDatabaseReport(intent, base(2, two, false)); err != nil {
		t.Fatalf("a complete list: %v", err)
	}
	if base(2, nil, false).PendingListed() {
		t.Fatal("a count without a list (a relay from before N1-L2) reads as listed")
	}
	if !base(0, nil, false).PendingListed() {
		t.Fatal("no pending request does not read as an empty list")
	}
	for name, r := range map[string]relay.ADCSDatabaseReport{
		"more listed than counted":  base(1, two, false),
		"fewer listed than counted": base(3, two, false),
		"oldest first":              base(2, []relay.ADCSPendingRequest{two[1], two[0]}, false),
		"repeated id":               base(2, []relay.ADCSPendingRequest{two[0], two[0]}, false),
		"no id":                     base(1, []relay.ADCSPendingRequest{{Template: "WebServer"}}, false),
		"control characters":        base(1, []relay.ADCSPendingRequest{{RequestID: 3, Requester: "CORP\\eve\n"}}, false),
		"cut short below the bound": base(3, two, true),
	} {
		if err := relay.ValidateADCSDatabaseReport(intent, r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	full := make([]relay.ADCSPendingRequest, relay.MaxADCSPendingRequests)
	for i := range full {
		full[i] = relay.ADCSPendingRequest{RequestID: relay.MaxADCSPendingRequests + 10 - i}
	}
	if err := relay.ValidateADCSDatabaseReport(intent, base(relay.MaxADCSPendingRequests+3, full, true)); err != nil {
		t.Fatalf("a list cut short at the bound: %v", err)
	}
	if err := relay.ValidateADCSDatabaseReport(intent, base(relay.MaxADCSPendingRequests+3, full, false)); err == nil {
		t.Fatal("a list at the bound that does not say it is cut short was accepted")
	}
}

// certutilPagingStandIn writes a POSIX stand-in that serves out the way
// certutil does: every row for a plain view, the request-id column for -out
// RequestID, and only the rows in range for -restrict
// "RequestID>lo,RequestID<=hi". Each invocation's argv is appended to the
// log, one line per invocation.
func certutilPagingStandIn(t *testing.T, out string) (script, argsLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	dir := t.TempDir()
	argsLog = filepath.Join(dir, "args")
	data := filepath.Join(dir, "view.csv")
	if err := os.WriteFile(data, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(dir, "certutil")
	body := `#!/bin/sh
echo "$*" >> '` + argsLog + `'
cols=""; restrict=""; prev=""
for a in "$@"; do
  [ "$prev" = "-out" ] && cols="$a"
  [ "$prev" = "-restrict" ] && restrict="$a"
  prev="$a"
done
if [ "$cols" = "RequestID" ]; then
  awk 'NR==1 { print "\"Issued Request ID\""; next } { split($0, f, "\",\""); id=f[1]; gsub(/"/, "", id); print "\"" id "\"" }' '` + data + `'
  exit 0
fi
if [ -n "$restrict" ]; then
  lo=$(echo "$restrict" | sed -n 's/^RequestID>\([0-9]*\),RequestID<=\([0-9]*\)$/\1/p')
  hi=$(echo "$restrict" | sed -n 's/^RequestID>\([0-9]*\),RequestID<=\([0-9]*\)$/\2/p')
  awk -v lo="$lo" -v hi="$hi" 'NR==1 { print; next } { split($0, f, "\",\""); id=f[1]; gsub(/"/, "", id); if (id ~ /^[0-9]+$/ && id+0 > lo+0 && id+0 <= hi+0) print }' '` + data + `'
  exit 0
fi
cat '` + data + `'
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script, argsLog
}

// A162-L1: a CA database whose rows exceed one certutil read's byte bound is
// read in pages of request ids — each page under the bound, a page still
// over it halved — and summarized exactly as one read of every row would be,
// with a row that names no request id still counted as rejected.
func TestRelayADCSDatabaseReadsALargeDatabaseInPagesA162L1(t *testing.T) {
	header := strings.SplitN(certutilCSV, "\n", 2)[0]
	var b strings.Builder
	b.WriteString(header + "\n")
	for id := 10; id <= 21; id++ {
		fmt.Fprintf(&b, "\"%d\",\"20 -- Issued\",\"1a000000%d\",\"10/1/2026 9:00 AM\",\"10/1/2027 9:00 AM\",\"host%d.corp.example\",\"WebServer\",\"CORP\\svc\",\"EMPTY\"\n", id, id, id)
	}
	b.WriteString("\"EMPTY\",\"30 -- Error\",\"EMPTY\",\"EMPTY\",\"EMPTY\",\"EMPTY\",\"EMPTY\",\"CORP\\bob\",\"EMPTY\"\n")
	out := b.String()
	rowLen := len(strings.SplitN(out, "\n", 3)[1]) + 1
	bound := int64(len(header) + 1 + 6*rowLen) // five rows fit; the whole database does not
	run := func(pageRows int) (relay.ADCSDatabaseReport, []string) {
		t.Helper()
		script, argsLog := certutilPagingStandIn(t, out)
		useCertutil(t, script)
		restore := relay.SetCertutilPagingForTest(bound, pageRows)
		defer restore()
		ch := &fakeChannel{jobs: []relay.Job{adcsDatabaseJob(t, `ca01.corp.example\CORP-CA`)}}
		if executed, err := relay.RunOnce(t.Context(), ch, nil, 1, 60); err != nil || executed != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
			t.Fatalf("executed = %d, %v; reports %+v", executed, err, ch.reports)
		}
		var got relay.ADCSDatabaseReport
		if err := json.Unmarshal([]byte(ch.reports[0].detail), &got); err != nil {
			t.Fatal(err)
		}
		if err := relay.ValidateADCSDatabaseReport(relay.ADCSDatabaseIntent{CAConfig: `ca01.corp.example\CORP-CA`}, got); err != nil {
			t.Fatalf("the paged report does not validate: %v", err)
		}
		raw, err := os.ReadFile(argsLog) // #nosec G304 -- test-owned temp file (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		return got, strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	restricts := func(calls []string) []string {
		var out []string
		for _, c := range calls {
			if _, after, found := strings.Cut(c, "-restrict "); found {
				out = append(out, strings.Fields(after)[0])
			}
		}
		return out
	}
	want := adcsdb.DBSummary{Issued: 12, Total: 12}

	got, calls := run(5)
	if got.Summary != want || got.RowsRead != 13 || got.RowsRejected != 1 {
		t.Fatalf("paged report = %+v", got)
	}
	if len(calls) != 5 || !strings.Contains(calls[0], "-out "+"RequestID,Request.Disposition") || !strings.Contains(calls[1], "-out RequestID csv") ||
		strings.Join(restricts(calls), " ") != "RequestID>0,RequestID<=14 RequestID>14,RequestID<=19 RequestID>19,RequestID<=21" {
		t.Fatalf("certutil calls = %q", calls)
	}

	// One page of every id is still over the bound: it is halved until each
	// part fits, and the summary is unchanged.
	got, calls = run(100)
	if got.Summary != want || got.RowsRead != 13 || got.RowsRejected != 1 {
		t.Fatalf("halved report = %+v", got)
	}
	if strings.Join(restricts(calls), " ") != "RequestID>0,RequestID<=21 RequestID>0,RequestID<=15 RequestID>15,RequestID<=21" {
		t.Fatalf("halved certutil restrictions = %q", restricts(calls))
	}
}
