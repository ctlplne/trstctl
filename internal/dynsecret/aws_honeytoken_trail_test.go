// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

func gzipped(t *testing.T, body string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

// N4: a log file is read record by record; only a decoy key's records come
// back — management and data events, logged in the decoy's account or in the
// account whose resource it reached — with their text bounded.
func TestScanCloudTrailLogFileFindsDecoyRecordsN4(t *testing.T) {
	body := `{"Records":[
	  {"eventVersion":"1.09","userIdentity":{"type":"IAMUser","accountId":"111111111111","accessKeyId":"AKIADECOY0000000001"},
	   "eventTime":"2026-11-04T08:30:01Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1",
	   "sourceIPAddress":"203.0.113.9","userAgent":"aws-cli/2.17\u0000\u202e","eventID":"ev-data-1","eventCategory":"Data",
	   "recipientAccountId":"222222222222","resources":[{"ARN":"arn:aws:s3:::payroll/2026.csv"}]},
	  {"userIdentity":{"accountId":"111111111111","accessKeyId":"AKIAOTHER0000000002"},"eventTime":"2026-11-04T08:30:02Z",
	   "eventSource":"iam.amazonaws.com","eventName":"ListUsers","awsRegion":"us-east-1","eventID":"ev-other"},
	  {"userIdentity":{"accountId":"111111111111","accessKeyId":"AKIADECOY0000000001"},"eventTime":"2026-11-04T08:31:00Z",
	   "eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","awsRegion":"us-east-1","eventID":"ev-mgmt-1",
	   "eventCategory":"Management","recipientAccountId":"111111111111","errorCode":"AccessDenied"}
	], "digestFile": "ignored"}`
	uses, records, err := ScanCloudTrailLogFile(gzipped(t, body), map[string]bool{"AKIADECOY0000000001": true}, 0)
	if err != nil || records != 3 || len(uses) != 2 {
		t.Fatalf("scan = %d uses of %d records, %v", len(uses), records, err)
	}
	data, mgmt := uses[0], uses[1]
	if data.EventID != "ev-data-1" || data.EventCategory != "Data" || data.RecipientAccountID != "222222222222" || data.AccountID != "111111111111" ||
		data.EventName != "GetObject" || data.UserAgent != "aws-cli/2.17" || !data.EventTime.Equal(time.Date(2026, 11, 4, 8, 30, 1, 0, time.UTC)) {
		t.Fatalf("data event use = %+v", data)
	}
	if mgmt.EventCategory != "Management" || mgmt.ErrorCode != "AccessDenied" || mgmt.RecipientAccountID != "111111111111" {
		t.Fatalf("management event use = %+v", mgmt)
	}
}

func TestScanCloudTrailLogFileRefusesWhatIsNotALogFileN4(t *testing.T) {
	keys := map[string]bool{"AKIADECOY0000000001": true}
	for name, body := range map[string]string{
		"no records":      `{"digest":true}`,
		"records object":  `{"Records":{}}`,
		"truncated":       `{"Records":[{"eventID":"x"}`,
		"top-level array": `[{"eventID":"x"}]`,
		"incomplete decoy record": `{"Records":[{"userIdentity":{"accessKeyId":"AKIADECOY0000000001"},
			"eventTime":"not a time","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","eventID":"e"}]}`,
	} {
		if _, _, err := ScanCloudTrailLogFile(gzipped(t, body), keys, 0); err == nil {
			t.Fatalf("%s was read as a log file", name)
		}
	}
	if _, _, err := ScanCloudTrailLogFile(strings.NewReader(`{"Records":[]}`), keys, 0); err == nil {
		t.Fatal("an uncompressed file was read")
	}
	big := `{"Records":[` + strings.Repeat(`{"eventID":"padding-record","eventSource":"s3.amazonaws.com"},`, 2000) + `{"eventID":"z"}]}`
	if _, _, err := ScanCloudTrailLogFile(gzipped(t, big), keys, 4096); err == nil || !strings.Contains(err.Error(), "decompresses past 4096 bytes") {
		t.Fatalf("an oversized file = %v", err)
	}
	if uses, records, err := ScanCloudTrailLogFile(gzipped(t, `{"Records":[]}`), keys, 0); err != nil || records != 0 || len(uses) != 0 {
		t.Fatalf("an empty log file = %v %d %v", uses, records, err)
	}
}

func TestAWSTrailFoldersN4(t *testing.T) {
	org, err := AWSTrailAccountsPrefix("o-a1b2c3d4e5")
	if err != nil || org != "AWSLogs/o-a1b2c3d4e5/" {
		t.Fatalf("organization prefix = %q %v", org, err)
	}
	if single, _ := AWSTrailAccountsPrefix(""); single != "AWSLogs/" {
		t.Fatalf("single-account prefix = %q", single)
	}
	if _, err := AWSTrailAccountsPrefix("o-../x"); err == nil {
		t.Fatal("a malformed organization ID was accepted")
	}
	day, err := AWSTrailDayFolder(org, "111111111111", "eu-west-1", time.Date(2026, 11, 4, 23, 59, 0, 0, time.FixedZone("x", -3600)))
	if err != nil || day != "AWSLogs/o-a1b2c3d4e5/111111111111/CloudTrail/eu-west-1/2026/11/05/" {
		t.Fatalf("day folder = %q %v", day, err)
	}
	if _, err := AWSTrailDayFolder(org, "1111", "eu-west-1", time.Now()); err == nil {
		t.Fatal("a short account ID was accepted")
	}
	if !AWSTrailLogFileName(day+"111111111111_CloudTrail_eu-west-1_20261105T0005Z_a1B2c3D4e5F6g7H8.json.gz") || AWSTrailLogFileName(day+"digest.json") {
		t.Fatal("log file names misread")
	}
}
