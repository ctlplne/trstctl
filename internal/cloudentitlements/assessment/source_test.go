// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCloudSourceRejectsAmbiguousCredentialReferenceA264(t *testing.T) {
	raw := []byte(`{"session_file_ref":"env:APPROVED","SESSION_FILE_REF":"env:UNAPPROVED","principals":[{"kind":"iam_user","name":"workload"}],"assessment":{"checks":[{"principal_arn":"arn:aws:iam::111122223333:user/workload","action":"s3:GetObject","resource":"arn:aws:s3:::owned/report","resource_account_id":"111122223333","context":{"complete":true}}]}}`)
	if _, err := DecodeSource(raw); err == nil {
		t.Fatal("case alias bypassed the operator credential-reference field")
	}
	duplicate := bytes.Replace(raw, []byte(`"SESSION_FILE_REF"`), []byte(`"session_file_ref"`), 1)
	if _, err := DecodeSource(duplicate); err == nil {
		t.Fatal("duplicate source field accepted")
	}
}
func FuzzCloudMachineSource(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"session_file_ref":"env:APPROVED","principals":[{"kind":"iam_user","name":"workload"}],"assessment":{"checks":[{"principal_arn":"arn:aws:iam::111122223333:user/workload","action":"s3:GetObject","resource":"arn:aws:s3:::owned/report","resource_account_id":"111122223333","context":{"complete":false}}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 768<<10 {
			return
		}
		cfg, err := DecodeSource(raw)
		if err == nil {
			round, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeSource(round); err != nil {
				t.Fatal("accepted source failed typed round trip")
			}
		}
	})
}
func FuzzCloudAssessmentRecord(f *testing.F) {
	f.Add([]byte(`{"version":1,"provider":"aws-iam"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2<<20 {
			return
		}
		value, err := DecodeAssessment(raw)
		if err == nil {
			_, _ = Fingerprint(value)
		}
	})
}
