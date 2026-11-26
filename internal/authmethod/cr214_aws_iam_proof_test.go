// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCR214AWSIAMProofRequiresSignedServerIDAndCurrentExpiry(t *testing.T) {
	const serverID = "trstctl.example.test"
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	date := now.Format("20060102T150405Z")
	signature := strings.Repeat("a", 64)
	base := AWSSignedGetCallerIdentityRequest{
		Method: http.MethodPost,
		URL:    "https://sts.amazonaws.com/",
		Body:   "Action=GetCallerIdentity&Version=2011-06-15",
		Headers: map[string][]string{
			"Authorization":      {"AWS4-HMAC-SHA256 Credential=AKIATEST/20261126/us-east-1/sts/aws4_request,SignedHeaders=host;x-amz-date;x-trstctl-aws-iam-server-id,Signature=" + signature},
			"X-Amz-Date":         {date},
			AWSIAMServerIDHeader: {serverID},
		},
	}
	check := func(name string, proof AWSSignedGetCallerIdentityRequest, want bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateAWSIAMProof(raw, serverID, now)
			if (err == nil) != want {
				t.Fatalf("proof accepted=%t, want %t: %v", err == nil, want, err)
			}
		})
	}
	check("signed POST", base, true)
	wrong := base
	wrong.Headers = map[string][]string{
		"Authorization": base.Headers["Authorization"], "X-Amz-Date": {date}, AWSIAMServerIDHeader: {"other-server"},
	}
	check("other server", wrong, false)
	unsigned := base
	unsigned.Headers = map[string][]string{
		"Authorization": {strings.Replace(base.Headers["Authorization"][0], ";x-trstctl-aws-iam-server-id", "", 1)},
		"X-Amz-Date":    {date}, AWSIAMServerIDHeader: {serverID},
	}
	check("unsigned server header", unsigned, false)
	duplicate := base
	duplicate.Headers = map[string][]string{
		"Authorization": base.Headers["Authorization"], "X-Amz-Date": {date}, AWSIAMServerIDHeader: {serverID, "other-server"},
	}
	check("duplicate server header", duplicate, false)
	duplicateSignature := base
	duplicateSignature.Headers = map[string][]string{
		"Authorization": {base.Headers["Authorization"][0] + ",Signature=" + strings.Repeat("b", 64)},
		"X-Amz-Date":    {date}, AWSIAMServerIDHeader: {serverID},
	}
	check("duplicate authorization signature", duplicateSignature, false)
	old := base
	old.Headers = map[string][]string{
		"Authorization": base.Headers["Authorization"],
		"X-Amz-Date":    {now.Add(-16 * time.Minute).Format("20060102T150405Z")}, AWSIAMServerIDHeader: {serverID},
	}
	check("stale POST", old, false)
	future := base
	future.Headers = map[string][]string{
		"Authorization": base.Headers["Authorization"],
		"X-Amz-Date":    {now.Add(6 * time.Minute).Format("20060102T150405Z")}, AWSIAMServerIDHeader: {serverID},
	}
	check("future POST", future, false)

	presigned := base
	presigned.Method = http.MethodGet
	presigned.Body = ""
	presigned.Headers = map[string][]string{AWSIAMServerIDHeader: {serverID}}
	q := url.Values{
		"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"},
		"X-Amz-Date": {date}, "X-Amz-Expires": {"60"},
		"X-Amz-SignedHeaders": {"host;x-trstctl-aws-iam-server-id"}, "X-Amz-Signature": {signature},
	}
	presigned.URL += "?" + q.Encode()
	check("presigned GET", presigned, true)
	q.Set("X-Amz-Expires", "901")
	presigned.URL = "https://sts.amazonaws.com/?" + q.Encode()
	check("presigned expiry beyond bound", presigned, false)
}
