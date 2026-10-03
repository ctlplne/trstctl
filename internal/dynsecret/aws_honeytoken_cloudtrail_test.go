// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAWSHoneyCloudTrailLookupBindsKeyAccountAndRegion(t *testing.T) {
	const key = "AKIADECOY00000001"
	start := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	seenRequest := false
	badAccount := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != awsCloudTrailTarget || !strings.Contains(r.Header.Get("Authorization"), "x-amz-target") {
			t.Errorf("CloudTrail operation target is not signed")
		}
		var request struct {
			LookupAttributes []struct {
				AttributeKey, AttributeValue string
			}
			StartTime, EndTime int64
			MaxResults         int
			NextToken          string
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if len(request.LookupAttributes) != 1 || request.LookupAttributes[0].AttributeKey != "AccessKeyId" || request.LookupAttributes[0].AttributeValue != key || request.StartTime != start.Unix() || request.EndTime != start.Add(time.Hour).Unix() || request.MaxResults != 50 {
			t.Errorf("CloudTrail query is not bounded to the exact key/window: %+v", request)
		}
		seenRequest = true
		account := "123456789012"
		if badAccount {
			account = "999999999999"
		}
		event := map[string]any{
			"eventID": "event-1", "eventTime": start.Add(time.Minute).Format(time.RFC3339),
			"eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
			"awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.10",
			"userAgent": "stock-aws-cli", "recipientAccountId": account,
			"userIdentity": map[string]string{"accountId": account, "accessKeyId": key},
		}
		body, _ := json.Marshal(event)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Events": []map[string]any{{"EventId": "event-1", "AccessKeyId": key,
				"EventName": "GetCallerIdentity", "EventSource": "sts.amazonaws.com",
				"EventTime": start.Add(time.Minute).Unix(), "CloudTrailEvent": string(body)}},
			"NextToken": "next-page",
		})
	}))
	defer server.Close()
	client, err := NewAWSHoneyCloudTrail(AWSHoneyCloudTrailConfig{
		Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1", AccountID: "123456789012",
		AccessKeyID: "CALLERKEY", SecretAccessKey: []byte("test-signing-value"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	uses, token, err := client.LookupManagementPage(context.Background(), key, start, start.Add(time.Hour), "")
	if err != nil || !seenRequest || token != "next-page" || len(uses) != 1 || uses[0].EventID != "event-1" || uses[0].SourceIPAddress != "192.0.2.10" {
		t.Fatalf("valid CloudTrail page rejected: events=%d token=%q err=%v", len(uses), token, err)
	}
	badAccount = true
	if _, _, err := client.LookupManagementPage(context.Background(), key, start, start.Add(time.Hour), token); err == nil {
		t.Fatal("wrong-account CloudTrail event was accepted")
	}
	if _, _, err := client.LookupManagementPage(context.Background(), key, start, start.Add(91*24*time.Hour), ""); err == nil {
		t.Fatal("unsupported 91-day lookup accepted")
	}
}
