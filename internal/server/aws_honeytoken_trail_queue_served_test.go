// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// n4l1SQSStandIn is SQS's query API for one queue (ReceiveMessage and
// DeleteMessageBatch, written from SQS's API reference): messages wait until
// deleted.
type n4l1SQSStandIn struct {
	*httptest.Server
	mu       sync.Mutex
	messages map[string]string // receipt -> body
	next     int
	deleted  []string
}

func newN4L1SQSStandIn(t *testing.T) *n4l1SQSStandIn {
	t.Helper()
	q := &n4l1SQSStandIn{messages: map[string]string{}}
	q.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || !strings.Contains(r.Header.Get("Authorization"), "/sqs/aws4_request") ||
			!strings.HasSuffix(r.Form.Get("QueueUrl"), "/123456789012/n4l1-trail") {
			http.Error(w, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>", http.StatusForbidden)
			return
		}
		q.mu.Lock()
		defer q.mu.Unlock()
		switch r.Form.Get("Action") {
		case "ReceiveMessage":
			var b strings.Builder
			for receipt, body := range q.messages {
				escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(body)
				b.WriteString("<Message><ReceiptHandle>" + receipt + "</ReceiptHandle><Body>" + escaped + "</Body></Message>")
			}
			_, _ = fmt.Fprintf(w, `<ReceiveMessageResponse><ReceiveMessageResult>%s</ReceiveMessageResult></ReceiveMessageResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		case "DeleteMessageBatch":
			var b strings.Builder
			for i := 1; r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.Id", i)) != ""; i++ {
				receipt := r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.ReceiptHandle", i))
				delete(q.messages, receipt)
				q.deleted = append(q.deleted, receipt)
				b.WriteString("<DeleteMessageBatchResultEntry><Id>" + r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.Id", i)) + "</Id></DeleteMessageBatchResultEntry>")
			}
			_, _ = fmt.Fprintf(w, `<DeleteMessageBatchResponse><DeleteMessageBatchResult>%s</DeleteMessageBatchResult></DeleteMessageBatchResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
		default:
			http.Error(w, "<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>", http.StatusBadRequest)
		}
	}))
	t.Cleanup(q.Close)
	return q
}

func (q *n4l1SQSStandIn) send(body string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.next++
	q.messages[fmt.Sprintf("n4l1-receipt-%d", q.next)] = body
}

func (q *n4l1SQSStandIn) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.messages)
}

// N4-L1: a trail with notifications_queue_url reads the log files the
// bucket's notifications name instead of listing every account, Region and
// day folder. On its first pass it lists the bucket once in full and reads
// what was there before the queue; after that a pass reads the file an S3
// event notification names without a single listing, deletes that message
// with S3's test event and a notification for another bucket, and the
// decoy's uses from both files are found in the trail. The account catalog
// names the queue.
func TestServedAWSHoneyTrailReadsItsNotificationsN4L1(t *testing.T) {
	const organization, decoyAccount = "o-n4l1queue1", "123456789012"
	s3 := s3test.NewServer(t)
	sqs := newN4L1SQSStandIn(t)
	now := time.Now().UTC()
	logFile := func(key, eventID string) []byte {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"Records": []map[string]any{{
			"eventVersion": "1.10", "eventTime": now.Add(-time.Minute).Format(time.RFC3339), "eventSource": "s3.amazonaws.com",
			"eventName": "GetObject", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.41", "userAgent": "aws-cli/2.18.4",
			"eventID": eventID, "eventCategory": "Data", "recipientAccountId": decoyAccount,
			"userIdentity": map[string]any{"type": "IAMUser", "accountId": decoyAccount, "accessKeyId": key},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(raw)
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	logName := func(suffix string) string {
		return fmt.Sprintf("AWSLogs/%s/%s/CloudTrail/us-east-1/%s/%s_CloudTrail_us-east-1_%sZ_%s.json.gz", organization, decoyAccount,
			now.Format("2006/01/02"), decoyAccount, now.Format("20060102T1504"), suffix)
	}

	fake := newServedAWSHoneyFixture(t)
	fake.nextKeyID, fake.nextSecret = "AKIAN4L1QUEUED01", "fake-n4l1-decoy-value"
	callerPath := filepath.Join(t.TempDir(), "aws-trail-session.json")
	caller, _ := json.Marshal(map[string]any{ // #nosec G101 -- the test's own stand-in session values, not credentials (CWE-798)
		"access_key_id": s3.AccessKeyID, "secret_access_key": "n4l1-caller-value", "session_token": "n4l1-caller-session",
		"expires_at": now.Add(time.Hour).Format(time.RFC3339),
	})
	if err := os.WriteFile(callerPath, caller, 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true, AllowCIDRs: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.NewString() // its own tenant: other served tests leave decoys on the shared one (AUD30)
	queueURL := sqs.URL + "/123456789012/n4l1-trail"
	cfg := config.AWSHoneyAccountConfig{
		TenantID: tenant, ID: "n4l1-aws", AccountID: decoyAccount, Regions: []string{"us-east-1"},
		IAMCredentialsRef: "file:" + callerPath, CloudTrailCredentialsRef: "file:" + callerPath,
		IAMEndpoint: fake.URL, CloudTrailEndpoints: map[string]string{"us-east-1": fake.URL},
		MaxTTL: "48h", PollInterval: "1m", AllowPrivate: true, AllowInsecureLoopback: true,
		PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		Trail: &config.AWSHoneyTrailConfig{Bucket: s3.Bucket, BucketRegion: "us-east-1", OrganizationID: organization,
			S3Endpoint: s3.URL, PathStyle: true, CredentialsRef: "file:" + callerPath, NotificationsQueueURL: queueURL},
	}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{HoneyAWSAccounts: []config.AWSHoneyAccountConfig{cfg}}, true); err != nil {
		t.Fatalf("the account attachment as configured: %v", err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		accounts, buildErr := awsHoneyAccountsFromConfig([]config.AWSHoneyAccountConfig{cfg}, d.Store, d.KEK, guard, nil)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		d.TenantAWSHoneyAccounts = accounts
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: accounts.ForTenant(tenant)}
	})
	h.tenant = tenant
	registerServedTenantID(t, h, tenant, "N4-L1 trail tenant")
	startServedExternalCADispatcher(t, h)
	owner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", owner, "n4l1-decoy",
		map[string]any{"account_id": "n4l1-aws", "name": "queue-bait", "placement": "qa/queue", "ttl_seconds": 86400})
	var created struct {
		ID          string `json:"id"`
		AccessKeyID string `json:"access_key_id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.AccessKeyID == "" {
		t.Fatalf("create the AWS decoy: HTTP %d", status)
	}
	listings := func() int {
		n := 0
		for _, request := range s3.Requests() {
			if request == "GET " {
				n++
			}
		}
		return n
	}

	// First pass: the bucket is listed once in full; the file delivered
	// before the queue was set up is read.
	s3.Seed(logName("backlog"), logFile(created.AccessKeyID, "n4l1-backlog-1"))
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 1 || listings() == 0 {
		t.Fatalf("the first pass read %d files (listings %d): %v", n, listings(), err)
	}
	listedBefore := listings()

	// A later pass reads what the notifications name, with no listing.
	notified := logName("notified")
	s3.Seed(notified, logFile(created.AccessKeyID, "n4l1-notified-1"))
	sqs.send(`{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"` + s3.Bucket +
		`"},"object":{"key":"` + url.QueryEscape(notified) + `"}}}]}`)
	sqs.send(`{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"` + s3.Bucket + `"}`)
	sqs.send(`{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"another-bucket"},"object":{"key":"` +
		url.QueryEscape(logName("elsewhere")) + `"}}}]}`)
	h.srv.awsHoneyTrailClock.forget(tenant + "\x00n4l1-aws")
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("the notified pass read %d files: %v", n, err)
	}
	if listings() != listedBefore || sqs.pending() != 0 {
		t.Fatalf("the notified pass listed the bucket %d more times and left %d messages", listings()-listedBefore, sqs.pending())
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/"+created.ID, owner, nil)
	var detail struct {
		State string `json:"state"`
		Uses  []struct {
			EventID string `json:"event_id"`
			FoundIn string `json:"found_in"`
		} `json:"uses"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &detail) != nil {
		t.Fatalf("decoy detail: HTTP %d", status)
	}
	found := map[string]string{}
	for _, use := range detail.Uses {
		found[use.EventID] = use.FoundIn
	}
	if detail.State != "triggered" || found["n4l1-backlog-1"] != "trail" || found["n4l1-notified-1"] != "trail" {
		t.Fatalf("decoy after the trail reads: state %s uses %v", detail.State, found)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/accounts", owner, nil)
	var catalog struct {
		Accounts []struct {
			Trail *struct {
				NotificationsQueueURL string `json:"notifications_queue_url"`
			} `json:"trail"`
		} `json:"accounts"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil || len(catalog.Accounts) != 1 || catalog.Accounts[0].Trail == nil ||
		catalog.Accounts[0].Trail.NotificationsQueueURL != queueURL {
		t.Fatalf("account catalog: HTTP %d %s", status, body)
	}
	if h.logContains(t, "n4l1-caller-session") {
		t.Fatal("the trail reader's session token reached the event log")
	}
	t.Logf("N4L1_TRAIL_QUEUE_OK listings_after_first_pass=%d deleted=%d", listings()-listedBefore, len(sqs.deleted))
}
