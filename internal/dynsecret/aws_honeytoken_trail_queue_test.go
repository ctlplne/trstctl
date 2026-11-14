// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// N4-L1: a trail's notifications name the bucket and keys to read, whichever
// way they reach the queue: an S3 event notification (keys URL-encoded), the
// same through EventBridge, either wrapped in an SNS envelope, or the trail's
// own SNS notification. S3's test event, another event and a body that is
// not a notification name nothing.
func TestParseAWSTrailNotificationReadsEveryShapeN4L1(t *testing.T) {
	const key = "AWSLogs/o-n4l1/123456789012/CloudTrail/us-east-1/2026/11/14/123456789012_CloudTrail_us-east-1_20261114T0900Z_n4l1.json.gz"
	s3Event := `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"trail-n4l1"},"object":{"key":"` +
		url.QueryEscape(key) + `"}}}]}`
	for name, c := range map[string]struct {
		body   string
		bucket string
		keys   []string
	}{
		"an S3 event":          {s3Event, "trail-n4l1", []string{key}},
		"through EventBridge":  {`{"version":"0","source":"aws.s3","detail-type":"Object Created","detail":{"bucket":{"name":"trail-n4l1"},"object":{"key":"` + key + `"}}}`, "trail-n4l1", []string{key}},
		"in an SNS envelope":   {`{"Type":"Notification","Message":` + jsonString(s3Event) + `}`, "trail-n4l1", []string{key}},
		"CloudTrail's own SNS": {`{"Type":"Notification","Message":` + jsonString(`{"s3Bucket":"trail-n4l1","s3ObjectKey":["`+key+`"]}`) + `}`, "trail-n4l1", []string{key}},
	} {
		bucket, keys, ok := ParseAWSTrailNotification([]byte(c.body))
		if !ok || bucket != c.bucket || strings.Join(keys, ",") != strings.Join(c.keys, ",") {
			t.Fatalf("%s = %q %v %v", name, bucket, keys, ok)
		}
	}
	for name, body := range map[string]string{
		"S3's test event": `{"Service":"Amazon S3","Event":"s3:TestEvent","Time":"2026-11-14T09:00:00Z","Bucket":"trail-n4l1"}`,
		"a deletion":      `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"trail-n4l1"},"object":{"key":"x"}}}]}`,
		"not JSON":        `hello`,
		"nested twice":    `{"Type":"Notification","Message":` + jsonString(`{"Type":"Notification","Message":`+jsonString(s3Event)+`}`) + `}`,
	} {
		if _, keys, _ := ParseAWSTrailNotification([]byte(body)); len(keys) != 0 {
			t.Fatalf("%s named %v", name, keys)
		}
	}
	if ValidAWSSQSQueueURL("https://sqs.us-east-1.amazonaws.com/notanaccount/q") || !ValidAWSSQSQueueURL("https://sqs.us-east-1.amazonaws.com/123456789012/trail-n4l1") {
		t.Fatal("queue URL validation")
	}
	if AWSSQSQueueRegion("https://sqs.eu-west-2.amazonaws.com/123456789012/q", "us-east-1") != "eu-west-2" ||
		AWSSQSQueueRegion("http://127.0.0.1:4566/123456789012/q", "us-east-1") != "us-east-1" {
		t.Fatal("queue Region")
	}
}

func jsonString(s string) string {
	return fmt.Sprintf("%q", s)
}

// sqsDouble is SQS's query API for one queue (ReceiveMessage and
// DeleteMessageBatch, from SQS's API reference).
type sqsDouble struct {
	mu       sync.Mutex
	bodies   map[string]string // receipt -> body
	deleted  []string
	failNext bool
	auth     []string
}

func (d *sqsDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auth = append(d.auth, r.Header.Get("Authorization"))
	if r.Form.Get("QueueUrl") == "" || r.Form.Get("Version") != "2012-11-05" {
		http.Error(w, "<ErrorResponse><Error><Code>MissingParameter</Code></Error></ErrorResponse>", http.StatusBadRequest)
		return
	}
	switch r.Form.Get("Action") {
	case "ReceiveMessage":
		var b strings.Builder
		for receipt, body := range d.bodies {
			b.WriteString("<Message><MessageId>m-" + receipt + "</MessageId><ReceiptHandle>" + receipt + "</ReceiptHandle><Body>" + xmlEscape(body) + "</Body></Message>")
		}
		_, _ = fmt.Fprintf(w, `<ReceiveMessageResponse><ReceiveMessageResult>%s</ReceiveMessageResult></ReceiveMessageResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "DeleteMessageBatch":
		var ok, failed strings.Builder
		for i := 1; r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.Id", i)) != ""; i++ {
			id := r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.Id", i))
			receipt := r.Form.Get(fmt.Sprintf("DeleteMessageBatchRequestEntry.%d.ReceiptHandle", i))
			if d.failNext {
				failed.WriteString("<BatchResultErrorEntry><Id>" + id + "</Id><Code>ReceiptHandleIsInvalid</Code></BatchResultErrorEntry>")
				continue
			}
			delete(d.bodies, receipt)
			d.deleted = append(d.deleted, receipt)
			ok.WriteString("<DeleteMessageBatchResultEntry><Id>" + id + "</Id></DeleteMessageBatchResultEntry>")
		}
		_, _ = fmt.Fprintf(w, `<DeleteMessageBatchResponse><DeleteMessageBatchResult>%s%s</DeleteMessageBatchResult></DeleteMessageBatchResponse>`, ok.String(), failed.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	default:
		http.Error(w, "<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>", http.StatusBadRequest)
	}
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// N4-L1: the queue client receives the trail's notifications signed for SQS
// in the queue's Region, names each message's files, and deletes handled
// messages in batches; a message SQS could not delete is an error.
func TestAWSTrailQueueReceivesAndDeletesN4L1(t *testing.T) {
	const key = "AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/14/123456789012_CloudTrail_us-east-1_20261114T0900Z_q.json.gz"
	double := &sqsDouble{bodies: map[string]string{
		"r1": `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"trail-q"},"object":{"key":"` + key + `"}}}]}`,
		"r2": `{"Service":"Amazon S3","Event":"s3:TestEvent"}`,
	}}
	server := httptest.NewServer(double)
	t.Cleanup(server.Close)
	queue, err := NewAWSTrailQueue(AWSTrailQueueConfig{QueueURL: server.URL + "/123456789012/trail-q", Region: "us-east-1",
		HTTPClient: server.Client(), AccessKeyID: "AKIDN4L1", SecretAccessKey: []byte("n4l1-signing-value")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(queue.Close)
	messages, err := queue.Receive(context.Background(), 10)
	if err != nil || len(messages) != 2 {
		t.Fatalf("receive = %+v %v", messages, err)
	}
	byReceipt := map[string]AWSTrailMessage{}
	for _, m := range messages {
		byReceipt[m.Receipt] = m
	}
	if m := byReceipt["r1"]; m.Bucket != "trail-q" || len(m.Keys) != 1 || m.Keys[0] != key {
		t.Fatalf("the notification = %+v", m)
	}
	if m := byReceipt["r2"]; len(m.Keys) != 0 {
		t.Fatalf("the test event named %v", m.Keys)
	}
	if err := queue.Delete(context.Background(), []string{"r1", "r2"}); err != nil {
		t.Fatal(err)
	}
	double.mu.Lock()
	deleted, auth := strings.Join(double.deleted, ","), double.auth[0]
	double.failNext = true
	double.bodies["r3"] = "{}"
	double.mu.Unlock()
	if deleted != "r1,r2" || !strings.Contains(auth, "/us-east-1/sqs/aws4_request") {
		t.Fatalf("deleted %q; authorization %q", deleted, auth)
	}
	if err := queue.Delete(context.Background(), []string{"r3"}); err == nil || !strings.Contains(err.Error(), "ReceiptHandleIsInvalid") {
		t.Fatalf("a failed delete = %v", err)
	}
	if _, err := NewAWSTrailQueue(AWSTrailQueueConfig{QueueURL: "https://sqs.us-east-1.amazonaws.com/q", Region: "us-east-1",
		AccessKeyID: "AKIDN4L1", SecretAccessKey: []byte("n4l1-signing-value")}); err == nil {
		t.Fatal("a queue URL without an account was accepted")
	}
}
