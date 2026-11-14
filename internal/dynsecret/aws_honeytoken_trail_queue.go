// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// N4-L1: a trail bucket's object-created notifications, read from an SQS
// queue instead of listing every account, Region and day folder. The queue
// may receive S3 event notifications directly, through EventBridge, or the
// trail's own SNS notifications (CloudTrail publishes each delivered file's
// key); each message names the log files to read, so a large organization's
// bucket is read without listing it.

const (
	awsSQSVersion = "2012-11-05"
	// awsTrailQueueMaxKeys bounds the keys one message may name.
	awsTrailQueueMaxKeys = 100
	// awsTrailQueueVisibility is how long a received message stays hidden
	// before SQS hands it out again (a file not read in that time).
	awsTrailQueueVisibility = "300"
)

var awsSQSQueuePath = regexp.MustCompile(`^/[0-9]{12}/[A-Za-z0-9_-]{1,80}(\.fifo)?$`)

// ValidAWSSQSQueueURL reports whether raw is a queue URL: a scheme, a host
// and /<account>/<queue name>.
func ValidAWSSQSQueueURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && awsSQSQueuePath.MatchString(u.Path)
}

// AWSSQSQueueRegion is the Region a queue URL names (sqs.<region>.…), or
// fallback for one that names none.
func AWSSQSQueueRegion(queueURL, fallback string) string {
	u, err := url.Parse(queueURL)
	if err != nil {
		return fallback
	}
	parts := strings.Split(u.Hostname(), ".")
	if len(parts) >= 3 && parts[0] == "sqs" && awsTrailRegion.MatchString(parts[1]) {
		return parts[1]
	}
	return fallback
}

// AWSTrailQueue reads one queue of a trail bucket's notifications with the
// trail's own credentials.
type AWSTrailQueue struct {
	client   *AWSIAMBackend
	queueURL string
}

// AWSTrailQueueConfig opens a queue.
type AWSTrailQueueConfig struct {
	QueueURL        string
	Region          string
	HTTPClient      HTTPDoer
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
}

// NewAWSTrailQueue opens the queue; requests go to the queue URL's host,
// signed for SQS in its Region.
func NewAWSTrailQueue(cfg AWSTrailQueueConfig) (*AWSTrailQueue, error) {
	if !ValidAWSSQSQueueURL(cfg.QueueURL) {
		return nil, errors.New("dynsecret aws trail: notifications_queue_url is not an SQS queue URL")
	}
	u, err := url.Parse(cfg.QueueURL)
	if err != nil {
		return nil, err
	}
	client, err := NewAWSIAMBackend(AWSIAMConfig{Endpoint: u.Scheme + "://" + u.Host, HTTPClient: cfg.HTTPClient, Region: cfg.Region,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey, SessionToken: cfg.SessionToken})
	if err != nil {
		return nil, fmt.Errorf("dynsecret aws trail: open the notifications queue: %w", err)
	}
	return &AWSTrailQueue{client: client, queueURL: cfg.QueueURL}, nil
}

// Close wipes the queue's credentials.
func (q *AWSTrailQueue) Close() { q.client.Close() }

// AWSTrailMessage is one received message: its receipt, and the bucket and
// object keys it names. A message that is not a notification names none and
// is deleted unread.
type AWSTrailMessage struct {
	Receipt string
	Bucket  string
	Keys    []string
}

// Receive takes up to max (1-10) messages without waiting; each stays
// hidden from other readers for five minutes.
func (q *AWSTrailQueue) Receive(ctx context.Context, max int) ([]AWSTrailMessage, error) {
	if max < 1 || max > 10 {
		max = 10
	}
	raw, err := q.client.callService(ctx, map[string]string{
		"Action": "ReceiveMessage", "Version": awsSQSVersion, "QueueUrl": q.queueURL,
		"MaxNumberOfMessages": strconv.Itoa(max), "WaitTimeSeconds": "0", "VisibilityTimeout": awsTrailQueueVisibility,
	}, "sqs")
	if err != nil {
		return nil, fmt.Errorf("dynsecret aws trail: receive notifications: %w", err)
	}
	var answer struct {
		Messages []struct {
			Receipt string `xml:"ReceiptHandle"`
			Body    string `xml:"Body"`
		} `xml:"ReceiveMessageResult>Message"`
	}
	if err := xml.Unmarshal(raw, &answer); err != nil {
		return nil, errors.New("dynsecret aws trail: the notifications queue answered something that is not ReceiveMessage")
	}
	out := make([]AWSTrailMessage, 0, len(answer.Messages))
	for _, m := range answer.Messages {
		if m.Receipt == "" {
			continue
		}
		bucket, keys, _ := ParseAWSTrailNotification([]byte(m.Body))
		out = append(out, AWSTrailMessage{Receipt: m.Receipt, Bucket: bucket, Keys: keys})
	}
	return out, nil
}

// Delete removes handled messages, ten to a request; a message SQS reports
// it could not delete is an error, and the message comes back.
func (q *AWSTrailQueue) Delete(ctx context.Context, receipts []string) error {
	for start := 0; start < len(receipts); start += 10 {
		end := min(start+10, len(receipts))
		params := map[string]string{"Action": "DeleteMessageBatch", "Version": awsSQSVersion, "QueueUrl": q.queueURL}
		for i, receipt := range receipts[start:end] {
			n := strconv.Itoa(i + 1)
			params["DeleteMessageBatchRequestEntry."+n+".Id"] = "m" + n
			params["DeleteMessageBatchRequestEntry."+n+".ReceiptHandle"] = receipt
		}
		raw, err := q.client.callService(ctx, params, "sqs")
		if err != nil {
			return fmt.Errorf("dynsecret aws trail: delete notifications: %w", err)
		}
		var answer struct {
			Failed []struct {
				ID   string `xml:"Id"`
				Code string `xml:"Code"`
			} `xml:"DeleteMessageBatchResult>BatchResultErrorEntry"`
		}
		if err := xml.Unmarshal(raw, &answer); err != nil {
			return errors.New("dynsecret aws trail: the notifications queue answered something that is not DeleteMessageBatch")
		}
		if len(answer.Failed) > 0 {
			return fmt.Errorf("dynsecret aws trail: %d notifications were not deleted (%s)", len(answer.Failed), answer.Failed[0].Code)
		}
	}
	return nil
}

// ParseAWSTrailNotification reads the bucket and object keys a queue
// message names: an S3 event notification (object keys URL-encoded), the
// same through EventBridge, either wrapped in an SNS envelope, or the
// trail's own SNS notification (s3Bucket, s3ObjectKey). ok is false for
// anything else, such as S3's test event; keys are capped at 100.
func ParseAWSTrailNotification(body []byte) (string, []string, bool) {
	return parseAWSTrailNotification(body, true)
}

func parseAWSTrailNotification(body []byte, unwrap bool) (string, []string, bool) {
	var msg struct {
		// SNS envelope
		Type    string `json:"Type"`
		Message string `json:"Message"`
		// S3 event notification
		Records []struct {
			EventSource string `json:"eventSource"`
			EventName   string `json:"eventName"`
			S3          struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key string `json:"key"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
		// EventBridge
		Source     string `json:"source"`
		DetailType string `json:"detail-type"`
		Detail     struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"detail"`
		// CloudTrail's own SNS notification
		S3Bucket    string   `json:"s3Bucket"`
		S3ObjectKey []string `json:"s3ObjectKey"`
	}
	if json.Unmarshal(body, &msg) != nil {
		return "", nil, false
	}
	decode := func(key string) string {
		if decoded, err := url.QueryUnescape(key); err == nil {
			return decoded
		}
		return key
	}
	switch {
	case unwrap && msg.Type == "Notification" && msg.Message != "":
		return parseAWSTrailNotification([]byte(msg.Message), false)
	case len(msg.Records) > 0:
		bucket, keys := "", []string{}
		for _, r := range msg.Records {
			if r.EventSource != "aws:s3" || !strings.HasPrefix(r.EventName, "ObjectCreated:") || r.S3.Object.Key == "" {
				continue
			}
			if bucket == "" {
				bucket = r.S3.Bucket.Name
			}
			if r.S3.Bucket.Name != bucket || len(keys) == awsTrailQueueMaxKeys {
				continue
			}
			keys = append(keys, decode(r.S3.Object.Key))
		}
		return bucket, keys, bucket != ""
	case msg.Source == "aws.s3" && msg.DetailType == "Object Created" && msg.Detail.Object.Key != "":
		return msg.Detail.Bucket.Name, []string{decode(msg.Detail.Object.Key)}, msg.Detail.Bucket.Name != ""
	case msg.S3Bucket != "" && len(msg.S3ObjectKey) > 0:
		keys := msg.S3ObjectKey
		if len(keys) > awsTrailQueueMaxKeys {
			keys = keys[:awsTrailQueueMaxKeys]
		}
		return msg.S3Bucket, append([]string(nil), keys...), true
	}
	return "", nil, false
}
