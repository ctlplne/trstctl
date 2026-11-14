// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// N4-L1: a trail's notifications_queue_url is an SQS queue URL
// (/<account>/<queue>); a private or loopback queue needs
// allow_private_endpoint, as the S3 endpoint does.
func TestValidateAWSHoneyTrailNotificationsQueueN4L1(t *testing.T) {
	base := AWSHoneyAccountConfig{ // #nosec G101 -- test-only file reference paths, no credential values (CWE-798)
		TenantID: "11111111-1111-4111-8111-111111111111", ID: "security-account",
		AccountID: "123456789012", Regions: []string{"us-east-1"},
		IAMCredentialsRef:        "file:/var/lib/trstctl/iam-session.json",
		CloudTrailCredentialsRef: "file:/var/lib/trstctl/cloudtrail-session.json",
		MaxTTL:                   "720h", PollInterval: "5m",
		Trail: &AWSHoneyTrailConfig{Bucket: "org-trail-logs", BucketRegion: "us-east-1", OrganizationID: "o-a1b2c3d4e5",
			CredentialsRef:        "file:/var/lib/trstctl/trail-session.json", // #nosec G101 -- test-only file reference path (CWE-798)
			NotificationsQueueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/org-trail-notifications"},
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{HoneyAWSAccounts: []AWSHoneyAccountConfig{base}}, true); err != nil {
		t.Fatalf("a valid queue was rejected: %v", err)
	}
	for name, c := range map[string]struct {
		queue string
		want  string
	}{
		"no account":   {"https://sqs.us-east-1.amazonaws.com/org-trail-notifications", "must be an SQS queue URL"},
		"a query":      {"https://sqs.us-east-1.amazonaws.com/123456789012/q?x=1", "must be an SQS queue URL"},
		"plain HTTP":   {"http://sqs.us-east-1.amazonaws.com/123456789012/q", "notifications_queue_url"},
		"private host": {"https://10.0.0.5/123456789012/q", "requires allow_private_endpoint"},
	} {
		trail := *base.Trail
		trail.NotificationsQueueURL = c.queue
		item := base
		item.Trail = &trail
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{HoneyAWSAccounts: []AWSHoneyAccountConfig{item}}, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v; want an error naming %q", name, err, c.want)
		}
	}
}
