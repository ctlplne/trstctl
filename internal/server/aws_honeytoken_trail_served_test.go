// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/objectstore"
)

// N4 against a stock S3 API with CloudTrail's file layout: an AWS decoy
// account attachment names its organization trail, and the leader reads the
// trail's log files from LocalStack S3 (files written in CloudTrail's schema
// and layout; community LocalStack does not deliver trails). The decoy key's
// management event in its own account and its data event in another account
// are both found and trigger the decoy; another key's records are not; a file
// that is not a log file is recorded as refused; a second pass reads nothing
// again, and a newly delivered file is read.
func TestServedAWSHoneyTrailFindsDataEventsInEveryAccountN4(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned LocalStack image is not present locally: %v\n%s", err, out)
	}
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=s3", a202LocalStackImage)
	s3Endpoint := "http://" + address
	a201Await(t, "LocalStack S3", func() bool {
		resp, err := http.Get(s3Endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var health struct{ Services map[string]string }
		return json.NewDecoder(resp.Body).Decode(&health) == nil &&
			(health.Services["s3"] == "available" || health.Services["s3"] == "running")
	})
	const bucketName, organization, decoyAccount, otherAccount = "org-trail-logs", "o-a1b2c3d4e5", "123456789012", "210987654321"
	if out, err := a201Exec(localstack, "awslocal", "s3", "mb", "s3://"+bucketName); err != nil {
		t.Fatalf("make the trail bucket: %v %s", err, out)
	}
	writer, err := objectstore.Open(objectstore.Options{Endpoint: s3Endpoint, Region: "us-east-1", Bucket: bucketName, Prefix: "security/trail",
		PathStyle: true, AccessKeyID: "test", SecretAccessKey: []byte("test"), AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Destroy)
	now := time.Now().UTC()
	deliver := func(account, region, suffix string, body []byte) string {
		t.Helper()
		name := fmt.Sprintf("AWSLogs/%s/%s/CloudTrail/%s/%s/%s_CloudTrail_%s_%sZ_%s.json.gz", organization, account, region,
			now.Format("2006/01/02"), account, region, now.Format("20060102T1504"), suffix)
		if err := writer.Create(t.Context(), name, bytes.NewReader(body), int64(len(body)), crypto.SHA256Sum(body)); err != nil {
			t.Fatal(err)
		}
		return name
	}
	logFile := func(records ...map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"Records": records})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	record := func(key, account, recipient, source, name, category, id string) map[string]any {
		return map[string]any{
			"eventVersion": "1.10", "eventTime": now.Add(-time.Minute).Format(time.RFC3339), "eventSource": source, "eventName": name,
			"awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.7", "userAgent": "aws-cli/2.18.4", "eventID": id,
			"eventCategory": category, "recipientAccountId": recipient,
			"userIdentity": map[string]any{"type": "IAMUser", "accountId": account, "accessKeyId": key},
		}
	}

	fake := newServedAWSHoneyFixture(t)
	fake.nextKeyID, fake.nextSecret = "AKIATRAILDECOY000001", "fake-honey-trail-secret-value"
	callerPath := filepath.Join(t.TempDir(), "aws-monitor-session.json")
	caller, _ := json.Marshal(map[string]any{
		"access_key_id": "ASIAOPERATOR00001", "secret_access_key": "test", "session_token": "operator-test-session",
		"expires_at": now.Add(time.Hour).Format(time.RFC3339),
	})
	if err := os.WriteFile(callerPath, caller, 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true, AllowCIDRs: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	// Its own tenant: other served tests leave decoys on the shared one, and
	// this test needs a tenant with none (AUD30).
	tenant := uuid.NewString()
	cfg := config.AWSHoneyAccountConfig{
		TenantID: tenant, ID: "qa-aws", AccountID: decoyAccount, Regions: []string{"us-east-1"},
		IAMCredentialsRef: "file:" + callerPath, CloudTrailCredentialsRef: "file:" + callerPath,
		IAMEndpoint: fake.URL, CloudTrailEndpoints: map[string]string{"us-east-1": fake.URL},
		MaxTTL: "48h", PollInterval: "1m", AllowPrivate: true, AllowInsecureLoopback: true,
		PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		Trail: &config.AWSHoneyTrailConfig{Bucket: bucketName, BucketRegion: "us-east-1", KeyPrefix: "security/trail",
			OrganizationID: organization, S3Endpoint: s3Endpoint, PathStyle: true, CredentialsRef: "file:" + callerPath},
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
	registerServedTenantID(t, h, tenant, "N4 trail tenant")
	startServedExternalCADispatcher(t, h)
	owner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	// Nothing is read while the tenant has no decoy.
	deliver(decoyAccount, "us-east-1", "early", logFile(record("AKIAOTHER0000000009", decoyAccount, decoyAccount, "iam.amazonaws.com", "ListUsers", "Management", "early-1")))
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("a pass with no decoy read %d files: %v", n, err)
	}
	h.srv.awsHoneyTrailClock = awsHoneyTrailClock{}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", owner, "n4-decoy",
		map[string]any{"account_id": "qa-aws", "name": "trail-bait", "placement": "qa/trail", "ttl_seconds": 86400})
	var created struct {
		ID          string `json:"id"`
		AccessKeyID string `json:"access_key_id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.AccessKeyID == "" {
		t.Fatalf("create the AWS decoy: HTTP %d %s", status, body)
	}
	key := created.AccessKeyID
	// The decoy's own account logs its management call; another account logs
	// the data event on its bucket; a third file is not a log file.
	deliver(decoyAccount, "us-east-1", "a1", logFile(
		record("AKIAOTHER0000000009", decoyAccount, decoyAccount, "iam.amazonaws.com", "ListUsers", "Management", "other-1"),
		record(key, decoyAccount, decoyAccount, "sts.amazonaws.com", "GetCallerIdentity", "Management", "n4-mgmt-1")))
	deliver(otherAccount, "us-east-1", "b1", logFile(
		record(key, decoyAccount, otherAccount, "s3.amazonaws.com", "GetObject", "Data", "n4-data-1")))
	deliver(otherAccount, "eu-west-1", "c1", []byte("not gzip"))

	read, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context())
	if err != nil || read != 4 { // early-1 is read now too: the decoy exists
		t.Fatalf("first pass read %d files: %v", read, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/"+created.ID, owner, nil)
	var detail struct {
		State string `json:"state"`
		Uses  []struct {
			EventID            string `json:"event_id"`
			EventName          string `json:"event_name"`
			EventCategory      string `json:"event_category"`
			AccountID          string `json:"account_id"`
			RecipientAccountID string `json:"recipient_account_id"`
			FoundIn            string `json:"found_in"`
		} `json:"uses"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &detail) != nil {
		t.Fatalf("decoy detail: HTTP %d %s", status, body)
	}
	uses := map[string]string{}
	for _, use := range detail.Uses {
		uses[use.EventID] = strings.Join([]string{use.EventName, use.EventCategory, use.AccountID, use.RecipientAccountID, use.FoundIn}, "|")
	}
	if detail.State != "triggered" || len(uses) != 2 ||
		uses["n4-mgmt-1"] != "GetCallerIdentity|Management|"+decoyAccount+"|"+decoyAccount+"|trail" ||
		uses["n4-data-1"] != "GetObject|Data|"+decoyAccount+"|"+otherAccount+"|trail" {
		t.Fatalf("decoy after the trail read: state %s uses %v", detail.State, uses)
	}
	catalog := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/accounts", owner, nil)
		var out struct {
			Accounts []struct {
				ID    string `json:"id"`
				Trail *struct {
					Bucket string `json:"bucket"`
					Read   struct {
						Objects int `json:"objects"`
						Uses    int `json:"uses"`
						Refused int `json:"refused"`
					} `json:"read"`
				} `json:"trail"`
			} `json:"accounts"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil || len(out.Accounts) != 1 || out.Accounts[0].Trail == nil {
			t.Fatalf("account catalog: HTTP %d %s", status, body)
		}
		r := out.Accounts[0].Trail.Read
		return fmt.Sprintf("%s objects=%d uses=%d refused=%d", out.Accounts[0].Trail.Bucket, r.Objects, r.Uses, r.Refused)
	}
	if got := catalog(); got != bucketName+" objects=4 uses=2 refused=1" {
		t.Fatalf("trail read summary = %s", got)
	}

	// A second pass reads nothing again; a new delivery is read.
	h.srv.awsHoneyTrailClock = awsHoneyTrailClock{}
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("a second pass read %d files again: %v", n, err)
	}
	deliver(otherAccount, "us-east-1", "b2", logFile(
		record(key, decoyAccount, otherAccount, "s3.amazonaws.com", "PutObject", "Data", "n4-data-2")))
	h.srv.awsHoneyTrailClock = awsHoneyTrailClock{}
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("a pass after a new delivery read %d files: %v", n, err)
	}
	if got := catalog(); got != bucketName+" objects=5 uses=3 refused=1" {
		t.Fatalf("trail read summary after the new delivery = %s", got)
	}
	// N4-L2: a file delivered on a day before yesterday, as during a control
	// plane outage of several days, is read too: every day folder from the
	// day the oldest decoy was created, not only today and yesterday.
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE honey_tokens SET created_at = now() - interval '5 days' WHERE tenant_id = $1 AND id = $2`, tenant, created.ID); err != nil {
		t.Fatal(err)
	}
	missedDay := now.AddDate(0, 0, -3)
	missedBody := logFile(record(key, decoyAccount, otherAccount, "s3.amazonaws.com", "GetObject", "Data", "n4l2-missed-1"))
	missed := fmt.Sprintf("AWSLogs/%s/%s/CloudTrail/%s/%s/%s_CloudTrail_%s_%sZ_%s.json.gz", organization, otherAccount, "us-east-1",
		missedDay.Format("2006/01/02"), otherAccount, "us-east-1", missedDay.Format("20060102T1504"), "missed")
	if err := writer.Create(t.Context(), missed, bytes.NewReader(missedBody), int64(len(missedBody)), crypto.SHA256Sum(missedBody)); err != nil {
		t.Fatal(err)
	}
	h.srv.awsHoneyTrailClock = awsHoneyTrailClock{}
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("a pass after a delivery three days ago read %d files: %v", n, err)
	}
	if got := catalog(); got != bucketName+" objects=6 uses=4 refused=1" {
		t.Fatalf("trail read summary after the missed day = %s", got)
	}
	h.srv.awsHoneyTrailClock = awsHoneyTrailClock{}
	if n, err := h.srv.ReadAWSHoneyTrailsOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("a pass after the missed day was read read %d files again: %v", n, err)
	}
	if h.logContains(t, "operator-test-session") {
		t.Fatal("the trail reader's session token reached the event log")
	}
	t.Logf("N4_LOCALSTACK_OK decoy=%s uses=%v", created.ID, uses)
}
