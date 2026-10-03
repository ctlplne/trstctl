// SPDX-License-Identifier: BUSL-1.1

package server

import (
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

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type servedAWSHoneyFixture struct {
	*httptest.Server
	mu          sync.Mutex
	user        string
	owner       string
	policy      string
	keyID       string
	issuedKeyID string
	uses        int
	actions     []string
}

func newServedAWSHoneyFixture(t *testing.T) *servedAWSHoneyFixture {
	t.Helper()
	f := &servedAWSHoneyFixture{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "signed AWS request required", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("X-Amz-Target") != "" {
			var lookup struct {
				LookupAttributes []struct {
					AttributeKey   string
					AttributeValue string
				} `json:"LookupAttributes"`
				StartTime int64 `json:"StartTime"`
				EndTime   int64 `json:"EndTime"`
			}
			if json.NewDecoder(r.Body).Decode(&lookup) != nil || len(lookup.LookupAttributes) != 1 ||
				lookup.LookupAttributes[0].AttributeKey != "AccessKeyId" || lookup.LookupAttributes[0].AttributeValue != f.issuedKeyID {
				http.Error(w, "wrong CloudTrail key filter", http.StatusBadRequest)
				return
			}
			f.actions = append(f.actions, "LookupEvents")
			events := []any{}
			when := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
			if f.uses > 0 && lookup.StartTime <= when.Unix() && lookup.EndTime >= when.Unix() {
				for i := 1; i <= f.uses; i++ {
					eventID := fmt.Sprintf("event-aws-honey-use-%d", i)
					inner, _ := json.Marshal(map[string]any{
						"eventID": eventID, "eventTime": when.Format(time.RFC3339),
						"eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
						"awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.51",
						"userAgent": "aws-cli/2", "errorCode": "AccessDenied",
						"recipientAccountId": "123456789012",
						"userIdentity":       map[string]string{"accountId": "123456789012", "accessKeyId": f.issuedKeyID},
					})
					events = append(events, map[string]any{
						"EventId": eventID, "EventName": "GetCallerIdentity",
						"EventSource": "sts.amazonaws.com", "AccessKeyId": f.issuedKeyID,
						"EventTime": when.Unix(), "CloudTrailEvent": string(inner),
					})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Events": events})
			return
		}
		_ = r.ParseForm()
		action, user := r.Form.Get("Action"), r.Form.Get("UserName")
		f.actions = append(f.actions, action)
		write := func(value string) { _, _ = w.Write([]byte(value)) }
		missing := func() { http.Error(w, "NoSuchEntity", http.StatusNotFound) }
		arn := func() string { return "arn:aws:iam::123456789012:user/trstctl/honeytokens/" + user }
		switch action {
		case "GetUser":
			if f.user != user {
				missing()
				return
			}
			write("<GetUserResponse><GetUserResult><User><Arn>" + arn() + "</Arn></User></GetUserResult></GetUserResponse>")
		case "ListUserTags":
			if f.user != user {
				missing()
				return
			}
			write("<ListUserTagsResponse><ListUserTagsResult><Tags><member><Key>trstctl-honeytoken-owner</Key><Value>" + f.owner + "</Value></member></Tags></ListUserTagsResult></ListUserTagsResponse>")
		case "CreateUser":
			if f.user != "" {
				http.Error(w, "EntityAlreadyExists", http.StatusConflict)
				return
			}
			if r.Form.Get("Path") != "/trstctl/honeytokens/" || r.Form.Get("Tags.member.1.Key") != "trstctl-honeytoken-owner" {
				http.Error(w, "ownership tag and path required", http.StatusBadRequest)
				return
			}
			f.user, f.owner = user, r.Form.Get("Tags.member.1.Value")
			write("<CreateUserResponse><CreateUserResult><User><Arn>" + arn() + "</Arn></User></CreateUserResult></CreateUserResponse>")
		case "PutUserPolicy":
			if f.user != user {
				missing()
				return
			}
			f.policy = r.Form.Get("PolicyDocument")
			write("<ok/>")
		case "GetUserPolicy":
			if f.user != user || f.policy == "" {
				missing()
				return
			}
			write("<GetUserPolicyResponse><GetUserPolicyResult><PolicyDocument>" + url.QueryEscape(f.policy) + "</PolicyDocument></GetUserPolicyResult></GetUserPolicyResponse>")
		case "CreateAccessKey":
			if !strings.Contains(f.policy, `"Effect":"Deny"`) {
				http.Error(w, "explicit deny required", http.StatusForbidden)
				return
			}
			f.keyID, f.issuedKeyID = "AKIADECOY00000001", "AKIADECOY00000001"
			write("<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>" + f.keyID + "</AccessKeyId><SecretAccessKey>fake-honey-secret-value</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>")
		case "ListAccessKeys":
			if f.user != user {
				missing()
				return
			}
			member := ""
			if f.keyID != "" {
				member = "<member><AccessKeyId>" + f.keyID + "</AccessKeyId></member>"
			}
			write("<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>" + member + "</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>")
		case "DeleteAccessKey":
			if r.Form.Get("AccessKeyId") != f.keyID {
				missing()
				return
			}
			f.keyID = ""
			write("<ok/>")
		case "DeleteUserPolicy":
			f.policy = ""
			write("<ok/>")
		case "DeleteUser":
			if f.keyID != "" {
				http.Error(w, "key still active", http.StatusConflict)
				return
			}
			f.user, f.owner = "", ""
			write("<ok/>")
		default:
			http.Error(w, "unsupported IAM action", http.StatusBadRequest)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func TestServedAWSHoneyTokenIssueDetectAndRetire(t *testing.T) {
	fake := newServedAWSHoneyFixture(t)
	credentialPath := filepath.Join(t.TempDir(), "aws-monitor-session.json")
	caller, _ := json.Marshal(map[string]any{
		"access_key_id": "ASIAOPERATOR00001", "secret_access_key": "operator-test-value",
		"session_token": "operator-test-session", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err := os.WriteFile(credentialPath, caller, 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true, AllowCIDRs: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	var accounts AWSHoneyAccountRegistry
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		cfg := config.AWSHoneyAccountConfig{
			TenantID: servedTestTenant, ID: "qa-aws", AccountID: "123456789012", Regions: []string{"us-east-1"},
			IAMCredentialsRef: "file:" + credentialPath, CloudTrailCredentialsRef: "file:" + credentialPath,
			IAMEndpoint: fake.URL, CloudTrailEndpoints: map[string]string{"us-east-1": fake.URL},
			MaxTTL: "48h", PollInterval: "1m", AllowPrivate: true, AllowInsecureLoopback: true,
			PrivateEgressCIDRs: []string{"127.0.0.1/32"},
		}
		var buildErr error
		accounts, buildErr = awsHoneyAccountsFromConfig([]config.AWSHoneyAccountConfig{cfg}, d.Store, d.KEK, guard, nil)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		d.TenantAWSHoneyAccounts = accounts
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: accounts.ForTenant(servedTestTenant)}
	})
	startServedExternalCADispatcher(t, h)
	owner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	reader := seedScopedToken(t, h.store, h.tenant, "secrets:read")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", reader, "aws-honey-reader", map[string]any{
		"account_id": "qa-aws", "name": "reader-bait", "placement": "qa/reader", "ttl_seconds": 86400,
	})
	if status != http.StatusForbidden {
		t.Fatalf("read-only caller created IAM bait: HTTP %d", status)
	}
	request := map[string]any{"account_id": "qa-aws", "name": "qa-aws-bait", "placement": "qa/trap", "ttl_seconds": 86400}
	status, _ = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws/preview", reader, request)
	if status != http.StatusForbidden {
		t.Fatalf("read-only caller previewed IAM creation: HTTP %d", status)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws/preview", owner, request)
	var preview struct {
		Ready                  bool   `json:"ready"`
		EffectFree             bool   `json:"effect_free"`
		RemoteAuthorityChecked bool   `json:"remote_authority_checked"`
		PreviewFingerprint     string `json:"preview_fingerprint"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || !preview.Ready || !preview.EffectFree || preview.RemoteAuthorityChecked || preview.PreviewFingerprint == "" {
		t.Fatalf("AWS decoy preview failed: HTTP %d body %s", status, body)
	}
	fake.mu.Lock()
	if fake.user != "" || fake.keyID != "" {
		t.Fatal("effect-free AWS preview changed IAM fixture")
	}
	fake.mu.Unlock()
	stale := map[string]any{"account_id": "qa-aws", "name": "qa-aws-bait", "placement": "qa/trap", "ttl_seconds": 7200, "preview_fingerprint": preview.PreviewFingerprint}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", owner, "aws-honey-stale", stale)
	if status != http.StatusConflict {
		t.Fatalf("stale AWS decoy review accepted: HTTP %d", status)
	}
	request["preview_fingerprint"] = preview.PreviewFingerprint
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", owner, "aws-honey-create-1", request)
	if status != http.StatusCreated {
		t.Fatalf("create AWS decoy: HTTP %d body %s", status, body)
	}
	var created struct {
		ID          string `json:"id"`
		AccessKeyID string `json:"access_key_id"`
		Secret      string `json:"secret_access_key"`
		LeaseID     string `json:"aws_lease_id"`
	}
	if json.Unmarshal(body, &created) != nil || created.ID == "" || created.LeaseID == "" || created.AccessKeyID != "AKIADECOY00000001" || created.Secret != "fake-honey-secret-value" {
		t.Fatalf("AWS decoy one-time reveal is incomplete: %s", body)
	}
	if h.logContains(t, created.Secret) {
		t.Fatal("AWS bait secret entered the event log")
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws", owner, "aws-honey-create-1", request)
	if status != http.StatusCreated || string(replay) != string(body) {
		t.Fatalf("AWS create replay changed its original result: HTTP %d", status)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/"+created.ID, owner, nil)
	if status != http.StatusOK || strings.Contains(string(body), created.Secret) {
		t.Fatalf("AWS investigation exposed secret or failed: HTTP %d", status)
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+created.LeaseID, owner, nil)
	if status != http.StatusNotFound {
		t.Fatalf("AWS honey lease leaked through generic dynamic-secret API: HTTP %d", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/"+created.ID+"/revoke", owner, "aws-wrong-revoke", nil)
	if status != http.StatusNotFound {
		t.Fatalf("native honeytoken revoke accepted AWS decoy: HTTP %d", status)
	}
	fake.mu.Lock()
	fake.uses = 1
	fake.mu.Unlock()
	for cycle := 0; cycle < 2; cycle++ {
		key := store.AWSHoneyScanKey(created.ID, "us-east-1", int64(cycle), 0)
		if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now()
			WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3 AND status = 'pending'`,
			h.tenant, store.AWSHoneyScanDestination, key); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			scan, err := h.store.GetAWSHoneyScan(t.Context(), h.tenant, created.ID, "us-east-1")
			if err != nil {
				t.Fatal(err)
			}
			if scan.Cycle > int64(cycle) {
				break
			}
			if time.Now().After(deadline) {
				var outboxID int64
				var status, lastError string
				var attempts int
				_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT id, status, attempts, COALESCE(last_error, '') FROM outbox
					WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
					h.tenant, store.AWSHoneyScanDestination, key).Scan(&outboxID, &status, &attempts, &lastError)
				message, _ := h.srv.outbox.Get(t.Context(), h.tenant, outboxID)
				debug := &secretIntegrationOutboxDispatcher{store: h.store, log: h.log, awsHoneyAccounts: accounts}
				directErr := debug.scanAWSHoneyToken(t.Context(), orchestrator.Message{TenantID: h.tenant, Destination: message.Destination, Payload: message.Payload, IdempotencyKey: message.IdempotencyKey})
				t.Fatalf("CloudTrail scan cycle %d did not complete: outbox=%s attempts=%d error=%s direct=%v", cycle, status, attempts, lastError, directErr)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	uses, err := h.store.ListAWSHoneyUses(t.Context(), h.tenant, created.ID, 10)
	if err != nil || len(uses) != 1 {
		t.Fatalf("CloudTrail event not deduped into one incident: uses=%d err=%v", len(uses), err)
	}
	if !h.hasEvent(t, "honeytoken.aws.scan_page") {
		t.Fatal("CloudTrail observation missing immutable scan evidence")
	}
	var alerts int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox
		WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&alerts); err != nil || alerts != 1 {
		t.Fatalf("AWS bait did not queue exactly one critical alert: count=%d err=%v", alerts, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws/"+created.ID+"/rearm", owner, "aws-honey-rearm", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"alarm_generation":1`) || !strings.Contains(string(body), `"state":"active"`) {
		t.Fatalf("rearm AWS bait after triage: HTTP %d body %s", status, body)
	}
	fake.mu.Lock()
	fake.uses = 2
	fake.mu.Unlock()
	key := store.AWSHoneyScanKey(created.ID, "us-east-1", 2, 0)
	if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now()
		WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3 AND status = 'pending'`,
		h.tenant, store.AWSHoneyScanDestination, key); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		scan, err := h.store.GetAWSHoneyScan(t.Context(), h.tenant, created.ID, "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		if scan.Cycle > 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rearmed AWS bait scan did not complete: cycle=%d", scan.Cycle)
		}
		time.Sleep(25 * time.Millisecond)
	}
	uses, err = h.store.ListAWSHoneyUses(t.Context(), h.tenant, created.ID, 10)
	if err != nil || len(uses) != 2 {
		t.Fatalf("rearmed bait did not retain both incidents: uses=%d err=%v", len(uses), err)
	}
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox
		WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`, h.tenant).Scan(&alerts); err != nil || alerts != 2 {
		t.Fatalf("rearmed AWS bait did not queue a new critical alert: count=%d err=%v", alerts, err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyAWSHoneyTokenRearmedTx(t.Context(), tx, h.tenant, created.ID, 0)
	}); err != nil {
		t.Fatal(err)
	}
	stillTriggered, err := h.store.GetHoneyToken(t.Context(), h.tenant, created.ID)
	if err != nil || stillTriggered.State != "triggered" || stillTriggered.AlarmGeneration != 1 {
		t.Fatalf("old rearm projection altered a newer incident: state=%s generation=%d err=%v", stillTriggered.State, stillTriggered.AlarmGeneration, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/aws/"+created.ID+"/retire", owner, "aws-honey-retire", nil)
	if status != http.StatusOK {
		t.Fatalf("retire AWS bait: HTTP %d body %s", status, body)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		lease, err := h.store.GetDynamicSecretLease(t.Context(), h.tenant, created.LeaseID)
		if err != nil {
			t.Fatal(err)
		}
		if lease.RevocationStatus == store.DynamicSecretRevocationCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("IAM deletion not independently completed: status=%s", lease.RevocationStatus)
		}
		time.Sleep(25 * time.Millisecond)
	}
	fake.mu.Lock()
	if fake.user != "" || fake.keyID != "" {
		t.Errorf("AWS fake still has IAM bait after completed retirement")
	}
	fake.mu.Unlock()
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/aws/"+created.ID, owner, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"state":"revoked"`) {
		t.Fatalf("retired IAM decoy readback: HTTP %d body %s", status, body)
	}
}
