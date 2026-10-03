// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type honeyIAMFake struct {
	*httptest.Server
	mu               sync.Mutex
	users            map[string]string
	keys             map[string]string
	policies         map[string]string
	actions          []string
	accountID        string
	weakPolicy       bool
	foreignUser      bool
	nextKey          int
	staleUserReads   int
	stalePolicyReads int
}

func newHoneyIAMFake(t *testing.T) *honeyIAMFake {
	t.Helper()
	f := &honeyIAMFake{users: map[string]string{}, keys: map[string]string{}, policies: map[string]string{}, accountID: "123456789012"}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "signature required", http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		action, user := r.Form.Get("Action"), r.Form.Get("UserName")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.actions = append(f.actions, action)
		write := func(body string) { _, _ = w.Write([]byte(body)) }
		missing := func() { http.Error(w, "NoSuchEntity", http.StatusNotFound) }
		arn := func() string { return "arn:aws:iam::" + f.accountID + ":user" + awsHoneyPath + user }
		switch action {
		case "GetUser":
			if f.staleUserReads > 0 && len(f.users) > 0 {
				f.staleUserReads--
				missing()
				return
			}
			if _, ok := f.users[user]; !ok {
				missing()
				return
			}
			write("<GetUserResponse><GetUserResult><User><Arn>" + arn() + "</Arn></User></GetUserResult></GetUserResponse>")
		case "ListUserTags":
			tag, ok := f.users[user]
			if !ok {
				missing()
				return
			}
			write("<ListUserTagsResponse><ListUserTagsResult><Tags><member><Key>" + awsHoneyTagName + "</Key><Value>" + tag + "</Value></member></Tags></ListUserTagsResult></ListUserTagsResponse>")
		case "CreateUser":
			if _, ok := f.users[user]; ok {
				http.Error(w, "EntityAlreadyExists", http.StatusConflict)
				return
			}
			if r.Form.Get("Path") != awsHoneyPath || r.Form.Get("Tags.member.1.Key") != awsHoneyTagName {
				http.Error(w, "missing scope", http.StatusBadRequest)
				return
			}
			f.users[user] = r.Form.Get("Tags.member.1.Value")
			if f.foreignUser {
				f.users[user] = "someone-else"
			}
			write("<CreateUserResponse><CreateUserResult><User><Arn>" + arn() + "</Arn></User></CreateUserResult></CreateUserResponse>")
		case "PutUserPolicy":
			if _, ok := f.users[user]; !ok {
				missing()
				return
			}
			f.policies[user] = r.Form.Get("PolicyDocument")
			write("<ok/>")
		case "GetUserPolicy":
			if f.stalePolicyReads > 0 {
				f.stalePolicyReads--
				missing()
				return
			}
			policy, ok := f.policies[user]
			if !ok {
				missing()
				return
			}
			if f.weakPolicy {
				policy = `{"Version":"2012-10-17","Statement":[]}`
			}
			write("<GetUserPolicyResponse><GetUserPolicyResult><PolicyDocument>" + url.QueryEscape(policy) + "</PolicyDocument></GetUserPolicyResult></GetUserPolicyResponse>")
		case "CreateAccessKey":
			if f.policies[user] == "" {
				http.Error(w, "deny policy required", http.StatusForbidden)
				return
			}
			f.nextKey++
			key := fmt.Sprintf("AKIADECOY%04d", f.nextKey)
			f.keys[key] = user
			write("<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>" + key + "</AccessKeyId><SecretAccessKey>fake-secret-" + key + "</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>")
		case "ListAccessKeys":
			if _, ok := f.users[user]; !ok {
				missing()
				return
			}
			members := ""
			for key, owner := range f.keys {
				if owner == user {
					members += "<member><AccessKeyId>" + key + "</AccessKeyId></member>"
				}
			}
			write("<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>" + members + "</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>")
		case "DeleteAccessKey":
			delete(f.keys, r.Form.Get("AccessKeyId"))
			write("<ok/>")
		case "DeleteUserPolicy":
			delete(f.policies, user)
			write("<ok/>")
		case "DeleteUser":
			for _, owner := range f.keys {
				if owner == user {
					http.Error(w, "DeleteConflict", http.StatusConflict)
					return
				}
			}
			delete(f.users, user)
			write("<ok/>")
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func newHoneyBackendForTest(t *testing.T, remote *honeyIAMFake) *AWSHoneyBackend {
	t.Helper()
	b, err := NewAWSHoneyBackend(AWSHoneyConfig{
		Endpoint: remote.URL, HTTPClient: remote.Client(), Region: "us-east-1", AccountID: "123456789012",
		AccessKeyID: "AKID", SecretAccessKey: []byte("test-signing-value"), UsernamePrefix: "qa",
		OwnerTag: "owned-decoy-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestAWSHoneyCreateDeniesAllBeforeKeyAndRetiresWithReadback(t *testing.T) {
	remote := newHoneyIAMFake(t)
	b := newHoneyBackendForTest(t, remote)
	ref, credential, err := b.Create(context.Background(), "decoy-1")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	var revealed struct {
		AccessKeyID     string           `json:"access_key_id"`
		SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
	}
	if err := json.Unmarshal(credential, &revealed); err != nil || revealed.AccessKeyID == "" || len(revealed.SecretAccessKey) == 0 {
		t.Fatalf("incomplete reveal: %v", err)
	}
	defer secret.Wipe(revealed.SecretAccessKey)
	remote.mu.Lock()
	policy := ""
	for _, value := range remote.policies {
		policy = value
	}
	joined := strings.Join(remote.actions, ",")
	remote.mu.Unlock()
	if policy != awsHoneyDenyAll || !strings.Contains(joined, "PutUserPolicy,GetUserPolicy,CreateAccessKey") {
		t.Fatalf("decoy key minted without verified explicit deny: %s", joined)
	}
	ref2, _, err := b.Create(context.Background(), "decoy-1")
	if err != nil || ref2 == ref {
		t.Fatalf("stable retry failed to replace old key: same=%t err=%v", ref2 == ref, err)
	}
	remote.mu.Lock()
	keys := len(remote.keys)
	remote.mu.Unlock()
	if keys != 1 {
		t.Fatalf("active keys after retry = %d, want one", keys)
	}
	if err := b.Retire(context.Background(), ref2); err != nil {
		t.Fatal(err)
	}
	remote.mu.Lock()
	users, keys := len(remote.users), len(remote.keys)
	remote.mu.Unlock()
	if users != 0 || keys != 0 {
		t.Fatalf("retirement left users=%d keys=%d", users, keys)
	}
}

func TestAWSHoneyRefusesWeakPolicyAndForeignOwnershipBeforeKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		weakPolicy   bool
		foreignOwner bool
	}{
		{name: "weak policy readback", weakPolicy: true},
		{name: "foreign retry collision", foreignOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := newHoneyIAMFake(t)
			remote.weakPolicy, remote.foreignUser = tc.weakPolicy, tc.foreignOwner
			b := newHoneyBackendForTest(t, remote)
			if _, _, err := b.Create(context.Background(), "decoy-1"); err == nil {
				t.Fatal("unsafe decoy creation succeeded")
			}
			remote.mu.Lock()
			keys := len(remote.keys)
			remote.mu.Unlock()
			if keys != 0 {
				t.Fatalf("key created despite unsafe policy/owner: %d", keys)
			}
		})
	}
}

func TestAWSHoneyWaitsForIAMReadbackBeforeMintingKey(t *testing.T) {
	remote := newHoneyIAMFake(t)
	remote.staleUserReads = 2
	remote.stalePolicyReads = 2
	b := newHoneyBackendForTest(t, remote)
	_, credential, err := b.Create(context.Background(), "eventual-consistency-decoy")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.staleUserReads != 0 || remote.stalePolicyReads != 0 || len(remote.keys) != 1 {
		t.Fatalf("IAM readback did not settle before key creation: user=%d policy=%d keys=%d", remote.staleUserReads, remote.stalePolicyReads, len(remote.keys))
	}
}
