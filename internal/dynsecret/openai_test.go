// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeOpenAI is a stand-in for the OpenAI admin API's project service
// accounts, from its documentation: creating one returns its API key once,
// the list pages with limit/after/has_more, and deleting one deletes its key;
// GET /v1/models accepts a live key.
type fakeOpenAI struct {
	mu       sync.Mutex
	accounts map[string]fakeOpenAIAccount // id -> account
	serial   int
}

type fakeOpenAIAccount struct{ project, name, key string }

func (f *fakeOpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/v1/models" {
		for _, account := range f.accounts {
			if "Bearer "+account.key == r.Header.Get("Authorization") {
				_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer sk-admin-fixture" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/organization/projects/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	project, rest, _ := strings.Cut(rest, "/service_accounts")
	id := strings.TrimPrefix(rest, "/")
	switch {
	case r.Method == http.MethodPost && id == "":
		var body struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.serial++
		account := fakeOpenAIAccount{project: project, name: body.Name, key: fmt.Sprintf("sk-svcacct-%04d", f.serial)}
		accountID := fmt.Sprintf("svc_acct_%04d", f.serial)
		f.accounts[accountID] = account
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "organization.project.service_account", "id": accountID, "name": body.Name,
			"role": "member", "api_key": map[string]any{"object": "organization.project.service_account.api_key", "value": account.key, "id": "key_" + accountID}})
	case r.Method == http.MethodGet && id == "":
		var ids []string
		for accountID, account := range f.accounts {
			if account.project == project {
				ids = append(ids, accountID)
			}
		}
		sort.Strings(ids)
		after := r.URL.Query().Get("after")
		var data []map[string]any
		for _, accountID := range ids {
			if after != "" && accountID <= after {
				continue
			}
			if len(data) == 2 { // small pages, so a retry's lookup crosses one
				break
			}
			data = append(data, map[string]any{"id": accountID, "name": f.accounts[accountID].name})
		}
		last := ""
		if len(data) > 0 {
			last = data[len(data)-1]["id"].(string)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data, "has_more": last != "" && last != ids[len(ids)-1], "last_id": last})
	case r.Method == http.MethodGet:
		account, ok := f.accounts[id]
		if !ok || account.project != project {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": account.name})
	case r.Method == http.MethodDelete:
		if account, ok := f.accounts[id]; !ok || account.project != project {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.accounts, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "organization.project.service_account.deleted", "id": id, "deleted": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeOpenAI) named(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, account := range f.accounts {
		if strings.HasPrefix(account.name, prefix) {
			n++
		}
	}
	return n
}

// A240: OpenAI service-account keys rotate in two phases. Each rotation (or
// lease) creates a named service account whose key comes with it, both keys
// work until the predecessor's account is deleted, a retried creation
// replaces its own account (found across list pages), and only accounts this
// provider named, in bound projects, are deleted.
func TestOpenAIServiceAccountKeysRotateInTwoPhases(t *testing.T) {
	ctx := context.Background()
	fake := &fakeOpenAI{accounts: map[string]fakeOpenAIAccount{
		"svc_acct_0a": {project: "proj_orders", name: "deploy-bot", key: "sk-foreign-a"},
		"svc_acct_0b": {project: "proj_orders", name: "ci-bot", key: "sk-foreign-b"},
		"svc_acct_0c": {project: "proj_orders", name: "batch-bot", key: "sk-foreign-c"},
	}}
	server := httptest.NewServer(fake)
	defer server.Close()
	backend, err := NewOpenAIBackend(OpenAIConfig{Endpoint: server.URL, AdminKey: []byte("sk-admin-fixture"),
		RoleBindings: map[string]string{"openai/orders": "proj_orders"}, UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	if _, _, err := backend.CreateCredential(ctx, GenerateRequest{Role: "openai/orders", LeaseID: "cmd-1", Static: true}); err != nil {
		t.Fatal(err)
	}
	oldRef, oldKey, err := backend.CreateCredential(ctx, GenerateRequest{Role: "openai/orders", LeaseID: "cmd-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if fake.named("trstctl-") != 1 {
		t.Fatalf("a retried creation left %d service accounts", fake.named("trstctl-"))
	}
	newRef, newKey, err := backend.CreateCredential(ctx, GenerateRequest{Role: "openai/orders", LeaseID: "cmd-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(oldRef, "proj_orders/svc_acct_") || oldRef == newRef {
		t.Fatalf("references %q %q", oldRef, newRef)
	}
	for name, key := range map[string][]byte{"predecessor": oldKey, "successor": newKey} {
		if err := backend.VerifyCredential(ctx, key); err != nil {
			t.Fatalf("the %s does not authenticate before retirement: %v", name, err)
		}
	}
	if err := backend.Revoke(ctx, oldRef); err != nil {
		t.Fatal(err)
	}
	if err := backend.VerifyCredential(ctx, oldKey); err == nil {
		t.Fatal("the retired key still authenticates")
	}
	if err := backend.VerifyCredential(ctx, newKey); err != nil {
		t.Fatalf("retiring the predecessor broke the successor: %v", err)
	}
	if err := backend.Revoke(ctx, oldRef); err != nil {
		t.Fatalf("a service account already gone counts as revoked: %v", err)
	}
	for ref, want := range map[string]string{
		"proj_orders/svc_acct_0a":    "did not create",
		"proj_billing/svc_acct_0002": "no service account of a bound project",
		"proj_orders/key_0001":       "no service account of a bound project",
	} {
		if err := backend.Revoke(ctx, ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("revoke %s: %v, want %q", ref, err, want)
		}
	}
	if fake.named("deploy-bot") != 1 {
		t.Fatal("a service account this provider did not name was deleted")
	}
	if _, err := NewOpenAIBackend(OpenAIConfig{Endpoint: server.URL, AdminKey: []byte("k"), RoleBindings: map[string]string{"r": "orders"},
		AllowInsecureLoopback: true, HTTPClient: server.Client()}); err == nil {
		t.Fatal("a binding that is not a project ID was accepted")
	}
}
