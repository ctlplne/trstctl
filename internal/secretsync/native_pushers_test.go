// SPDX-License-Identifier: MPL-2.0

package secretsync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const terraformVariablesMediaType = "application/vnd.api+json"

type terraformVariableFixture struct {
	ID          string
	Key         string
	Description string
	Category    string
	Value       []byte
	HCL         bool
	Sensitive   bool
}

type terraformVariablesEmulator struct {
	t      *testing.T
	server *httptest.Server

	mu             sync.Mutex
	variables      map[string]terraformVariableFixture
	reads          int
	writes         int
	operationIDs   []string
	workspaceID    string
	token          []byte
	plaintextLeaks int
}

func newTerraformVariablesEmulator(t *testing.T, workspaceID string, token []byte) *terraformVariablesEmulator {
	t.Helper()
	emulator := &terraformVariablesEmulator{
		t:           t,
		variables:   map[string]terraformVariableFixture{},
		workspaceID: workspaceID,
		token:       bytes.Clone(token),
	}
	emulator.server = httptest.NewTLSServer(http.HandlerFunc(emulator.serveHTTP))
	t.Cleanup(func() {
		emulator.server.Close()
		secret.Wipe(emulator.token)
		emulator.mu.Lock()
		defer emulator.mu.Unlock()
		for key, item := range emulator.variables {
			secret.Wipe(item.Value)
			delete(emulator.variables, key)
		}
	})
	return emulator
}

func (e *terraformVariablesEmulator) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+string(e.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Accept") != terraformVariablesMediaType {
		http.Error(w, "wrong accept type", http.StatusNotAcceptable)
		return
	}
	base := "/api/v2/workspaces/" + url.PathEscape(e.workspaceID) + "/vars"
	if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
		http.NotFound(w, r)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.operationIDs = append(e.operationIDs, r.Header.Get("Idempotency-Key"))
	w.Header().Set("Content-Type", terraformVariablesMediaType)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == base:
		e.reads++
		type attributes struct {
			Key         string `json:"key"`
			Description string `json:"description"`
			Category    string `json:"category"`
			HCL         bool   `json:"hcl"`
			Sensitive   bool   `json:"sensitive"`
		}
		data := make([]any, 0, len(e.variables))
		for _, item := range e.variables {
			data = append(data, map[string]any{
				"id": item.ID, "type": "vars",
				"attributes": attributes{
					Key: item.Key, Description: item.Description, Category: item.Category,
					HCL: item.HCL, Sensitive: item.Sensitive,
				},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": data,
			"meta": map[string]any{"pagination": map[string]int{"current-page": 1, "total-pages": 1}},
		})
	case r.Method == http.MethodPost && r.URL.Path == base:
		if r.Header.Get("Content-Type") != terraformVariablesMediaType {
			http.Error(w, "wrong content type", http.StatusUnsupportedMediaType)
			return
		}
		item, ok := e.decodeWrite(w, r)
		if !ok {
			return
		}
		mapKey := item.Category + "\x00" + item.Key
		if _, exists := e.variables[mapKey]; exists {
			http.Error(w, "duplicate variable", http.StatusUnprocessableEntity)
			return
		}
		item.ID = "var-" + strconv.Itoa(len(e.variables)+1)
		e.variables[mapKey] = item
		e.writes++
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, base+"/"):
		if r.Header.Get("Content-Type") != terraformVariablesMediaType {
			http.Error(w, "wrong content type", http.StatusUnsupportedMediaType)
			return
		}
		item, ok := e.decodeWrite(w, r)
		if !ok {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		mapKey := item.Category + "\x00" + item.Key
		current, exists := e.variables[mapKey]
		if !exists || current.ID != id {
			http.NotFound(w, r)
			return
		}
		secret.Wipe(current.Value)
		item.ID = id
		e.variables[mapKey] = item
		e.writes++
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unsupported variables operation", http.StatusMethodNotAllowed)
	}
}

func (e *terraformVariablesEmulator) decodeWrite(w http.ResponseWriter, r *http.Request) (terraformVariableFixture, bool) {
	var payload struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Key         string           `json:"key"`
				Description string           `json:"description"`
				Category    string           `json:"category"`
				Value       secret.JSONBytes `json:"value"`
				HCL         bool             `json:"hcl"`
				Sensitive   bool             `json:"sensitive"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return terraformVariableFixture{}, false
	}
	if payload.Data.Type != "vars" || payload.Data.Attributes.Key == "" || !payload.Data.Attributes.Sensitive {
		secret.Wipe(payload.Data.Attributes.Value)
		http.Error(w, "invalid sensitive variable", http.StatusUnprocessableEntity)
		return terraformVariableFixture{}, false
	}
	if bytes.Contains([]byte(payload.Data.Attributes.Description), payload.Data.Attributes.Value) {
		e.plaintextLeaks++
	}
	return terraformVariableFixture{
		Key: payload.Data.Attributes.Key, Description: payload.Data.Attributes.Description,
		Category: payload.Data.Attributes.Category, Value: payload.Data.Attributes.Value,
		HCL: payload.Data.Attributes.HCL, Sensitive: payload.Data.Attributes.Sensitive,
	}, true
}

func (e *terraformVariablesEmulator) read(category, key string) (terraformVariableFixture, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	item, ok := e.variables[category+"\x00"+key]
	item.Value = bytes.Clone(item.Value)
	return item, ok
}

func TestTerraformCloudOpenTofuPusherUsesNativeWorkspaceVariablesAPI(t *testing.T) {
	token := []byte("terraform-cloud-test-token")
	emulator := newTerraformVariablesEmulator(t, "ws-opentofu-production", token)
	pusher, err := NewTerraformCloudOpenTofuPusher(TerraformCloudOpenTofuConfig{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(),
		WorkspaceID: "ws-opentofu-production", Token: token, Category: "env",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	target := NewTerraformCloudOpenTofuTarget(pusher)
	first := []byte("postgres://native-first")
	second := []byte("postgres://native-second")
	const firstOperation = "sync-terraform-first"
	for i := 0; i < 2; i++ {
		if err := target.DeliverOperation(t.Context(), firstOperation, "DATABASE_URL", first); err != nil {
			t.Fatalf("first delivery %d: %v", i+1, err)
		}
	}
	if err := target.DeliverOperation(t.Context(), "sync-terraform-second", "DATABASE_URL", second); err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	remote, ok := emulator.read("env", "DATABASE_URL")
	if !ok {
		t.Fatal("native Terraform/OpenTofu variable was not created")
	}
	defer secret.Wipe(remote.Value)
	if !bytes.Equal(remote.Value, second) || !remote.Sensitive || remote.HCL || remote.Category != "env" {
		t.Fatalf("remote variable metadata/value = sensitive:%v hcl:%v category:%q value-match:%v",
			remote.Sensitive, remote.HCL, remote.Category, bytes.Equal(remote.Value, second))
	}
	if bytes.Contains([]byte(remote.Description), second) || emulator.plaintextLeaks != 0 {
		t.Fatal("Terraform/OpenTofu variable description leaked secret bytes")
	}
	if strings.Contains(remote.Description, "sync-terraform-second") || !strings.Contains(remote.Description, "operation-sha256=") {
		t.Fatalf("Terraform/OpenTofu replay marker exposed the raw operation id or omitted its digest: %q", remote.Description)
	}
	if emulator.writes != 2 {
		t.Fatalf("native writes = %d, want create + one changed-value update", emulator.writes)
	}
	if emulator.reads != 3 {
		t.Fatalf("read-before-write calls = %d, want one per outbox attempt", emulator.reads)
	}
	for i, operationID := range emulator.operationIDs {
		if operationID == "" {
			t.Fatalf("request %d omitted the durable operation identity", i+1)
		}
	}
}

type vaultKVVersion struct {
	version int
	data    map[string][]byte
}

type vaultKVV2Emulator struct {
	t      *testing.T
	server *httptest.Server

	mu           sync.Mutex
	paths        map[string]vaultKVVersion
	token        []byte
	namespace    string
	writeCalls   int
	writes       int
	readCalls    int
	raceNextCAS  bool
	operationIDs []string
}

func newVaultKVV2Emulator(t *testing.T, token []byte, namespace string) *vaultKVV2Emulator {
	t.Helper()
	emulator := &vaultKVV2Emulator{
		t: t, paths: map[string]vaultKVVersion{}, token: bytes.Clone(token), namespace: namespace,
	}
	emulator.server = httptest.NewTLSServer(http.HandlerFunc(emulator.serveHTTP))
	t.Cleanup(func() {
		emulator.server.Close()
		secret.Wipe(emulator.token)
		emulator.mu.Lock()
		defer emulator.mu.Unlock()
		for path, version := range emulator.paths {
			wipeByteMap(version.data)
			delete(emulator.paths, path)
		}
	})
	return emulator
}

func (e *vaultKVV2Emulator) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != string(e.token) || r.Header.Get("X-Vault-Namespace") != e.namespace {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	const prefix = "/v1/team-secrets/data/apps/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.operationIDs = append(e.operationIDs, r.Header.Get("Idempotency-Key"))
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		e.readCalls++
		version, ok := e.paths[path]
		if !ok {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		data := make(map[string]secret.JSONBytes, len(version.data))
		for key, value := range version.data {
			data[key] = secret.JSONBytes(value)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     data,
				"metadata": map[string]int{"version": version.version},
			},
		})
	case http.MethodPost:
		e.writeCalls++
		var request struct {
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
			Data map[string]secret.JSONBytes `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		defer func() {
			for key, value := range request.Data {
				secret.Wipe(value)
				delete(request.Data, key)
			}
		}()
		current := e.paths[path]
		if e.raceNextCAS {
			e.raceNextCAS = false
			wipeByteMap(current.data)
			current.version++
			current.data = map[string][]byte{
				"owner": []byte("concurrent-writer"),
				"value": []byte("concurrent-value"),
			}
			e.paths[path] = current
		}
		if request.Options.CAS != current.version {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["check-and-set parameter did not match current version"]}`))
			return
		}
		wipeByteMap(current.data)
		current.version++
		current.data = make(map[string][]byte, len(request.Data))
		for key, value := range request.Data {
			current.data[key] = bytes.Clone(value)
		}
		e.paths[path] = current
		e.writes++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]int{"version": current.version},
		})
	default:
		http.Error(w, "unsupported KV operation", http.StatusMethodNotAllowed)
	}
}

func (e *vaultKVV2Emulator) seed(path string, version int, data map[string][]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	copyData := make(map[string][]byte, len(data))
	for key, value := range data {
		copyData[key] = bytes.Clone(value)
	}
	e.paths[path] = vaultKVVersion{version: version, data: copyData}
}

func (e *vaultKVV2Emulator) read(path string) vaultKVVersion {
	e.mu.Lock()
	defer e.mu.Unlock()
	current := e.paths[path]
	copyData := make(map[string][]byte, len(current.data))
	for key, value := range current.data {
		copyData[key] = bytes.Clone(value)
	}
	return vaultKVVersion{version: current.version, data: copyData}
}

func TestVaultKVV2PusherReadsBeforeCASAndPreservesSiblingFields(t *testing.T) {
	token := []byte("vault-kv-sync-token")
	emulator := newVaultKVV2Emulator(t, token, "platform/team-a")
	emulator.seed("database", 1, map[string][]byte{
		"owner": []byte("platform"),
		"value": []byte("old-database-password"),
	})
	emulator.raceNextCAS = true
	pusher, err := NewVaultKVV2Pusher(VaultKVV2Config{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: token,
		Mount: "team-secrets", PathPrefix: "apps", Field: "value", Namespace: "platform/team-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	target := NewVaultKVV2Target(pusher)
	value := []byte("rotated-database-password")
	const operationID = "sync-vault-kv-rotation"
	for i := 0; i < 2; i++ {
		if err := target.DeliverOperation(t.Context(), operationID, "database", value); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}
	remote := emulator.read("database")
	defer wipeByteMap(remote.data)
	if remote.version != 3 || !bytes.Equal(remote.data["value"], value) {
		t.Fatalf("Vault readback version=%d value-match=%v, want version 3 and exact value",
			remote.version, bytes.Equal(remote.data["value"], value))
	}
	if !bytes.Equal(remote.data["owner"], []byte("concurrent-writer")) {
		t.Fatalf("Vault CAS retry lost a sibling field: owner=%q", remote.data["owner"])
	}
	if emulator.writeCalls != 2 || emulator.writes != 1 {
		t.Fatalf("Vault write attempts/commits = %d/%d, want one conflict + one commit", emulator.writeCalls, emulator.writes)
	}
	if emulator.readCalls != 3 {
		t.Fatalf("Vault read-before-write calls = %d, want conflict reread plus replay read", emulator.readCalls)
	}
	for i, got := range emulator.operationIDs {
		if got != operationID {
			t.Fatalf("request %d operation id = %q, want %q", i+1, got, operationID)
		}
	}
}

func TestVaultKVV2PusherCreatesMissingPathWithCASZero(t *testing.T) {
	token := []byte("vault-kv-create-token")
	emulator := newVaultKVV2Emulator(t, token, "platform/team-a")
	pusher, err := NewVaultKVV2Pusher(VaultKVV2Config{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: token,
		Mount: "team-secrets", PathPrefix: "apps", Namespace: "platform/team-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	value := []byte("first-service-token")
	if err := NewVaultKVV2Target(pusher).DeliverOperation(t.Context(), "sync-vault-create", "new-service", value); err != nil {
		t.Fatal(err)
	}
	remote := emulator.read("new-service")
	defer wipeByteMap(remote.data)
	if remote.version != 1 || !bytes.Equal(remote.data["value"], value) {
		t.Fatalf("Vault create readback version=%d value-match=%v", remote.version, bytes.Equal(remote.data["value"], value))
	}
	if emulator.readCalls != 1 || emulator.writeCalls != 1 || emulator.writes != 1 {
		t.Fatalf("Vault missing-path read/write/commit = %d/%d/%d, want 1/1/1",
			emulator.readCalls, emulator.writeCalls, emulator.writes)
	}
}

func TestNativeSecretSyncPushersRejectNonTextSecretValues(t *testing.T) {
	tests := []struct {
		name string
		push func([]byte) error
	}{
		{
			name: "Terraform Cloud OpenTofu",
			push: func(value []byte) error {
				pusher, err := NewTerraformCloudOpenTofuPusher(TerraformCloudOpenTofuConfig{
					Endpoint: "https://app.terraform.test", HTTPClient: responseDoerFunc(func(*http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("HTTP must not run for invalid secret text")
					}), WorkspaceID: "ws-test", Token: []byte("token"),
				})
				if err != nil {
					return err
				}
				defer pusher.Close()
				return pusher.Push(t.Context(), "INVALID", value)
			},
		},
		{
			name: "Vault KV v2",
			push: func(value []byte) error {
				pusher, err := NewVaultKVV2Pusher(VaultKVV2Config{
					Endpoint: "https://vault.test", HTTPClient: responseDoerFunc(func(*http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("HTTP must not run for invalid secret text")
					}), Token: []byte("token"), Mount: "secret",
				})
				if err != nil {
					return err
				}
				defer pusher.Close()
				return pusher.Push(t.Context(), "invalid", value)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.push([]byte{0xff, 0xfe, 0xfd})
			if err == nil || !strings.Contains(err.Error(), "UTF-8") {
				t.Fatalf("error = %v, want UTF-8 rejection", err)
			}
		})
	}
}

func wipeByteMap(values map[string][]byte) {
	for key, value := range values {
		secret.Wipe(value)
		delete(values, key)
	}
}
