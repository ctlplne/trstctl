// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// servedGCPKeys is a stand-in for the IAM API's service-account keys, from
// its reference: keys.create returns the key file once (privateKeyData,
// base64), an account holds at most ten keys, and keys.delete answers 404 for
// a key already gone.
type servedGCPKeys struct {
	mu     sync.Mutex
	keys   map[string]bool
	serial int
}

const servedGCPAccount = "/v1/projects/p/serviceAccounts/rotate@p.iam.gserviceaccount.com/keys"

func (g *servedGCPKeys) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer served-gcp-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == servedGCPAccount:
		if len(g.keys) >= 10 {
			hostedJSONReply(w, http.StatusTooManyRequests, map[string]any{"error": map[string]string{"status": "RESOURCE_EXHAUSTED"}})
			return
		}
		g.serial++
		id := fmt.Sprintf("%040x", g.serial)
		g.keys[id] = true
		file, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "p", "private_key_id": id,
			"private_key": "-----BEGIN PRIVATE KEY-----\nserved\n-----END PRIVATE KEY-----\n", "client_email": "rotate@p.iam.gserviceaccount.com"})
		hostedJSONReply(w, http.StatusOK, map[string]string{"name": strings.TrimPrefix(servedGCPAccount, "/v1/") + "/" + id, "privateKeyData": base64.StdEncoding.EncodeToString(file)})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, servedGCPAccount+"/"):
		id := strings.TrimPrefix(r.URL.Path, servedGCPAccount+"/")
		if !g.keys[id] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(g.keys, id)
		hostedJSONReply(w, http.StatusOK, map[string]any{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 Google Cloud service-account keys, against a stand-in of the IAM API:
// a static rotation is two-phase, both keys live between verification
// (not_available: a new key can take a minute to work) and the approved
// deadline, after which only the predecessor is deleted.
func TestServedGCPServiceAccountKeysRotateA240(t *testing.T) {
	vendor := &servedGCPKeys{keys: map[string]bool{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "gcp-rotate", Type: "gcp-iam", Endpoint: stand.URL, Project: "p",
			ServiceAccount: "rotate@p.iam.gserviceaccount.com", BearerTokenRef: writeServedCredentialFile(t, "gcp-token", "served-gcp-token"),
			AllowedRoles: []string{"gcp/app"}, MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "gcp/app", seed: `{"type":"service_account","private_key_id":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("private_key_id"),
		authenticates: func(t *testing.T, id string) bool {
			vendor.mu.Lock()
			defer vendor.mu.Unlock()
			return vendor.keys[id]
		},
		newRefPrefix: "projects/p/serviceAccounts/rotate@p.iam.gserviceaccount.com/keys/", wantVerifyMode: "not_available",
	}.run(t)
}
