// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/azurekv"
	"trstctl.com/trstctl/internal/kms/gcpkms"
)

const (
	servedAzureVaultURL = "https://trstctl-test.managedhsm.azure.net"
	servedAzureToken    = "azure-access-token-do-not-log"
	servedGCPParent     = "projects/p/locations/l/keyRings/r"
	servedGCPToken      = "ya29.gcp-access-token-do-not-log" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
)

// TestServedCloudKMSManagedKeyLifecycleCAPKEY02 proves CAP-KEY-02 through the
// running control-plane surface: Azure Key Vault HSM and GCP Cloud KMS backends
// are wired through crypto.RemoteKeyLifecycle and the served API drives generate,
// rotate, revoke, and zeroize using only opaque cloud-KMS key handles.
func TestServedCloudKMSManagedKeyLifecycleCAPKEY02(t *testing.T) {
	azure := newServedAzureKV(t)
	gcp := newServedGCPKMS(t)
	cases := []struct {
		name      string
		prefix    string
		lifecycle crypto.RemoteKeyLifecycle
	}{
		{
			name:   "azure-key-vault-hsm",
			prefix: servedAzureVaultURL + "/keys/",
			lifecycle: azurekv.New(servedAzureVaultURL, azurekv.Credentials{BearerToken: []byte(servedAzureToken)},
				azurekv.WithEndpoint("https://azure-kms.test"), azurekv.WithHTTPClient(azure)),
		},
		{
			name:   "gcp-kms",
			prefix: servedGCPParent + "/cryptoKeys/",
			lifecycle: gcpkms.New(servedGCPParent, gcpkms.Credentials{BearerToken: []byte(servedGCPToken)},
				gcpkms.WithEndpoint("https://cloudkms.test/v1"), gcpkms.WithHTTPClient(gcp)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.ManagedKeyFactory = func(md ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
					if md.Log == nil || md.Idempotency == nil {
						t.Fatal("managed-key cloud KMS factory did not receive event log and idempotency spine")
					}
					return newServedPKCS11ManagedKeys(tc.lifecycle), nil
				}
			})
			token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cloud-kms-operator", []string{
				string(authz.KeysRead), string(authz.KeysWrite),
			})

			code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys", token, tc.name+"-generate", map[string]string{
				"algorithm": string(crypto.RSA2048),
			})
			if code != http.StatusCreated {
				t.Fatalf("%s managed-key generate = %d, want 201; body=%s", tc.name, code, body)
			}
			generated := decodeManagedKey(t, body)
			if generated.KeyID == "" || generated.Algorithm != crypto.RSA2048 || generated.State != "active" || len(generated.PublicDER) == 0 {
				t.Fatalf("bad %s generated key response: %+v", tc.name, generated)
			}
			if !strings.HasPrefix(generated.KeyID, tc.prefix) {
				t.Fatalf("%s managed key id = %q, want opaque provider handle prefix %q", tc.name, generated.KeyID, tc.prefix)
			}

			code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/rotate", token, tc.name+"-rotate", map[string]string{
				"key_id": generated.KeyID,
			})
			if code != http.StatusOK {
				t.Fatalf("%s managed-key rotate = %d, want 200; body=%s", tc.name, code, body)
			}
			rotated := decodeManagedKey(t, body)
			if rotated.KeyID == "" || rotated.KeyID == generated.KeyID || rotated.State != "active" || len(rotated.PublicDER) == 0 {
				t.Fatalf("bad %s rotated key response: %+v", tc.name, rotated)
			}

			code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/revoke", token, tc.name+"-revoke", map[string]string{
				"key_id": rotated.KeyID,
			})
			if code != http.StatusOK {
				t.Fatalf("%s managed-key revoke = %d, want 200; body=%s", tc.name, code, body)
			}
			revoked := decodeManagedKey(t, body)
			if revoked.State != "revoked" {
				t.Fatalf("%s revoked state = %q, want revoked", tc.name, revoked.State)
			}

			code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/zeroize", token, tc.name+"-zeroize", map[string]string{
				"key_id": rotated.KeyID,
			})
			if code != http.StatusOK {
				t.Fatalf("%s managed-key zeroize = %d, want 200; body=%s", tc.name, code, body)
			}
			zeroized := decodeManagedKey(t, body)
			if zeroized.State != "zeroized" {
				t.Fatalf("%s zeroized state = %q, want zeroized", tc.name, zeroized.State)
			}
		})
	}
}

type servedCloudKey struct {
	signer   *crypto.LockedSigner
	alg      crypto.Algorithm
	disabled bool
	zeroized bool
}

type servedAzureKV struct {
	token string
	mu    sync.Mutex
	keys  map[string]*servedCloudKey
	n     int
}

func newServedAzureKV(t *testing.T) *servedAzureKV {
	t.Helper()
	f := &servedAzureKV{token: servedAzureToken, keys: map[string]*servedCloudKey{}}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		seen := map[*crypto.LockedSigner]bool{}
		for _, k := range f.keys {
			if !seen[k.signer] {
				k.signer.Destroy()
				seen[k.signer] = true
			}
		}
	})
	return f
}

func (f *servedAzureKV) Do(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	f.handle(rec, r)
	return rec.Result(), nil
}

func (f *servedAzureKV) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":"Unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/create"):
		f.create(w, r, body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/keys/"):
		f.getKey(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/keys/"):
		f.disable(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/keys/"):
		f.delete(w, r)
	default:
		http.Error(w, `{"error":{"code":"BadRequest"}}`, http.StatusBadRequest)
	}
}

func (f *servedAzureKV) create(w http.ResponseWriter, r *http.Request, body []byte) {
	var in struct {
		Kty     string `json:"kty"`
		KeySize int    `json:"key_size"`
		Crv     string `json:"crv"`
	}
	_ = json.Unmarshal(body, &in)
	alg := servedAzureAlgFor(in.Kty, in.KeySize, in.Crv)
	if alg == "" {
		http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
		return
	}
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		http.Error(w, `{"error":{"code":"InternalError"}}`, http.StatusInternalServerError)
		return
	}
	name := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/create"), "/keys/")
	f.mu.Lock()
	f.n++
	version := fmt.Sprintf("v%d", f.n)
	f.keys[name+"/"+version] = &servedCloudKey{signer: signer, alg: alg}
	f.keys[name] = f.keys[name+"/"+version]
	f.mu.Unlock()
	kid := servedAzureVaultURL + "/keys/" + name + "/" + version
	writeServedJSON(w, map[string]any{
		"key": map[string]string{"kid": kid},
		"der": base64.StdEncoding.EncodeToString(signer.Public().DER),
	})
}

func (f *servedAzureKV) getKey(w http.ResponseWriter, r *http.Request) {
	key := f.azureLookup(r.URL.Path)
	if key == nil || key.zeroized {
		http.Error(w, `{"error":{"code":"KeyNotFound"}}`, http.StatusNotFound)
		return
	}
	writeServedJSON(w, map[string]string{"der": base64.StdEncoding.EncodeToString(key.signer.Public().DER)})
}

func (f *servedAzureKV) disable(w http.ResponseWriter, r *http.Request) {
	key := f.azureLookup(r.URL.Path)
	if key == nil || key.zeroized {
		http.Error(w, `{"error":{"code":"KeyNotFound"}}`, http.StatusNotFound)
		return
	}
	f.mu.Lock()
	key.disabled = true
	f.mu.Unlock()
	writeServedJSON(w, map[string]any{"attributes": map[string]bool{"enabled": false}})
}

func (f *servedAzureKV) delete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/keys/")
	f.mu.Lock()
	defer f.mu.Unlock()
	deleted := false
	seen := map[*crypto.LockedSigner]bool{}
	for id, key := range f.keys {
		if id == name || strings.HasPrefix(id, name+"/") {
			key.zeroized = true
			if !seen[key.signer] {
				key.signer.Destroy()
				seen[key.signer] = true
			}
			delete(f.keys, id)
			deleted = true
		}
	}
	if !deleted {
		http.Error(w, `{"error":{"code":"KeyNotFound"}}`, http.StatusNotFound)
		return
	}
	writeServedJSON(w, map[string]string{"id": servedAzureVaultURL + "/deletedkeys/" + name})
}

func (f *servedAzureKV) azureLookup(path string) *servedCloudKey {
	id := strings.TrimPrefix(path, "/keys/")
	f.mu.Lock()
	defer f.mu.Unlock()
	if key := f.keys[id]; key != nil {
		return key
	}
	if name, _, ok := strings.Cut(id, "/"); ok {
		return f.keys[name]
	}
	return f.keys[id]
}

func servedAzureAlgFor(kty string, size int, curve string) crypto.Algorithm {
	switch kty {
	case "RSA":
		switch size {
		case 2048:
			return crypto.RSA2048
		case 3072:
			return crypto.RSA3072
		case 4096:
			return crypto.RSA4096
		}
	case "EC":
		switch curve {
		case "P-256":
			return crypto.ECDSAP256
		case "P-384":
			return crypto.ECDSAP384
		case "P-521":
			return crypto.ECDSAP521
		}
	}
	return ""
}

type servedGCPKMS struct {
	token string
	mu    sync.Mutex
	keys  map[string]*servedCloudKey
}

func newServedGCPKMS(t *testing.T) *servedGCPKMS {
	t.Helper()
	f := &servedGCPKMS{token: servedGCPToken, keys: map[string]*servedCloudKey{}}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, k := range f.keys {
			k.signer.Destroy()
		}
	})
	return f
}

func (f *servedGCPKMS) Do(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	f.handle(rec, r)
	return rec.Result(), nil
}

func (f *servedGCPKMS) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
		return
	}
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	path = strings.TrimPrefix(path, "/")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/cryptoKeys"):
		f.create(w, r, path, body)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/publicKey"):
		f.publicKey(w, path)
	case r.Method == http.MethodPatch && strings.Contains(path, "/cryptoKeyVersions/"):
		f.disable(w, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":destroy"):
		f.destroy(w, path)
	default:
		http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
	}
}

func (f *servedGCPKMS) create(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	keyID := r.URL.Query().Get("cryptoKeyId")
	if keyID == "" {
		http.Error(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
		return
	}
	var in struct {
		Purpose         string `json:"purpose"`
		VersionTemplate struct {
			Algorithm string `json:"algorithm"`
		} `json:"versionTemplate"`
	}
	_ = json.Unmarshal(body, &in)
	alg := servedGCPAlgFor(in.VersionTemplate.Algorithm)
	if in.Purpose != "ASYMMETRIC_SIGN" || alg == "" {
		http.Error(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
		return
	}
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		http.Error(w, `{"error":{"code":500,"status":"INTERNAL"}}`, http.StatusInternalServerError)
		return
	}
	cryptoKey := path + "/" + keyID
	versionName := cryptoKey + "/cryptoKeyVersions/1"
	f.mu.Lock()
	f.keys[versionName] = &servedCloudKey{signer: signer, alg: alg}
	f.mu.Unlock()
	writeServedJSON(w, map[string]string{"name": cryptoKey})
}

func (f *servedGCPKMS) publicKey(w http.ResponseWriter, path string) {
	versionName := strings.TrimSuffix(path, "/publicKey")
	key := f.gcpKey(versionName)
	if key == nil || key.zeroized {
		http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.signer.Public().DER})
	writeServedJSON(w, map[string]string{"pem": string(pemBytes)})
}

func (f *servedGCPKMS) disable(w http.ResponseWriter, path string) {
	key := f.gcpKey(path)
	if key == nil || key.zeroized {
		http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
		return
	}
	f.mu.Lock()
	key.disabled = true
	f.mu.Unlock()
	writeServedJSON(w, map[string]string{"name": path, "state": "DISABLED"})
}

func (f *servedGCPKMS) destroy(w http.ResponseWriter, path string) {
	versionName := strings.TrimSuffix(path, ":destroy")
	f.mu.Lock()
	key := f.keys[versionName]
	if key != nil {
		key.zeroized = true
		key.signer.Destroy()
		delete(f.keys, versionName)
	}
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
		return
	}
	writeServedJSON(w, map[string]string{"name": versionName, "state": "DESTROY_SCHEDULED"})
}

func (f *servedGCPKMS) gcpKey(versionName string) *servedCloudKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[versionName]
}

func servedGCPAlgFor(gcpAlg string) crypto.Algorithm {
	switch gcpAlg {
	case "RSA_SIGN_PKCS1_2048_SHA256":
		return crypto.RSA2048
	case "RSA_SIGN_PKCS1_3072_SHA256":
		return crypto.RSA3072
	case "RSA_SIGN_PKCS1_4096_SHA256":
		return crypto.RSA4096
	case "EC_SIGN_P256_SHA256":
		return crypto.ECDSAP256
	case "EC_SIGN_P384_SHA384":
		return crypto.ECDSAP384
	}
	return ""
}

func writeServedJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
