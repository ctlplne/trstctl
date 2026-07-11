// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestRemoteKeyLifecycle(t *testing.T) {
	doer := newLifecycleDoer(t, "gcp-token")
	b := New("projects/p/locations/us/keyRings/trstctl", Credentials{BearerToken: []byte("gcp-token")},
		WithEndpoint("https://cloudkms.test/v1"), WithHTTPClient(doer), WithOpTimeout(0))
	var _ crypto.RemoteKeyLifecycle = b

	ctx := context.Background()
	signer, ref, err := b.GenerateManagedKey(ctx, crypto.RSA2048)
	if err != nil {
		t.Fatalf("generate managed key: %v", err)
	}
	if signer.Public().Algorithm != crypto.RSA2048 || len(signer.Public().DER) == 0 {
		t.Fatalf("generate returned bad public key: %+v", signer.Public())
	}
	if !strings.HasPrefix(ref.ID, "projects/p/locations/us/keyRings/trstctl/cryptoKeys/") {
		t.Fatalf("managed key id = %q, want Cloud KMS key-version id", ref.ID)
	}

	_, next, err := b.RotateKey(ctx, ref)
	if err != nil {
		t.Fatalf("rotate managed key: %v", err)
	}
	if next.ID == ref.ID {
		t.Fatal("rotate returned the original key version")
	}
	if err := b.RevokeKey(ctx, next); err != nil {
		t.Fatalf("revoke managed key: %v", err)
	}
	if !doer.disabled(next.ID) {
		t.Fatalf("Cloud KMS key version %q was not disabled on revoke", next.ID)
	}
	if err := b.ZeroizeKey(ctx, next); err != nil {
		t.Fatalf("zeroize managed key: %v", err)
	}
	if !doer.destroyed(next.ID) {
		t.Fatalf("Cloud KMS key version %q was not destroyed on zeroize", next.ID)
	}
}

func TestOperationAwareLifecycleReconcilesAmbiguousProviderEffects(t *testing.T) {
	doer := newLifecycleDoer(t, "gcp-token")
	b := New("projects/p/locations/us/keyRings/trstctl", Credentials{BearerToken: []byte("gcp-token")},
		WithEndpoint("https://cloudkms.test/v1"), WithHTTPClient(doer), WithOpTimeout(0))
	var lifecycle crypto.OperationAwareRemoteKeyLifecycle = b
	ctx := context.Background()

	doer.loseCreateResponse = true
	if _, _, err := lifecycle.GenerateManagedKeyForOperation(ctx, "gcp-generate-op", crypto.RSA2048); err == nil {
		t.Fatal("generate returned success after the provider response was lost")
	}
	createdID := doer.lastCreatedID()
	if doer.createEffects != 1 {
		t.Fatalf("create effects after ambiguous response = %d, want 1", doer.createEffects)
	}
	signer, ref, err := lifecycle.GenerateManagedKeyForOperation(ctx, "gcp-generate-op", crypto.RSA2048)
	if err != nil {
		t.Fatalf("reconcile generated key: %v", err)
	}
	_, replay, err := lifecycle.GenerateManagedKeyForOperation(ctx, "gcp-generate-op", crypto.RSA2048)
	if err != nil {
		t.Fatalf("replay generated key: %v", err)
	}
	if ref.ID != createdID || replay != ref || doer.createEffects != 1 {
		t.Fatalf("generate refs/effects = %+v/%+v/%d, provider created %q", ref, replay, doer.createEffects, createdID)
	}
	if len(signer.Public().DER) == 0 {
		t.Fatal("reconciled signer returned no provider public key")
	}

	doer.loseCreateResponse = true
	if _, _, err := lifecycle.RotateKeyForOperation(ctx, "gcp-rotate-op", ref); err == nil {
		t.Fatal("rotate returned success after the provider response was lost")
	}
	rotatedID := doer.lastCreatedID()
	_, rotated, err := lifecycle.RotateKeyForOperation(ctx, "gcp-rotate-op", ref)
	if err != nil {
		t.Fatalf("reconcile rotated key: %v", err)
	}
	_, rotatedReplay, err := lifecycle.RotateKeyForOperation(ctx, "gcp-rotate-op", ref)
	if err != nil {
		t.Fatalf("replay rotated key: %v", err)
	}
	if rotated.ID != rotatedID || rotatedReplay != rotated || doer.createEffects != 2 {
		t.Fatalf("rotate refs/effects = %+v/%+v/%d, provider created %q", rotated, rotatedReplay, doer.createEffects, rotatedID)
	}

	doer.loseDisableResponse = true
	if err := lifecycle.RevokeKeyForOperation(ctx, "gcp-revoke-op", rotated); err == nil {
		t.Fatal("revoke returned success after the provider response was lost")
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "gcp-revoke-op", rotated); err != nil {
		t.Fatalf("reconcile revoked key: %v", err)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "gcp-revoke-op", rotated); err != nil {
		t.Fatalf("replay revoked key: %v", err)
	}
	if doer.disableEffects != 1 {
		t.Fatalf("disable effects = %d, want 1", doer.disableEffects)
	}

	doer.loseDestroyResponse = true
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "gcp-zeroize-op", rotated); err == nil {
		t.Fatal("zeroize returned success after the provider response was lost")
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "gcp-zeroize-op", rotated); err != nil {
		t.Fatalf("reconcile zeroized key: %v", err)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "gcp-zeroize-op", rotated); err != nil {
		t.Fatalf("replay zeroized key: %v", err)
	}
	if doer.destroyEffects != 1 {
		t.Fatalf("destroy effects = %d, want 1", doer.destroyEffects)
	}
}

type lifecycleDoer struct {
	t                   *testing.T
	token               string
	mu                  sync.Mutex
	keys                map[string]*lifecycleKey
	lastVersion         string
	createEffects       int
	disableEffects      int
	destroyEffects      int
	loseCreateResponse  bool
	loseDisableResponse bool
	loseDestroyResponse bool
}

type lifecycleKey struct {
	signer    *crypto.LockedSigner
	disabled  bool
	destroyed bool
}

func newLifecycleDoer(t *testing.T, token string) *lifecycleDoer {
	t.Helper()
	d := &lifecycleDoer{t: t, token: token, keys: map[string]*lifecycleKey{}}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, key := range d.keys {
			key.signer.Destroy()
		}
	})
	return d
}

func (d *lifecycleDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "Bearer "+d.token {
		return jsonResponse(req, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": 401, "status": "UNAUTHENTICATED"}}), nil
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	path := strings.TrimPrefix(req.URL.Path, "/v1/")
	path = strings.TrimPrefix(path, "/")
	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(path, "/cryptoKeys"):
		response := d.create(req, path, body)
		if response.StatusCode/100 == 2 && d.consumeLostCreateResponse() {
			return nil, fmt.Errorf("gcp emulator: response lost after create effect")
		}
		return response, nil
	case req.Method == http.MethodGet && strings.HasSuffix(path, "/publicKey"):
		return d.publicKey(req, path), nil
	case req.Method == http.MethodGet && strings.Contains(path, "/cryptoKeyVersions/"):
		return d.versionState(req, path), nil
	case req.Method == http.MethodGet && strings.Contains(path, "/cryptoKeys/"):
		return d.cryptoKey(req, path), nil
	case req.Method == http.MethodPatch && strings.Contains(path, "/cryptoKeyVersions/"):
		response := d.disable(req, path)
		if response.StatusCode/100 == 2 && d.consumeLostDisableResponse() {
			return nil, fmt.Errorf("gcp emulator: response lost after disable effect")
		}
		return response, nil
	case req.Method == http.MethodPost && strings.HasSuffix(path, ":destroy"):
		response := d.destroy(req, path)
		if response.StatusCode/100 == 2 && d.consumeLostDestroyResponse() {
			return nil, fmt.Errorf("gcp emulator: response lost after destroy effect")
		}
		return response, nil
	default:
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}}), nil
	}
}

func (d *lifecycleDoer) create(req *http.Request, path string, body []byte) *http.Response {
	keyID := req.URL.Query().Get("cryptoKeyId")
	if keyID == "" {
		return jsonResponse(req, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": 400, "status": "INVALID_ARGUMENT"}})
	}
	var in struct {
		Purpose         string `json:"purpose"`
		VersionTemplate struct {
			Algorithm string `json:"algorithm"`
		} `json:"versionTemplate"`
	}
	_ = json.Unmarshal(body, &in)
	if in.Purpose != "ASYMMETRIC_SIGN" || in.VersionTemplate.Algorithm != "RSA_SIGN_PKCS1_2048_SHA256" {
		return jsonResponse(req, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": 400, "status": "INVALID_ARGUMENT"}})
	}
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return jsonResponse(req, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": 500, "status": "INTERNAL"}})
	}
	cryptoKey := path + "/" + keyID
	versionName := cryptoKey + "/cryptoKeyVersions/1"
	d.mu.Lock()
	d.keys[versionName] = &lifecycleKey{signer: signer}
	d.lastVersion = versionName
	d.createEffects++
	d.mu.Unlock()
	return jsonResponse(req, http.StatusOK, map[string]string{"name": cryptoKey})
}

func (d *lifecycleDoer) cryptoKey(req *http.Request, path string) *http.Response {
	d.mu.Lock()
	key := d.keys[path+"/cryptoKeyVersions/1"]
	d.mu.Unlock()
	if key == nil {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
	}
	return jsonResponse(req, http.StatusOK, map[string]string{"name": path})
}

func (d *lifecycleDoer) versionState(req *http.Request, path string) *http.Response {
	d.mu.Lock()
	key := d.keys[path]
	d.mu.Unlock()
	if key == nil {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
	}
	state := "ENABLED"
	if key.disabled {
		state = "DISABLED"
	}
	if key.destroyed {
		state = "DESTROY_SCHEDULED"
	}
	return jsonResponse(req, http.StatusOK, map[string]string{"name": path, "state": state})
}

func (d *lifecycleDoer) publicKey(req *http.Request, path string) *http.Response {
	versionName := strings.TrimSuffix(path, "/publicKey")
	d.mu.Lock()
	key := d.keys[versionName]
	d.mu.Unlock()
	if key == nil || key.destroyed {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.signer.Public().DER})
	return jsonResponse(req, http.StatusOK, map[string]string{"pem": string(pemBytes)})
}

func (d *lifecycleDoer) disable(req *http.Request, path string) *http.Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[path]
	if key == nil || key.destroyed {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
	}
	key.disabled = true
	d.disableEffects++
	return jsonResponse(req, http.StatusOK, map[string]string{"name": path, "state": "DISABLED"})
}

func (d *lifecycleDoer) destroy(req *http.Request, path string) *http.Response {
	versionName := strings.TrimSuffix(path, ":destroy")
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[versionName]
	if key == nil {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
	}
	key.destroyed = true
	d.destroyEffects++
	return jsonResponse(req, http.StatusOK, map[string]string{"name": versionName, "state": "DESTROY_SCHEDULED"})
}

func (d *lifecycleDoer) consumeLostCreateResponse() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	lost := d.loseCreateResponse
	d.loseCreateResponse = false
	return lost
}

func (d *lifecycleDoer) consumeLostDisableResponse() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	lost := d.loseDisableResponse
	d.loseDisableResponse = false
	return lost
}

func (d *lifecycleDoer) consumeLostDestroyResponse() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	lost := d.loseDestroyResponse
	d.loseDestroyResponse = false
	return lost
}

func (d *lifecycleDoer) lastCreatedID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastVersion
}

func (d *lifecycleDoer) disabled(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[id]
	return key != nil && key.disabled
}

func (d *lifecycleDoer) destroyed(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[id]
	return key != nil && key.destroyed
}

func jsonResponse(req *http.Request, code int, v any) *http.Response {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(v)
	return &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(&buf),
		Request:    req,
	}
}
