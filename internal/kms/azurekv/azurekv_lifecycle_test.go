// SPDX-License-Identifier: BUSL-1.1

package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestRemoteKeyLifecycle(t *testing.T) {
	doer := newLifecycleDoer(t, "azure-token")
	b := New("https://trstctl-test.managedhsm.azure.net", Credentials{BearerToken: []byte("azure-token")},
		WithEndpoint("https://azure.test"), WithHTTPClient(doer), WithOpTimeout(0))
	var _ crypto.RemoteKeyLifecycle = b

	ctx := context.Background()
	signer, ref, err := b.GenerateManagedKey(ctx, crypto.RSA2048)
	if err != nil {
		t.Fatalf("generate managed key: %v", err)
	}
	if signer.Public().Algorithm != crypto.RSA2048 || len(signer.Public().DER) == 0 {
		t.Fatalf("generate returned bad public key: %+v", signer.Public())
	}
	if !strings.HasPrefix(ref.ID, "https://trstctl-test.managedhsm.azure.net/keys/") {
		t.Fatalf("managed key id = %q, want Azure key id", ref.ID)
	}

	_, next, err := b.RotateKey(ctx, ref)
	if err != nil {
		t.Fatalf("rotate managed key: %v", err)
	}
	if next.ID == ref.ID {
		t.Fatal("rotate returned the original key id")
	}
	if err := b.RevokeKey(ctx, next); err != nil {
		t.Fatalf("revoke managed key: %v", err)
	}
	if !doer.disabled(next.ID) {
		t.Fatalf("Azure key %q was not disabled on revoke", next.ID)
	}
	if err := b.ZeroizeKey(ctx, next); err != nil {
		t.Fatalf("zeroize managed key: %v", err)
	}
	if !doer.deleted(next.ID) {
		t.Fatalf("Azure key %q was not deleted on zeroize", next.ID)
	}
}

func TestOperationAwareLifecycleReconcilesAmbiguousProviderEffects(t *testing.T) {
	doer := newLifecycleDoer(t, "azure-token")
	b := New("https://trstctl-test.managedhsm.azure.net", Credentials{BearerToken: []byte("azure-token")},
		WithEndpoint("https://azure.test"), WithHTTPClient(doer), WithOpTimeout(0))
	var lifecycle crypto.OperationAwareRemoteKeyLifecycle = b
	ctx := context.Background()

	doer.loseCreateResponse = true
	if _, _, err := lifecycle.GenerateManagedKeyForOperation(ctx, "azure-generate-op", crypto.RSA2048); err == nil {
		t.Fatal("generate returned success after the provider response was lost")
	}
	createdID := doer.lastCreatedID()
	if doer.createEffects != 1 {
		t.Fatalf("create effects after ambiguous response = %d, want 1", doer.createEffects)
	}
	signer, ref, err := lifecycle.GenerateManagedKeyForOperation(ctx, "azure-generate-op", crypto.RSA2048)
	if err != nil {
		t.Fatalf("reconcile generated key: %v", err)
	}
	_, replay, err := lifecycle.GenerateManagedKeyForOperation(ctx, "azure-generate-op", crypto.RSA2048)
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
	if _, _, err := lifecycle.RotateKeyForOperation(ctx, "azure-rotate-op", ref); err == nil {
		t.Fatal("rotate returned success after the provider response was lost")
	}
	rotatedID := doer.lastCreatedID()
	_, rotated, err := lifecycle.RotateKeyForOperation(ctx, "azure-rotate-op", ref)
	if err != nil {
		t.Fatalf("reconcile rotated key: %v", err)
	}
	_, rotatedReplay, err := lifecycle.RotateKeyForOperation(ctx, "azure-rotate-op", ref)
	if err != nil {
		t.Fatalf("replay rotated key: %v", err)
	}
	if rotated.ID != rotatedID || rotatedReplay != rotated || doer.createEffects != 2 {
		t.Fatalf("rotate refs/effects = %+v/%+v/%d, provider created %q", rotated, rotatedReplay, doer.createEffects, rotatedID)
	}

	doer.loseDisableResponse = true
	if err := lifecycle.RevokeKeyForOperation(ctx, "azure-revoke-op", rotated); err == nil {
		t.Fatal("revoke returned success after the provider response was lost")
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "azure-revoke-op", rotated); err != nil {
		t.Fatalf("reconcile revoked key: %v", err)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "azure-revoke-op", rotated); err != nil {
		t.Fatalf("replay revoked key: %v", err)
	}
	if doer.disableEffects != 1 {
		t.Fatalf("disable effects = %d, want 1", doer.disableEffects)
	}

	doer.loseDeleteResponse = true
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "azure-zeroize-op", rotated); err == nil {
		t.Fatal("zeroize returned success after the provider response was lost")
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "azure-zeroize-op", rotated); err != nil {
		t.Fatalf("reconcile zeroized key: %v", err)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "azure-zeroize-op", rotated); err != nil {
		t.Fatalf("replay zeroized key: %v", err)
	}
	if doer.deleteEffects != 1 {
		t.Fatalf("delete effects = %d, want 1", doer.deleteEffects)
	}
}

type lifecycleDoer struct {
	t                   *testing.T
	token               string
	mu                  sync.Mutex
	keys                map[string]*lifecycleKey
	n                   int
	createEffects       int
	disableEffects      int
	deleteEffects       int
	loseCreateResponse  bool
	loseDisableResponse bool
	loseDeleteResponse  bool
}

type lifecycleKey struct {
	signer   *crypto.LockedSigner
	name     string
	version  string
	disabled bool
	deleted  bool
}

func newLifecycleDoer(t *testing.T, token string) *lifecycleDoer {
	t.Helper()
	d := &lifecycleDoer{t: t, token: token, keys: map[string]*lifecycleKey{}}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		seen := map[*crypto.LockedSigner]bool{}
		for _, key := range d.keys {
			if !seen[key.signer] {
				key.signer.Destroy()
				seen[key.signer] = true
			}
		}
	})
	return d
}

func (d *lifecycleDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "Bearer "+d.token {
		return jsonResponse(req, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "Unauthorized"}}), nil
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/create"):
		response := d.create(req, body)
		if response.StatusCode/100 == 2 && d.consumeLostCreateResponse() {
			return nil, fmt.Errorf("azure emulator: response lost after create effect")
		}
		return response, nil
	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/keys/"):
		return d.get(req), nil
	case req.Method == http.MethodPatch && strings.HasPrefix(req.URL.Path, "/keys/"):
		response := d.disable(req, body)
		if response.StatusCode/100 == 2 && d.consumeLostDisableResponse() {
			return nil, fmt.Errorf("azure emulator: response lost after disable effect")
		}
		return response, nil
	case req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, "/keys/"):
		response := d.delete(req)
		if response.StatusCode/100 == 2 && d.consumeLostDeleteResponse() {
			return nil, fmt.Errorf("azure emulator: response lost after delete effect")
		}
		return response, nil
	default:
		return jsonResponse(req, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "BadRequest"}}), nil
	}
}

func (d *lifecycleDoer) create(req *http.Request, body []byte) *http.Response {
	var in struct {
		Kty     string `json:"kty"`
		KeySize int    `json:"key_size"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Kty != "RSA" || in.KeySize != 2048 {
		return jsonResponse(req, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "BadParameter"}})
	}
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return jsonResponse(req, http.StatusInternalServerError, map[string]any{"error": map[string]string{"code": "InternalError"}})
	}
	name := strings.TrimPrefix(strings.TrimSuffix(req.URL.Path, "/create"), "/keys/")
	d.mu.Lock()
	d.n++
	d.createEffects++
	version := fmt.Sprintf("v%d", d.n)
	key := &lifecycleKey{signer: signer, name: name, version: version}
	d.keys[name+"/"+version] = key
	d.keys[name] = key
	d.mu.Unlock()
	return jsonResponse(req, http.StatusOK, map[string]any{
		"key": map[string]string{"kid": "https://trstctl-test.managedhsm.azure.net/keys/" + name + "/" + version},
		"der": base64.StdEncoding.EncodeToString(signer.Public().DER),
	})
}

func (d *lifecycleDoer) get(req *http.Request) *http.Response {
	ref := strings.TrimPrefix(req.URL.Path, "/keys/")
	d.mu.Lock()
	key := d.keys[ref]
	d.mu.Unlock()
	if key == nil || key.deleted {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "KeyNotFound"}})
	}
	return jsonResponse(req, http.StatusOK, map[string]any{
		"key": map[string]any{
			"kid":     "https://trstctl-test.managedhsm.azure.net/keys/" + key.name + "/" + key.version,
			"key_ops": []string{"sign"},
		},
		"der":        base64.StdEncoding.EncodeToString(key.signer.Public().DER),
		"attributes": map[string]bool{"enabled": !key.disabled},
	})
}

func (d *lifecycleDoer) disable(req *http.Request, body []byte) *http.Response {
	var in struct {
		Attributes struct {
			Enabled bool `json:"enabled"`
		} `json:"attributes"`
	}
	_ = json.Unmarshal(body, &in)
	ref := strings.TrimPrefix(req.URL.Path, "/keys/")
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[ref]
	if key == nil || key.deleted {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "KeyNotFound"}})
	}
	key.disabled = !in.Attributes.Enabled
	d.disableEffects++
	return jsonResponse(req, http.StatusOK, map[string]any{"attributes": map[string]bool{"enabled": false}})
}

func (d *lifecycleDoer) delete(req *http.Request) *http.Response {
	name := strings.TrimPrefix(req.URL.Path, "/keys/")
	d.mu.Lock()
	defer d.mu.Unlock()
	deleted := false
	for id, key := range d.keys {
		if id == name || strings.HasPrefix(id, name+"/") {
			key.deleted = true
			deleted = true
		}
	}
	if !deleted {
		return jsonResponse(req, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "KeyNotFound"}})
	}
	d.deleteEffects++
	return jsonResponse(req, http.StatusOK, map[string]string{"id": "https://trstctl-test.managedhsm.azure.net/deletedkeys/" + name})
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

func (d *lifecycleDoer) consumeLostDeleteResponse() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	lost := d.loseDeleteResponse
	d.loseDeleteResponse = false
	return lost
}

func (d *lifecycleDoer) lastCreatedID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, key := range d.keys {
		if strings.Contains(id, "/") && key.version == fmt.Sprintf("v%d", d.n) {
			return "https://trstctl-test.managedhsm.azure.net/keys/" + id
		}
	}
	return ""
}

func (d *lifecycleDoer) disabled(id string) bool {
	_, version := keyNameAndVersion(id, "")
	name, _ := keyNameAndVersion(id, "")
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[name+"/"+version]
	return key != nil && key.disabled
}

func (d *lifecycleDoer) deleted(id string) bool {
	name, _ := keyNameAndVersion(id, "")
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.keys[name]
	return key != nil && key.deleted
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
