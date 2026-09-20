// SPDX-License-Identifier: BUSL-1.1

package awskms_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/awskms"
)

// TestOperationAwareLifecycleReconcilesAmbiguousProviderEffects models the
// dangerous window precisely: KMS applies a mutation, but the response is lost
// before the signer can journal it. Every replay must bind/confirm provider state
// without creating or mutating a second time.
func TestOperationAwareLifecycleReconcilesAmbiguousProviderEffects(t *testing.T) {
	f := newOperationKMS(t)
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: []byte(testSK)},
		awskms.WithEndpoint(f.srv.URL), awskms.WithHTTPClient(f.srv.Client()), awskms.WithOpTimeout(0))
	var lifecycle crypto.OperationAwareRemoteKeyLifecycle = b
	ctx := context.Background()

	f.loseCreateResponse = true
	if _, _, err := lifecycle.GenerateManagedKeyForOperation(ctx, "aws-generate-op", crypto.ECDSAP256); err == nil {
		t.Fatal("generate returned success after the provider response was lost")
	}
	createdID := f.lastCreated()
	if got := f.createEffects(); got != 1 {
		t.Fatalf("CreateKey effects after ambiguous response = %d, want 1", got)
	}
	signer, ref, err := lifecycle.GenerateManagedKeyForOperation(ctx, "aws-generate-op", crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("reconcile generated key: %v", err)
	}
	if ref.ID != createdID {
		t.Fatalf("reconciled ref = %q, provider created %q", ref.ID, createdID)
	}
	_, replayRef, err := lifecycle.GenerateManagedKeyForOperation(ctx, "aws-generate-op", crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("replay generated key: %v", err)
	}
	if replayRef != ref || f.createEffects() != 1 {
		t.Fatalf("generate replay ref/effects = %+v/%d, want %+v/1", replayRef, f.createEffects(), ref)
	}
	if len(signer.Public().DER) == 0 {
		t.Fatal("reconciled signer returned no provider public key")
	}

	f.loseCreateResponse = true
	if _, _, err := lifecycle.RotateKeyForOperation(ctx, "aws-rotate-op", ref); err == nil {
		t.Fatal("rotate returned success after the provider response was lost")
	}
	rotatedID := f.lastCreated()
	_, rotated, err := lifecycle.RotateKeyForOperation(ctx, "aws-rotate-op", ref)
	if err != nil {
		t.Fatalf("reconcile rotated key: %v", err)
	}
	_, rotatedReplay, err := lifecycle.RotateKeyForOperation(ctx, "aws-rotate-op", ref)
	if err != nil {
		t.Fatalf("replay rotated key: %v", err)
	}
	if rotated.ID != rotatedID || rotatedReplay != rotated || f.createEffects() != 2 {
		t.Fatalf("rotate refs/effects = %+v/%+v/%d, provider created %q", rotated, rotatedReplay, f.createEffects(), rotatedID)
	}

	f.loseDisableResponse = true
	if err := lifecycle.RevokeKeyForOperation(ctx, "aws-revoke-op", rotated); err == nil {
		t.Fatal("revoke returned success after the provider response was lost")
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "aws-revoke-op", rotated); err != nil {
		t.Fatalf("reconcile revoked key: %v", err)
	}
	if err := lifecycle.RevokeKeyForOperation(ctx, "aws-revoke-op", rotated); err != nil {
		t.Fatalf("replay revoked key: %v", err)
	}
	if got := f.disableEffects; got != 1 {
		t.Fatalf("DisableKey effects = %d, want 1", got)
	}

	f.loseDeleteResponse = true
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "aws-zeroize-op", rotated); err == nil {
		t.Fatal("zeroize returned success after the provider response was lost")
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "aws-zeroize-op", rotated); err != nil {
		t.Fatalf("reconcile zeroized key: %v", err)
	}
	if err := lifecycle.ZeroizeKeyForOperation(ctx, "aws-zeroize-op", rotated); err != nil {
		t.Fatalf("replay zeroized key: %v", err)
	}
	if got := f.deleteEffects; got != 1 {
		t.Fatalf("ScheduleKeyDeletion effects = %d, want 1", got)
	}
}

type operationKMSKey struct {
	signer *crypto.LockedSigner
	spec   string
	tags   map[string]string
	state  string
}

type operationKMS struct {
	srv *httptest.Server
	mu  sync.Mutex

	keys                map[string]*operationKMSKey
	n                   int
	disableEffects      int
	deleteEffects       int
	loseCreateResponse  bool
	loseDisableResponse bool
	loseDeleteResponse  bool
}

func newOperationKMS(t *testing.T) *operationKMS {
	t.Helper()
	f := &operationKMS{keys: map[string]*operationKMSKey{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(func() {
		f.srv.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, key := range f.keys {
			key.signer.Destroy()
		}
	})
	return f
}

func (f *operationKMS) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if !verifySigV4(r, body, testAK, testSK) {
		http.Error(w, `{"__type":"SignatureDoesNotMatch"}`, http.StatusForbidden)
		return
	}
	var in struct {
		KeyID    string `json:"KeyId"`
		KeySpec  string `json:"KeySpec"`
		KeyUsage string `json:"KeyUsage"`
		Tags     []struct {
			Key   string `json:"TagKey"`
			Value string `json:"TagValue"`
		} `json:"Tags"`
	}
	_ = json.Unmarshal(body, &in)
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.ListKeys":
		f.listKeys(w)
	case "TrentService.ListResourceTags":
		f.listTags(w, in.KeyID)
	case "TrentService.CreateKey":
		f.create(w, in)
	case "TrentService.DescribeKey":
		f.describe(w, in.KeyID)
	case "TrentService.GetPublicKey":
		f.publicKey(w, in.KeyID)
	case "TrentService.DisableKey":
		f.disable(w, in.KeyID)
	case "TrentService.ScheduleKeyDeletion":
		f.delete(w, in.KeyID)
	default:
		http.Error(w, `{"__type":"UnknownOperationException"}`, http.StatusBadRequest)
	}
}

func (f *operationKMS) listKeys(w http.ResponseWriter) {
	f.mu.Lock()
	ids := make([]string, 0, len(f.keys))
	for id := range f.keys {
		ids = append(ids, id)
	}
	f.mu.Unlock()
	sort.Strings(ids)
	keys := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, map[string]string{"KeyId": id, "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/" + id})
	}
	writeJSON(w, map[string]any{"Keys": keys, "Truncated": false})
}

func (f *operationKMS) listTags(w http.ResponseWriter, id string) {
	f.mu.Lock()
	key := f.keys[id]
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	tags := make([]map[string]string, 0, len(key.tags))
	for k, v := range key.tags {
		tags = append(tags, map[string]string{"TagKey": k, "TagValue": v})
	}
	writeJSON(w, map[string]any{"Tags": tags, "Truncated": false})
}

func (f *operationKMS) create(w http.ResponseWriter, in struct {
	KeyID    string `json:"KeyId"`
	KeySpec  string `json:"KeySpec"`
	KeyUsage string `json:"KeyUsage"`
	Tags     []struct {
		Key   string `json:"TagKey"`
		Value string `json:"TagValue"`
	} `json:"Tags"`
}) {
	alg := algFor(in.KeySpec)
	if alg == "" || in.KeyUsage != "SIGN_VERIFY" || len(in.Tags) == 0 {
		http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
		return
	}
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		http.Error(w, `{"__type":"KMSInternalException"}`, http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.n++
	id := fmt.Sprintf("operation-key-%d", f.n)
	tags := map[string]string{}
	for _, tag := range in.Tags {
		tags[tag.Key] = tag.Value
	}
	f.keys[id] = &operationKMSKey{signer: signer, spec: in.KeySpec, tags: tags, state: "Enabled"}
	lose := f.loseCreateResponse
	f.loseCreateResponse = false
	f.mu.Unlock()
	if lose {
		loseKMSResponse(w)
		return
	}
	writeJSON(w, map[string]any{"KeyMetadata": map[string]any{"KeyId": id, "KeySpec": in.KeySpec, "KeyUsage": "SIGN_VERIFY", "KeyState": "Enabled", "Enabled": true}})
}

func (f *operationKMS) describe(w http.ResponseWriter, id string) {
	f.mu.Lock()
	key := f.keys[id]
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"KeyMetadata": map[string]any{
		"KeyId": id, "KeySpec": key.spec, "KeyUsage": "SIGN_VERIFY", "KeyState": key.state, "Enabled": key.state == "Enabled",
	}})
}

func (f *operationKMS) publicKey(w http.ResponseWriter, id string) {
	f.mu.Lock()
	key := f.keys[id]
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"PublicKey": base64.StdEncoding.EncodeToString(key.signer.Public().DER)})
}

func (f *operationKMS) disable(w http.ResponseWriter, id string) {
	f.mu.Lock()
	key := f.keys[id]
	if key != nil {
		key.state = "Disabled"
		f.disableEffects++
	}
	lose := f.loseDisableResponse
	f.loseDisableResponse = false
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	if lose {
		loseKMSResponse(w)
		return
	}
	writeJSON(w, map[string]any{})
}

func (f *operationKMS) delete(w http.ResponseWriter, id string) {
	f.mu.Lock()
	key := f.keys[id]
	if key != nil {
		key.state = "PendingDeletion"
		f.deleteEffects++
	}
	lose := f.loseDeleteResponse
	f.loseDeleteResponse = false
	f.mu.Unlock()
	if key == nil {
		http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
		return
	}
	if lose {
		loseKMSResponse(w)
		return
	}
	writeJSON(w, map[string]any{"KeyId": id, "DeletionDate": 0})
}

func (f *operationKMS) lastCreated() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("operation-key-%d", f.n)
}

func (f *operationKMS) createEffects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func loseKMSResponse(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("AWS KMS emulator response writer cannot model a lost connection")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		panic(fmt.Sprintf("AWS KMS emulator hijack response: %v", err))
	}
	_ = conn.Close()
}
