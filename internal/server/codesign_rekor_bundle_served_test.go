// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// P9-L2: a signature's transparency-log entry reaches the operator as the
// bundle stock cosign verifies offline. A Rekor stand-in (the log's v1 entry
// API, its entries signed the way Rekor signs them) receives the signature
// through the outbox; the verified receipt is recorded, and
// GET .../rekor-bundle serves it: the signed entry timestamp verifies under
// the log's key over the logged body, index, time and log identity, and the
// body is the signature's hashedrekord. A changed timestamp does not verify,
// and an operation with no entry answers 404.
func TestServedCodeSigningRekorBundleVerifiesOfflineP9L2(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signingKey.Destroy)
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logKey.Destroy)
	var mu sync.Mutex
	var nextIndex int64
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		var proposed rekorProposedEntry
		if err != nil || json.Unmarshal(raw, &proposed) != nil || proposed.Kind != "hashedrekord" {
			http.Error(w, "not a hashedrekord", http.StatusBadRequest)
			return
		}
		mu.Lock()
		index := nextIndex
		nextIndex++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(signedRekorReceipt(t, proposed, logKey, logKey.Public(), index))
	}))
	t.Cleanup(rekor.Close)

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key-p9l2": testOperationDigestSigner{DigestSigner: signingKey},
			}},
			TransparencyHandler: &rekorHandler{endpoint: rekor.URL + "/api/v1/log/entries", client: rekor.Client(), logPublicKey: logKey.Public()},
			RekorDestination:    defaultRekorDestination,
		}
	})
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot-p9l2", []string{
		string(authz.KeysRead), string(authz.KeysWrite), string(authz.CertsRead),
	})
	digest := crypto.SHA256Sum([]byte("p9l2 release artifact"))
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, "p9l2-sign", map[string]any{
		"key_id": "release-key-p9l2", "artifact_type": "blob", "digest": digest,
	})
	var signed struct {
		OperationID string `json:"operation_id"`
		Signature   []byte `json:"signature"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &signed) != nil || len(signed.Signature) == 0 {
		t.Fatalf("sign = %d %s", status, body)
	}
	operationID := signed.OperationID
	if operationID == "" {
		// Without the response naming it, the operation is the one the
		// identities view lists for this tenant.
		status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/code-signing/identities", token, "", nil)
		var list struct {
			Items []struct {
				OperationID string `json:"operation_id"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) == 0 {
			t.Fatalf("the sign response names no operation and the identities view lists none: %d %s", status, body)
		}
		operationID = list.Items[0].OperationID
	}

	var bundle struct {
		OperationID    string `json:"operation_id"`
		EntryUUID      string `json:"entry_uuid"`
		LogIndex       int64  `json:"log_index"`
		LogID          string `json:"log_id"`
		IntegratedTime int64  `json:"integrated_time"`
		CosignBundle   string `json:"cosign_bundle"`
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/code-signing/identities/"+operationID+"/rekor-bundle", token, "", nil)
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &bundle); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rekor-bundle for %s: HTTP %d %s after the outbox had 30s to publish (log saw %d entries)", operationID, status, body, nextIndex)
		}
		time.Sleep(time.Second)
	}
	if bundle.OperationID != operationID || bundle.LogID != crypto.SHA256Hex(logKey.Public().DER) || len(bundle.EntryUUID) != 64 || bundle.IntegratedTime <= 0 {
		t.Fatalf("bundle = %+v", bundle)
	}

	// cosign's offline check, over the served document.
	var document struct {
		Base64Signature string `json:"base64Signature"`
		RekorBundle     struct {
			SignedEntryTimestamp []byte `json:"SignedEntryTimestamp"`
			Payload              struct {
				Body           string `json:"body"`
				IntegratedTime int64  `json:"integratedTime"`
				LogIndex       int64  `json:"logIndex"`
				LogID          string `json:"logID"`
			} `json:"Payload"`
		} `json:"rekorBundle"`
	}
	if err := json.Unmarshal([]byte(bundle.CosignBundle), &document); err != nil || len(document.RekorBundle.SignedEntryTimestamp) == 0 ||
		document.Base64Signature != base64.StdEncoding.EncodeToString(signed.Signature) {
		t.Fatalf("cosign bundle = %s (%v)", bundle.CosignBundle, err)
	}
	cosign := document.RekorBundle
	integrated, index := cosign.Payload.IntegratedTime, cosign.Payload.LogIndex
	canonical, err := canonicalRekorSET(rekorLogEntry{Body: cosign.Payload.Body, IntegratedTime: &integrated, LogID: cosign.Payload.LogID, LogIndex: &index})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRekorSET(logKey.Public(), canonical, cosign.SignedEntryTimestamp); err != nil {
		t.Fatalf("the bundle's signed entry timestamp does not verify under the log key: %v", err)
	}
	changed := bytes.Clone(cosign.SignedEntryTimestamp)
	changed[len(changed)/2] ^= 0x01
	if verifyRekorSET(logKey.Public(), canonical, changed) == nil {
		t.Fatal("a changed signed entry timestamp verified")
	}
	logged, err := base64.StdEncoding.DecodeString(cosign.Payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	var entry rekorProposedEntry
	if err := json.Unmarshal(logged, &entry); err != nil || !bytes.Equal(entry.Spec.Signature.Content, signed.Signature) ||
		entry.Spec.Data.Hash.Value != hex.EncodeToString(digest) {
		t.Fatalf("the logged body is not this signature's hashedrekord: %s (%v)", logged, err)
	}

	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/code-signing/identities/no-such-operation/rekor-bundle", token, "", nil); status != http.StatusNotFound {
		t.Fatalf("an operation with no entry = %d %s; want 404", status, body)
	}
}
