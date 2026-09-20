// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRekorHandlerAssemblyRequiresPinnedLogPublicKey(t *testing.T) {
	_, err := rekorHandlerFromConfig(config.CodeSigningRekor{
		Endpoint: "https://rekor.sigstore.dev/api/v1/log/entries",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "log_public_key_file is required") {
		t.Fatalf("Rekor handler assembled without pinned log trust: %v", err)
	}
}

func TestRekorHandlerPublishesVendorHashedRekordAndValidatesEchoedBinding(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer logKey.Destroy()
	digest := crypto.SHA256Sum([]byte("artifact"))
	signature, err := key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15})
	if err != nil {
		t.Fatal(err)
	}
	transparency := codeSigningTransparencyPayload{
		Mode: "key", KeyID: "release", ArtifactType: "blob", DigestHex: crypto.SHA256Hex([]byte("artifact")),
		Algorithm: string(key.Algorithm()), Signature: signature, PublicKeyDER: key.Public().DER, QueuedAt: time.Now(),
	}
	payload, err := json.Marshal(transparency)
	if err != nil {
		t.Fatal(err)
	}
	wantProposed, _, err := rekorEntryFromPayload(transparency)
	if err != nil {
		t.Fatal(err)
	}
	receipt := signedRekorReceipt(t, wantProposed, logKey, logKey.Public(), 0)
	loggedBody, err := json.Marshal(wantProposed)
	if err != nil {
		t.Fatal(err)
	}
	entryUUID := crypto.SHA256Hex(append([]byte{0}, loggedBody...))
	postCalls, getCalls := 0, 0
	var responseBodies []*retainingCredentialResponseBody
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet {
			getCalls++
			if req.URL.Path != "/api/v1/log/entries/"+entryUUID {
				t.Fatalf("unexpected Rekor duplicate lookup: %s", req.URL)
			}
			body := newRetainingCredentialResponseBody(receipt)
			responseBodies = append(responseBodies, body)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
		}
		if req.Method != http.MethodPost || req.URL.Path != "/api/v1/log/entries" || req.Header.Get("X-Trstctl-Idempotency-Key") != "sign-1" {
			t.Fatalf("unexpected Rekor request: %s %s headers=%v", req.Method, req.URL, req.Header)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		var proposed rekorProposedEntry
		if err := json.Unmarshal(body, &proposed); err != nil {
			t.Fatal(err)
		}
		if proposed.Kind != "hashedrekord" || proposed.APIVersion != "0.0.1" || proposed.Spec.Data.Hash.Algorithm != "sha256" || proposed.Spec.Data.Hash.Value != crypto.SHA256Hex([]byte("artifact")) || !bytes.Equal(proposed.Spec.Signature.Content, signature) || !bytes.Contains(proposed.Spec.Signature.PublicKey.Content, []byte("BEGIN PUBLIC KEY")) {
			t.Fatalf("invalid Rekor HashedRekord: %+v", proposed)
		}
		if postCalls == 0 {
			postCalls++
			body := newRetainingCredentialResponseBody(receipt)
			responseBodies = append(responseBodies, body)
			return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: body}, nil
		}
		postCalls++
		headers := make(http.Header)
		headers.Set("Location", "https://rekor.example/api/v1/log/entries/"+entryUUID)
		responseBody := newRetainingCredentialResponseBody([]byte(`{"code":409,"message":"entry already exists"}`))
		responseBodies = append(responseBodies, responseBody)
		return &http.Response{
			StatusCode: http.StatusConflict, Header: headers,
			Body: responseBody,
		}, nil
	})}
	handler := &rekorHandler{endpoint: "https://rekor.example/api/v1/log/entries", client: client, logPublicKey: logKey.Public()}
	message := orchestrator.Message{
		Destination: defaultRekorDestination, IdempotencyKey: "sign-1", Payload: payload,
	}
	if err := handler.Deliver(context.Background(), message); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if err := handler.Deliver(context.Background(), message); err != nil {
		t.Fatalf("idempotent Deliver after Rekor 409: %v", err)
	}
	if postCalls != 2 || getCalls != 1 {
		t.Fatalf("Rekor retry calls POST=%d GET=%d, want POST=2 GET=1", postCalls, getCalls)
	}
	for _, body := range responseBodies {
		body.assertObservedBytesWiped(t)
	}
}

func TestRekorDuplicateLookupRejectsUntrustedLocation(t *testing.T) {
	clientCalls := 0
	handler := &rekorHandler{
		endpoint: "https://rekor.example/api/v1/log/entries",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			clientCalls++
			return nil, nil
		})},
	}
	for _, location := range []string{
		"https://attacker.example/api/v1/log/entries/" + strings.Repeat("a", 64),
		"https://rekor.example/api/v1/log/entries/" + strings.Repeat("a", 64) + "?redirect=attacker",
		"https://rekor.example/api/v1/log/entries/not-a-rekor-entry-id",
		"",
	} {
		if _, err := handler.fetchExistingReceipt(context.Background(), location); err == nil {
			t.Fatalf("duplicate lookup trusted unsafe Location %q", location)
		}
	}
	if clientCalls != 0 {
		t.Fatalf("unsafe duplicate Locations reached the HTTP client %d time(s)", clientCalls)
	}
}

func TestRekorReceiptRejectsUnboundLogEntry(t *testing.T) {
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer logKey.Destroy()
	proposed := rekorProposedEntry{
		APIVersion: "0.0.1", Kind: "hashedrekord",
		Spec: rekorHashedSpec{Data: rekorData{Hash: rekorHash{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}},
	}
	forged := proposed
	forged.Spec.Data.Hash.Value = strings.Repeat("b", 64)
	receipt := signedRekorReceipt(t, forged, logKey, logKey.Public(), 0)
	if err := validateRekorReceipt(receipt, proposed, logKey.Public()); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("forged Rekor receipt error = %v, want binding rejection", err)
	}
}

func TestRekorReceiptRejectsForgedSETAndUUID(t *testing.T) {
	trusted, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Destroy()
	attacker, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Destroy()
	proposed := rekorProposedEntry{
		APIVersion: "0.0.1", Kind: "hashedrekord",
		Spec: rekorHashedSpec{Data: rekorData{Hash: rekorHash{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}},
	}
	forgedSET := signedRekorReceipt(t, proposed, attacker, trusted.Public(), 0)
	if err := validateRekorReceipt(forgedSET, proposed, trusted.Public()); err == nil || !strings.Contains(err.Error(), "signed entry timestamp") {
		t.Fatalf("attacker-signed SET error = %v, want pinned-key rejection", err)
	}

	valid := signedRekorReceipt(t, proposed, trusted, trusted.Public(), 0)
	var entries map[string]rekorLogEntry
	if err := json.Unmarshal(valid, &entries); err != nil {
		t.Fatal(err)
	}
	var logged rekorLogEntry
	for _, entry := range entries {
		logged = entry
	}
	badUUID, err := json.Marshal(map[string]rekorLogEntry{strings.Repeat("f", 64): logged})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRekorReceipt(badUUID, proposed, trusted.Public()); err == nil || !strings.Contains(err.Error(), "UUID does not bind") {
		t.Fatalf("unbound UUID error = %v, want leaf-hash rejection", err)
	}
}

func signedRekorReceipt(t *testing.T, proposed rekorProposedEntry, signer crypto.DigestSigner, logIdentity crypto.PublicKey, index int64) []byte {
	t.Helper()
	loggedBody, err := json.Marshal(proposed)
	if err != nil {
		t.Fatal(err)
	}
	leafInput := append([]byte{0}, loggedBody...)
	uuid := crypto.SHA256Hex(leafInput)
	integrated := int64(1_770_000_000) + index
	logged := rekorLogEntry{
		Body: base64.StdEncoding.EncodeToString(loggedBody), IntegratedTime: &integrated,
		LogID: crypto.SHA256Hex(logIdentity.DER), LogIndex: &index,
	}
	canonical, err := canonicalRekorSET(logged)
	if err != nil {
		t.Fatal(err)
	}
	set, err := crypto.SignMessage(signer, canonical)
	if err != nil {
		t.Fatal(err)
	}
	logged.Verification.SignedEntryTimestamp = set
	receipt, err := json.Marshal(map[string]rekorLogEntry{uuid: logged})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
