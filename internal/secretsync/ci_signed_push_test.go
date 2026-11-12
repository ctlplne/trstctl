// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// OD-12 (B14-L2): a generic CI push the operator gave a signing key carries
// the signed webhook's handshake. The receiver verifies X-Trstctl-Signature
// over the timestamp and the exact body, so a changed body, a late replay and
// another key fail; the envelope and the bearer token are unchanged; a push
// without a key carries no signature headers, as before.
func TestGenericCIPushIsHMACSignedLikeTheWebhookOD12(t *testing.T) {
	key := []byte("shared-ci-signing-key")
	now := time.Unix(1_800_000_000, 0)
	type push struct {
		body                           []byte
		timestamp, signature, delivery string
		auth, path                     string
	}
	var mu sync.Mutex
	var got []push
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p := push{body: body, timestamp: r.Header.Get(WebhookTimestampHeader), signature: r.Header.Get(WebhookSignatureHeader),
			delivery: r.Header.Get(WebhookDeliveryHeader), auth: r.Header.Get("Authorization"), path: r.URL.Path}
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
		if p.signature != "" && VerifyWebhookSignature(key, p.timestamp, body, p.signature, now, 0) != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()

	signed, err := NewCIPusher(CIPusherConfig{Endpoint: receiver.URL, HTTPClient: receiver.Client(), BearerToken: []byte("ci-token"),
		Provider: "example-ci", SigningKey: key, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !signed.Signed() {
		t.Fatal("a CI pusher with a signing key does not report itself signed")
	}
	ctx := WithOperationID(context.Background(), "delivery-7")
	if err := signed.Push(ctx, "deploy/token", []byte("s3cr\"et\n")); err != nil {
		t.Fatalf("signed push refused by the receiver: %v", err)
	}
	mu.Lock()
	first := got[0]
	mu.Unlock()
	var envelope struct {
		Provider     string `json:"provider"`
		Key          string `json:"key"`
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(first.body, &envelope); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	value, _ := base64.StdEncoding.DecodeString(envelope.EncodedValue)
	if first.path != "/secrets" || envelope.Provider != "example-ci" || envelope.Key != "deploy/token" || string(value) != "s3cr\"et\n" ||
		first.auth != "Bearer ci-token" || first.delivery != "delivery-7" || first.timestamp != "1800000000" {
		t.Fatalf("signed push = %+v envelope %+v", first, envelope)
	}
	if err := VerifyWebhookSignature(key, first.timestamp, first.body, first.signature, now, 0); err != nil {
		t.Fatalf("the genuine push does not verify: %v", err)
	}
	tampered := bytes.Replace(first.body, []byte(envelope.EncodedValue), []byte(base64.StdEncoding.EncodeToString([]byte("attacker"))), 1)
	for name, err := range map[string]error{
		"tampered body": VerifyWebhookSignature(key, first.timestamp, tampered, first.signature, now, 0),
		"late replay":   VerifyWebhookSignature(key, first.timestamp, first.body, first.signature, now.Add(10*time.Minute), 0),
		"another key":   VerifyWebhookSignature([]byte("other"), first.timestamp, first.body, first.signature, now, 0),
		"no signature":  VerifyWebhookSignature(key, first.timestamp, first.body, "", now, 0),
	} {
		if err == nil {
			t.Fatalf("%s verified", name)
		}
	}
	signed.Close()
	if signed.Signed() {
		t.Fatal("Close kept the signing key")
	}

	// Without a key the push is the bearer-only envelope, as before.
	plain, err := NewCIPusher(CIPusherConfig{Endpoint: receiver.URL, HTTPClient: receiver.Client(), BearerToken: []byte("ci-token")})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain.Signed() {
		t.Fatal("a CI pusher without a key reports itself signed")
	}
	if err := plain.Push(ctx, "deploy/token", []byte("v")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	second := got[1]
	mu.Unlock()
	if second.signature != "" || second.timestamp != "" || second.delivery != "" || second.auth != "Bearer ci-token" {
		t.Fatalf("unsigned push = %+v", second)
	}
}

// OD-12: the catalog row of a configured target reports the signature only
// when it is there: always for the webhook, and for a generic CI push only
// with a signing key.
func TestConfiguredTargetReportsItsPayloadSignatureOD12(t *testing.T) {
	if NewConfiguredTarget("ci", "generic-ci-json", false, nil).PayloadSigned() {
		t.Fatal("an unsigned CI target reports a signature")
	}
	if !NewConfiguredTarget("ci", "generic-ci-json", false, nil).WithSignedPayload(true).PayloadSigned() {
		t.Fatal("a signed CI target does not report its signature")
	}
	if !NewConfiguredTarget("hooks", "webhook", false, nil).PayloadSigned() {
		t.Fatal("the signed webhook does not report its signature")
	}
	var missing *Target
	if missing.PayloadSigned() {
		t.Fatal("a missing target reports a signature")
	}
}
