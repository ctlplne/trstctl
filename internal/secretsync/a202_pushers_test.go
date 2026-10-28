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
	"strings"
	"sync"
	"testing"
	"time"
)

// A202: a receiver holding the signing key verifies a delivery; a changed body,
// a stale timestamp, another key, or a missing header fails. The default body
// carries the value base64-encoded; a template places it where the receiver
// wants it, JSON-escaped.
func TestWebhookDeliveryVerifiesAtTheReceiverAndATamperedBodyFails(t *testing.T) {
	key := []byte("shared-webhook-signing-key")
	now := time.Unix(1_800_000_000, 0)
	type delivery struct {
		body                          []byte
		timestamp, signature, deliver string
		auth                          string
	}
	var mu sync.Mutex
	var got []delivery
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, delivery{body: body, timestamp: r.Header.Get(WebhookTimestampHeader),
			signature: r.Header.Get(WebhookSignatureHeader), deliver: r.Header.Get(WebhookDeliveryHeader), auth: r.Header.Get("Authorization")})
		mu.Unlock()
		if err := VerifyWebhookSignature(key, r.Header.Get(WebhookTimestampHeader), body, r.Header.Get(WebhookSignatureHeader), now, 0); err != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()

	pusher, err := NewWebhookPusher(WebhookConfig{Endpoint: receiver.URL, HTTPClient: receiver.Client(), SigningKey: key,
		BearerToken: []byte("receiver-token"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	ctx := WithOperationID(context.Background(), "delivery-42")
	if err := pusher.Push(ctx, "db/password", []byte("s3cr\"et\n")); err != nil {
		t.Fatalf("signed delivery refused by the receiver: %v", err)
	}
	mu.Lock()
	first := got[0]
	mu.Unlock()
	var envelope struct {
		Key         string `json:"key"`
		ValueBase64 string `json:"value_base64"`
		DeliveryID  string `json:"delivery_id"`
		Timestamp   int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(first.body, &envelope); err != nil {
		t.Fatalf("default body is not JSON: %v %s", err, first.body)
	}
	value, _ := base64.StdEncoding.DecodeString(envelope.ValueBase64)
	if envelope.Key != "db/password" || string(value) != "s3cr\"et\n" || envelope.DeliveryID != "delivery-42" ||
		envelope.Timestamp != now.Unix() || first.deliver != "delivery-42" || first.auth != "Bearer receiver-token" {
		t.Fatalf("delivery = %+v headers %+v", envelope, first)
	}

	// The receiver's check: tamper, replay late, wrong key, missing header.
	tampered := bytes.Replace(first.body, []byte(envelope.ValueBase64), []byte(base64.StdEncoding.EncodeToString([]byte("attacker"))), 1)
	for name, err := range map[string]error{
		"tampered body": VerifyWebhookSignature(key, first.timestamp, tampered, first.signature, now, 0),
		"late replay":   VerifyWebhookSignature(key, first.timestamp, first.body, first.signature, now.Add(10*time.Minute), 0),
		"another key":   VerifyWebhookSignature([]byte("other"), first.timestamp, first.body, first.signature, now, 0),
		"no signature":  VerifyWebhookSignature(key, first.timestamp, first.body, "", now, 0),
		"no timestamp":  VerifyWebhookSignature(key, "", first.body, first.signature, now, 0),
	} {
		if err == nil {
			t.Fatalf("%s verified", name)
		}
	}
	if err := VerifyWebhookSignature(key, first.timestamp, first.body, first.signature, now, 0); err != nil {
		t.Fatalf("the genuine delivery = %v", err)
	}

	// A template places the value where the receiver wants it.
	templated, err := NewWebhookPusher(WebhookConfig{Endpoint: receiver.URL, HTTPClient: receiver.Client(), SigningKey: key,
		BodyTemplate: `{"data":{"name":"${key}","secret":"${value}"},"at":${timestamp}}`, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer templated.Close()
	if err := templated.Push(context.Background(), "api/token", []byte("tok\"en\\")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	second := got[1].body
	mu.Unlock()
	var shaped struct {
		Data struct{ Name, Secret string }
		At   int64
	}
	if err := json.Unmarshal(second, &shaped); err != nil || shaped.Data.Name != "api/token" || shaped.Data.Secret != "tok\"en\\" || shaped.At != now.Unix() {
		t.Fatalf("templated body = %s (%v)", second, err)
	}
	if err := templated.Push(context.Background(), "bin", []byte{0xff, 0xfe}); err == nil {
		t.Fatal("a non-UTF-8 secret went into ${value}")
	}
}

func TestWebhookTemplateValidation(t *testing.T) {
	for template, ok := range map[string]bool{
		"":                              true,
		`{"v":"${value_base64}"}`:       true,
		`{"v":"${value}","k":"${key}"}`: true,
		`{"k":"${key}"}`:                false, // carries no value
		`{"v":${value}}`:                false, // unquoted string placeholder
		`{"v":"${secret}"}`:             false, // unknown placeholder
		`{"v":"${value"}`:               false,
	} {
		if err := ValidateWebhookTemplate(template); (err == nil) != ok {
			t.Errorf("template %q: %v, want ok=%v", template, err, ok)
		}
	}
}

// A202: Parameter Store writes a SecureString with Overwrite at the
// hierarchical name, signed with SigV4 for the ssm service.
func TestParameterStorePutsASecureStringParameter(t *testing.T) {
	var target, auth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, auth = r.Header.Get("X-Amz-Target"), r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"Version":1,"Tier":"Standard"}`))
	}))
	defer srv.Close()
	pusher, err := NewAWSParameterStorePusher(AWSParameterStoreConfig{
		Endpoint: srv.URL, HTTPClient: srv.Client(), Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE",
		SecretAccessKey: []byte("example-secret"), PathPrefix: "/apps/payments/", KMSKeyID: "alias/apps",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	if err := pusher.Push(context.Background(), "db/password", []byte("pa\"ss")); err != nil {
		t.Fatal(err)
	}
	if target != "AmazonSSM.PutParameter" || !strings.Contains(auth, "/us-east-1/ssm/aws4_request") {
		t.Fatalf("target %q auth %q", target, auth)
	}
	if body["Name"] != "/apps/payments/db/password" || body["Value"] != "pa\"ss" || body["Type"] != "SecureString" ||
		body["Overwrite"] != true || body["KeyId"] != "alias/apps" {
		t.Fatalf("PutParameter body = %v", body)
	}
	if err := pusher.Push(context.Background(), "bin", []byte{0xff}); err == nil {
		t.Fatal("a non-UTF-8 value was written to Parameter Store")
	}
}

// A202: Netlify reads the variable first; a present one gets the value for the
// target's context (PATCH), a missing one is created as a secret with scopes.
func TestNetlifySetsAnExistingVariableAndCreatesAMissingOne(t *testing.T) {
	var mu sync.Mutex
	existing := map[string]bool{"PRESENT": true}
	var calls []string
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		lastBody = body
		if r.Header.Get("Authorization") != "Bearer netlify-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		key := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch r.Method {
		case http.MethodGet:
			if !existing[key] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"scopes":["builds","functions","runtime"]}`))
		case http.MethodPatch, http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	pusher, err := NewNetlifyPusher(NetlifyConfig{Endpoint: srv.URL + "/api/v1", HTTPClient: srv.Client(), Token: []byte("netlify-token"),
		AccountID: "team-1", SiteID: "site-1", Context: "production"})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	ctx := context.Background()
	if err := pusher.Push(ctx, "PRESENT", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	var patch struct{ Context, Value string }
	_ = json.Unmarshal(lastBody, &patch)
	mu.Unlock()
	if patch.Context != "production" || patch.Value != "v1" {
		t.Fatalf("PATCH body = %+v", patch)
	}
	if err := pusher.Push(ctx, "MISSING", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	var created []struct {
		Key      string
		Scopes   []string
		IsSecret bool `json:"is_secret"`
		Values   []struct{ Value, Context string }
	}
	_ = json.Unmarshal(lastBody, &created)
	recorded := append([]string(nil), calls...)
	mu.Unlock()
	if len(created) != 1 || created[0].Key != "MISSING" || !created[0].IsSecret || created[0].Values[0].Value != "v2" ||
		created[0].Values[0].Context != "production" || strings.Join(created[0].Scopes, ",") != "builds,functions,runtime" {
		t.Fatalf("POST body = %+v", created)
	}
	want := []string{
		"GET /api/v1/accounts/team-1/env/PRESENT?site_id=site-1",
		"PATCH /api/v1/accounts/team-1/env/PRESENT?site_id=site-1",
		"GET /api/v1/accounts/team-1/env/MISSING?site_id=site-1",
		"POST /api/v1/accounts/team-1/env?site_id=site-1",
	}
	if strings.Join(recorded, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Netlify calls:\n%s\nwant:\n%s", strings.Join(recorded, "\n"), strings.Join(want, "\n"))
	}
	if _, err := NewNetlifyPusher(NetlifyConfig{Token: []byte("t"), AccountID: "a", Context: "staging"}); err == nil {
		t.Fatal("an unknown deploy context was accepted")
	}
}
