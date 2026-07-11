// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedCodeSigningKeyBasedAndKeylessSigstore(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate code-signing key: %v", err)
	}
	t.Cleanup(signingKey.Destroy)
	rekor := &rekorFixture{}
	var ephemeralKeys sync.Map

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": testOperationDigestSigner{DigestSigner: signingKey}}},
			Attestors: []attest.Attestor{
				fulcioFixtureAttestor{
					subject: "repo:acme/payments:ref:refs/heads/main",
					issuer:  "https://token.actions.githubusercontent.com",
				},
			},
			NewEphemeralSigner: func(_ context.Context, operationID string, algorithm crypto.Algorithm) (crypto.DigestSigner, string, error) {
				if existing, ok := ephemeralKeys.Load(operationID); ok {
					return testOperationDigestSigner{DigestSigner: existing.(*crypto.LockedSigner)}, operationID, nil
				}
				key, err := crypto.GenerateLockedKey(algorithm)
				if err != nil {
					return nil, "", err
				}
				ephemeralKeys.Store(operationID, key)
				return testOperationDigestSigner{DigestSigner: key}, operationID, nil
			},
			DestroyEphemeralSigner: func(_ context.Context, handle string) error {
				if value, ok := ephemeralKeys.LoadAndDelete(handle); ok {
					value.(*crypto.LockedSigner).Destroy()
				}
				return nil
			},
			RekorDestination:    "transparency.rekor",
			TransparencyHandler: rekor,
		}
	})
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		h.srv.RunDispatcher(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	digest := crypto.SHA256Sum([]byte("oci manifest bytes"))

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, "clm-06-keyed-sign", map[string]any{
		"key_id":        "release-key",
		"artifact_type": "oci-image",
		"digest":        digest,
	})
	if code != http.StatusOK {
		op, _, _ := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, "clm-06-keyed-sign")
		t.Fatalf("key-based code-signing = %d, want 200; body=%s operation=%+v", code, body, op)
	}
	var keyed struct {
		Algorithm        string `json:"algorithm"`
		KeyID            string `json:"key_id"`
		ArtifactType     string `json:"artifact_type"`
		Signature        []byte `json:"signature"`
		PublicKeyDER     []byte `json:"public_key_der"`
		TransparencyDest string `json:"transparency_destination"`
	}
	if err := json.Unmarshal(body, &keyed); err != nil {
		t.Fatalf("decode key-based response: %v body=%s", err, body)
	}
	if keyed.KeyID != "release-key" || keyed.ArtifactType != "oci-image" || keyed.TransparencyDest != "transparency.rekor" {
		t.Fatalf("unexpected key-based response: %+v", keyed)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.Algorithm(keyed.Algorithm), DER: keyed.PublicKeyDER}, digest, keyed.Signature, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err != nil {
		t.Fatalf("served key-based signature does not verify: %v", err)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/keyless", token, "clm-06-keyless-sign", map[string]any{
		"artifact_type":    "oci-image",
		"digest":           digest,
		"identity_method":  "fulcio_fixture",
		"identity_payload": []byte(`{"token":"fixture-good"}`),
		"fulcio_san":       "repo:acme/payments:ref:refs/heads/main",
		"fulcio_issuer":    "https://token.actions.githubusercontent.com",
	})
	if code != http.StatusOK {
		t.Fatalf("keyless code-signing = %d, want 200; body=%s", code, body)
	}
	var keyless struct {
		Algorithm        string `json:"algorithm"`
		ArtifactType     string `json:"artifact_type"`
		Signature        []byte `json:"signature"`
		PublicKeyDER     []byte `json:"public_key_der"`
		FulcioSAN        string `json:"fulcio_san"`
		FulcioIssuer     string `json:"fulcio_issuer"`
		TransparencyDest string `json:"transparency_destination"`
	}
	if err := json.Unmarshal(body, &keyless); err != nil {
		t.Fatalf("decode keyless response: %v body=%s", err, body)
	}
	if keyless.FulcioSAN != "repo:acme/payments:ref:refs/heads/main" || keyless.FulcioIssuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("keyless response is not bound to the Fulcio fixture identity: %+v", keyless)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.Algorithm(keyless.Algorithm), DER: keyless.PublicKeyDER}, digest, keyless.Signature, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err != nil {
		t.Fatalf("served keyless signature does not verify: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	cleanupStatus := ""
	for time.Now().Before(deadline) {
		op, found, loadErr := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, "clm-06-keyless-sign")
		if loadErr == nil && found {
			cleanupStatus = op.CleanupStatus
		}
		if rekor.Accepted() == 2 && cleanupStatus == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := rekor.Accepted(); got != 2 {
		t.Fatalf("Rekor fixture accepted %d entries, want 2", got)
	}
	if cleanupStatus != "completed" {
		t.Fatalf("keyless ephemeral cleanup status = %q, want completed", cleanupStatus)
	}

	identityToken := []byte(`{"token":"fixture-good"}`)
	if op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, "clm-06-keyless-sign"); err != nil || !found {
		t.Fatalf("load keyless operation = found %v err %v", found, err)
	} else if bytes.Contains(op.SealedCommand, identityToken) {
		t.Fatal("keyless identity token is plaintext in code_signing_operations")
	}
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == "codesign.commanded" && bytes.Contains(event.Data, identityToken) {
			return errors.New("keyless identity token is plaintext in immutable event")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !h.hasEvent(t, "codesign.signed") || !h.hasEvent(t, "codesign.keyless.signed") {
		t.Fatal("served code-signing did not record key-based and keyless audit events")
	}
}

type codeSigningKeyMap struct {
	keys map[string]crypto.DigestSigner
}

func (m codeSigningKeyMap) Signer(_ string, keyID string) (crypto.DigestSigner, error) {
	signer, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("no key %s", keyID)
	}
	return signer, nil
}

var _ codesign.KeyResolver = codeSigningKeyMap{}

type testOperationDigestSigner struct{ crypto.DigestSigner }

func (s testOperationDigestSigner) SignDigestForOperation(_ string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.SignDigest(digest, opts)
}

type fulcioFixtureAttestor struct {
	subject string
	issuer  string
}

func (a fulcioFixtureAttestor) Method() string { return "fulcio_fixture" }

func (a fulcioFixtureAttestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	if string(payload) != `{"token":"fixture-good"}` {
		return attest.Attestation{}, errFulcioFixtureRejected{}
	}
	return attest.Attestation{
		Subject: a.subject,
		Claims:  map[string]string{"oidc_issuer": a.issuer},
	}, nil
}

type errFulcioFixtureRejected struct{}

func (errFulcioFixtureRejected) Error() string { return "fulcio fixture rejected identity token" }

type rekorFixture struct {
	mu      sync.Mutex
	entries [][]byte
}

func (r *rekorFixture) Deliver(_ context.Context, m orchestrator.Message) error {
	if m.Destination != "transparency.rekor" {
		return fmt.Errorf("unexpected transparency destination %q", m.Destination)
	}
	operationID := strings.TrimPrefix(m.IdempotencyKey, "codesign.rekor:")
	if operationID == m.IdempotencyKey || m.EffectLane != m.Destination+":"+operationID {
		return fmt.Errorf("Rekor outbox identity/lane is not operation-bound: key=%q lane=%q", m.IdempotencyKey, m.EffectLane)
	}
	var payload struct {
		Mode         string `json:"mode"`
		ArtifactType string `json:"artifact_type"`
		DigestHex    string `json:"digest_hex"`
		Signature    []byte `json:"signature"`
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return err
	}
	if payload.Mode == "" || payload.ArtifactType == "" || payload.DigestHex == "" || len(payload.Signature) == 0 || len(payload.PublicKeyDER) == 0 {
		return fmt.Errorf("incomplete Rekor payload: %+v", payload)
	}
	r.mu.Lock()
	r.entries = append(r.entries, append([]byte(nil), m.Payload...))
	r.mu.Unlock()
	return nil
}

func (r *rekorFixture) Accepted() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
