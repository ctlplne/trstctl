// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedCodeSigningKeyBasedAndKeylessSigstore(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate code-signing key: %v", err)
	}
	t.Cleanup(signingKey.Destroy)
	rekor := &rekorFixture{}

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": signingKey}},
			Attestors: []attest.Attestor{
				fulcioFixtureAttestor{
					subject: "repo:acme/payments:ref:refs/heads/main",
					issuer:  "https://token.actions.githubusercontent.com",
				},
			},
			RekorDestination:    "transparency.rekor",
			TransparencyHandler: rekor,
		}
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
		t.Fatalf("key-based code-signing = %d, want 200; body=%s", code, body)
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
	if err := crypto.VerifyMessage(keyed.PublicKeyDER, digest, keyed.Signature); err != nil {
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
	if err := crypto.VerifyMessage(keyless.PublicKeyDER, digest, keyless.Signature); err != nil {
		t.Fatalf("served keyless signature does not verify: %v", err)
	}

	rows, err := h.srv.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	var rekorRows []orchestrator.Record
	for _, row := range rows {
		if row.Destination == "transparency.rekor" {
			rekorRows = append(rekorRows, row)
		}
	}
	if len(rekorRows) != 2 {
		t.Fatalf("Rekor outbox rows = %d, want 2; rows=%+v", len(rekorRows), rows)
	}
	if n, err := h.srv.outbox.Dispatch(context.Background(), h.srv.obHandler); err != nil || n != 2 {
		t.Fatalf("dispatch Rekor outbox rows = (%d, %v), want (2, nil)", n, err)
	}
	if rekor.Accepted() != 2 {
		t.Fatalf("Rekor fixture accepted %d entries, want 2", rekor.Accepted())
	}
	if !h.hasEvent(t, "codesign.signed") || !h.hasEvent(t, "codesign.keyless.signed") {
		t.Fatal("served code-signing did not record key-based and keyless audit events")
	}
}

type codeSigningKeyMap struct {
	keys map[string]crypto.DigestSigner
}

func (m codeSigningKeyMap) Signer(keyID string) (crypto.DigestSigner, error) {
	signer, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("no key %s", keyID)
	}
	return signer, nil
}

var _ codesign.KeyResolver = codeSigningKeyMap{}

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
	entries [][]byte
}

func (r *rekorFixture) Deliver(_ context.Context, m orchestrator.Message) error {
	if m.Destination != "transparency.rekor" {
		return fmt.Errorf("unexpected transparency destination %q", m.Destination)
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
	r.entries = append(r.entries, append([]byte(nil), m.Payload...))
	return nil
}

func (r *rekorFixture) Accepted() int { return len(r.entries) }
