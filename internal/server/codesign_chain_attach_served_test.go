// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
)

// P9-L1: a code-signing key's certificate chain is attached, and rotated,
// through the API: checked against the key's public key and the codeSigning
// usage, recorded, and served from the next request on — with no
// configuration change and no restart, and by another service over the same
// store (another replica). A chain for another key, a TLS server leaf or no
// certificate at all is refused; a principal that may only read cannot
// attach; an exact retry records nothing more.
func TestServedCodeSigningChainAttachedWithoutRestartP9L1(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signingKey.Destroy)
	otherKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherKey.Destroy)
	ca := newP9CA(t)
	cfg := CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
		"release-key-p9l1": testOperationDigestSigner{DigestSigner: signingKey},
	}}}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.CodeSigning = cfg })
	writer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-admin", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	reader := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-reader", []string{string(authz.KeysRead)})
	const route = "/api/v1/code-signing/keys/release-key-p9l1/certificate"

	if status, body := secretsReq(t, h, http.MethodGet, route, reader, nil); status != http.StatusNotFound {
		t.Fatalf("a key with no chain = %d %s; want 404", status, body)
	}
	chainFor := func(key crypto.DigestSigner, eku string) (string, string) {
		t.Helper()
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer", RequestedEKUs: []string{eku}}, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf := ca.issue(t, csr, eku)
		info, err := certinfo.Inspect(leaf)
		if err != nil {
			t.Fatal(err)
		}
		return string(append(crypto.EncodeCertificatePEM(leaf), crypto.EncodeCertificatePEM(ca.rootDER)...)), info.SHA256Fingerprint
	}
	attach := func(token, key, chain string) (int, api.CodeSigningKeyCertificate, []byte) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPut, route, token, key, map[string]any{"chain_pem": chain})
		var out api.CodeSigningKeyCertificate
		_ = json.Unmarshal(body, &out)
		return status, out, body
	}

	// Refusals before anything is recorded.
	wrongKey, _ := chainFor(otherKey, "codeSigning")
	serverLeaf, _ := chainFor(signingKey, "serverAuth")
	for name, tc := range map[string]struct {
		chain string
		want  string
	}{
		"another key's chain": {wrongKey, "does not name this key"},
		"a TLS server leaf":   {serverLeaf, "codeSigning"},
		"no certificate":      {"-----BEGIN NOTHING-----\nAA==\n-----END NOTHING-----\n", "no PEM certificate"},
	} {
		if status, _, body := attach(writer, "p9l1-refused-"+strings.ReplaceAll(name, " ", "-"), tc.chain); status != http.StatusUnprocessableEntity || !strings.Contains(string(body), tc.want) {
			t.Fatalf("%s = %d %s; want 422 naming %q", name, status, body, tc.want)
		}
	}
	firstChain, firstLeaf := chainFor(signingKey, "codeSigning")
	if status, _, body := attach(reader, "p9l1-reader", firstChain); status != http.StatusForbidden {
		t.Fatalf("a reader attaching = %d %s; want 403", status, body)
	}
	if n := countCodeSigningChainEvents(t, h); n != 0 {
		t.Fatalf("refused attachments recorded %d events", n)
	}

	// Attach: served at once, as attached.
	status, attached, body := attach(writer, "p9l1-attach", firstChain)
	if status != http.StatusOK || attached.Source != "attached" || attached.AttachedBy != "release-admin" || attached.AttachedAt == nil ||
		attached.ChainPEM != firstChain || attached.LeafFingerprint != firstLeaf || !attached.CodeSigningEKU {
		t.Fatalf("attach = %d %s", status, body)
	}
	if replay, _, replayBody := attach(writer, "p9l1-attach", firstChain); replay != status || string(replayBody) != string(body) {
		t.Fatalf("an exact retry = %d %s; want the first response", replay, replayBody)
	}
	if n := countCodeSigningChainEvents(t, h); n != 1 {
		t.Fatalf("attach and its retry recorded %d events; want 1", n)
	}
	status, body = secretsReq(t, h, http.MethodGet, route, reader, nil)
	var served api.CodeSigningKeyCertificate
	if status != http.StatusOK || json.Unmarshal(body, &served) != nil || served.Source != "attached" || served.ChainPEM != firstChain {
		t.Fatalf("read after attach = %d %s", status, body)
	}

	// Rotate: the next chain is served from the next request on.
	secondChain, secondLeaf := chainFor(signingKey, "codeSigning")
	if status, rotated, body := attach(writer, "p9l1-rotate", secondChain); status != http.StatusOK || rotated.LeafFingerprint != secondLeaf || rotated.ChainPEM != secondChain {
		t.Fatalf("rotate = %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, route, reader, nil)
	if status != http.StatusOK || json.Unmarshal(body, &served) != nil || served.LeafFingerprint != secondLeaf || strings.Contains(served.ChainPEM, firstChain[:200]) {
		t.Fatalf("read after rotation = %d %s; want the second leaf only", status, body)
	}

	// Another replica, built from the same configuration over the same store,
	// serves the rotated chain without having seen either request.
	replica := &servedCodeSigningService{cfg: cfg, store: h.store}
	fromReplica, err := replica.KeyCertificate(context.Background(), h.tenant, "release-key-p9l1")
	if err != nil || fromReplica.Source != "attached" || fromReplica.LeafFingerprint != secondLeaf {
		t.Fatalf("another replica reads %+v, %v; want the rotated chain", fromReplica, err)
	}
}

func countCodeSigningChainEvents(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == "codesign.certificate_attached" {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
