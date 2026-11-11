// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// A172-L3: a private key found in a secret store is linked to the
// certificate it belongs to. Its finding carries the SHA-256 of its public
// key, the hash the certificate's own public key has, and the credential graph
// links the stored key to that certificate (KEY_OF): compromising the stored
// key puts the certificate at risk. A stored key whose certificate is not in
// the inventory links to nothing, and an encrypted key carries no hash.
func TestServedStoredPrivateKeyLinksToItsCertificateA172L3(t *testing.T) {
	ctx := context.Background()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(keyPEM)
	const subjectName = "a172l3.served.test"
	certDER, err := crypto.SelfSignedCACert(key, subjectName, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Destroy)
	otherPEM, err := other.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(otherPEM)
	encrypted := "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nMIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIa172l3encrypted\n-----END " + "ENCRYPTED PRIVATE KEY-----\n"

	var vaultSeen []string
	vault := a172VaultKVDouble(map[string]map[string]string{
		"ci/web-tls":   {"key": string(keyPEM)},
		"ci/other-tls": {"key": string(otherPEM)},
		"ci/locked":    {"key": encrypted},
	}, &vaultSeen)
	t.Cleanup(vault.Close)
	t.Setenv("TRSTCTL_A172L3_VAULT_TOKEN", "vault-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A172L3_VAULT_TOKEN"))
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "graph:read", string(authz.PrivateEgress))

	notBefore, notAfter := info.NotBefore, info.NotAfter
	cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		Subject: info.Subject, Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter, Source: "a172l3-inventory",
		CertificateDER: certDER, Status: "active",
	})
	if err != nil {
		t.Fatalf("record the certificate: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "a172l3-vault", "kind": "secret_store", "config": map[string]any{"providers": []map[string]any{{
			"provider": "hashicorp-vault", "vault_url": vault.URL, "mount": "secret", "path_prefix": "ci",
			"token_ref": "env:TRSTCTL_A172L3_VAULT_TOKEN", "inspect_content": true, // #nosec G101 -- a credential reference to a fabricated fixture value (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, vault.URL)},
		}}}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("create the source: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID}); status != http.StatusCreated {
		t.Fatalf("run: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=secret_store_api_key&limit=100", tok, nil)
	var list struct {
		Items []struct {
			ID       string         `json:"id"`
			SourceID string         `json:"source_id"`
			Ref      string         `json:"ref"`
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("findings: %d %s", status, body)
	}
	findingOf := map[string]string{}
	spkiOf := map[string]string{}
	for _, f := range list.Items {
		if f.SourceID != source.ID {
			continue
		}
		name, _ := f.Metadata["secret_name"].(string)
		findingOf[name] = f.ID
		spkiOf[name], _ = f.Metadata["spki_sha256"].(string)
	}
	if spkiOf["ci/web-tls"] != info.SPKISHA256 {
		t.Fatalf("the stored key's public key hash = %q, want the certificate's %q (findings %s)", spkiOf["ci/web-tls"], info.SPKISHA256, body)
	}
	if spkiOf["ci/other-tls"] == "" || spkiOf["ci/other-tls"] == info.SPKISHA256 {
		t.Fatalf("the other key's public key hash = %q", spkiOf["ci/other-tls"])
	}
	if findingOf["ci/locked"] == "" || spkiOf["ci/locked"] != "" {
		t.Fatalf("an encrypted key carries a public key hash: %q", spkiOf["ci/locked"])
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
	var g struct {
		Nodes []struct {
			ID    string            `json:"id"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
		Edges []struct {
			From, To, Type string
		} `json:"edges"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &g) != nil {
		t.Fatalf("graph: %d %s", status, body)
	}
	certNode := ""
	for _, n := range g.Nodes {
		if n.Attrs["certificate_id"] == cert.ID {
			certNode = n.ID
		}
	}
	keyOf := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == "KEY_OF" {
			keyOf[e.From] = append(keyOf[e.From], e.To)
		}
	}
	if links := keyOf["disc:"+findingOf["ci/web-tls"]]; certNode == "" || len(links) != 1 || links[0] != certNode {
		t.Fatalf("the stored key links to %v, want its certificate %q", links, certNode)
	}
	if links := keyOf["disc:"+findingOf["ci/other-tls"]]; len(links) != 0 {
		t.Fatalf("a key with no certificate in the inventory links to %v", links)
	}
}
