// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// P9 against stock cosign: an image in a local registry is signed with a key
// that never leaves trstctl's signer — cosign writes the payload, trstctl's
// code-signing API signs its digest, cosign attaches the signature — and stock
// `cosign verify` passes with the key's public key and fails with another
// key's. Run by runners/p9-lab-proof.sh, which starts registry:2 on a lab
// network and pushes a sample image; skipped otherwise.
func TestCosignVerifiesATrstctlSignedImageP9(t *testing.T) {
	image, cosignImage, network := os.Getenv("TRSTCTL_P9_LAB_IMAGE"), os.Getenv("TRSTCTL_P9_LAB_COSIGN_IMAGE"), os.Getenv("TRSTCTL_P9_LAB_NETWORK")
	if image == "" || cosignImage == "" || network == "" {
		t.Skip("run runners/p9-lab-proof.sh (registry:2 with a sample image, and a cosign image)")
	}
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
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": testOperationDigestSigner{DigestSigner: signingKey},
		}}}
	})
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})

	work := t.TempDir()
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), body, 0o644); err != nil { // #nosec G306 G703 -- a public payload, signature and keys the cosign container reads (CWE-22)
			t.Fatal(err)
		}
	}
	cosign := func(args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		full := append([]string{"run", "--rm", "--network", network, "-v", work + ":/work:ro", "-w", "/work", cosignImage}, args...)
		cmd := exec.CommandContext(ctx, "docker", full...) // #nosec G204 G702 -- the lab runner names the network and the local cosign image (CWE-78)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err != nil {
			return append(stdout.Bytes(), stderr.Bytes()...), err
		}
		return stdout.Bytes(), nil
	}
	registry := []string{"--allow-insecure-registry", "--allow-http-registry"}

	payload, err := cosign(append(append([]string{"generate"}, registry...), image)...)
	if err != nil || !bytes.Contains(payload, []byte(`"docker-manifest-digest"`)) {
		t.Fatalf("cosign generate: %v\n%s", err, payload)
	}
	write("payload.json", payload)
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, "p9-cosign-lab", map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image", "digest": crypto.SHA256Sum(payload),
	})
	var signed struct {
		Signature    []byte `json:"signature"`
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &signed) != nil || len(signed.Signature) == 0 {
		t.Fatalf("trstctl sign: HTTP %d %s", status, body)
	}
	if !bytes.Equal(signed.PublicKeyDER, signingKey.Public().DER) {
		t.Fatal("the signing response names another key")
	}
	write("payload.sig", []byte(base64.StdEncoding.EncodeToString(signed.Signature)))
	write("trstctl.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signed.PublicKeyDER}))
	write("other.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherKey.Public().DER}))

	if out, err := cosign(append(append([]string{"attach", "signature", "--payload", "payload.json", "--signature", "payload.sig"}, registry...), image)...); err != nil {
		t.Fatalf("cosign attach signature: %v\n%s", err, out)
	}
	out, err := cosign(append(append([]string{"verify", "--key", "trstctl.pub", "--insecure-ignore-tlog=true"}, registry...), image)...)
	if err != nil || !bytes.Contains(out, []byte(`"docker-manifest-digest"`)) {
		t.Fatalf("stock cosign verify failed for a trstctl-signed image: %v\n%s", err, out)
	}
	digest := image[strings.LastIndex(image, "@")+1:]
	if !bytes.Contains(out, []byte(digest)) {
		t.Fatalf("cosign verified another manifest than %s:\n%s", digest, out)
	}
	t.Logf("stock cosign verify: %s", bytes.TrimSpace(out))
	if out, err := cosign(append(append([]string{"verify", "--key", "other.pub", "--insecure-ignore-tlog=true"}, registry...), image)...); err == nil {
		t.Fatalf("cosign verified the image with another key:\n%s", out)
	}
}
