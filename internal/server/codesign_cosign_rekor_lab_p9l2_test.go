// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// P9-L2 against stock cosign: the image is signed through trstctl's API as
// in P9, the signature reaches a Rekor log through the outbox, and the bundle
// trstctl recorded is attached with the signature (cosign attach signature
// --rekor-response). Stock cosign verify then checks the log entry offline
// against the log's public key — no --insecure-ignore-tlog — and refuses the
// same image when told to trust another log key. The log is a stand-in for
// Rekor's v1 entry API whose entries are signed the way Rekor signs them.
// Run by runners/p9l2-lab-proof.sh (registry:2 with a sample image, and a
// cosign image); skipped otherwise.
func TestCosignVerifiesTheRekorBundleP9L2(t *testing.T) {
	image, cosignImage, network := os.Getenv("TRSTCTL_P9_LAB_IMAGE"), os.Getenv("TRSTCTL_P9_LAB_COSIGN_IMAGE"), os.Getenv("TRSTCTL_P9_LAB_NETWORK")
	if image == "" || cosignImage == "" || network == "" {
		t.Skip("run runners/p9l2-lab-proof.sh (registry:2 with a sample image, and a cosign image)")
	}
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
	otherLogKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherLogKey.Destroy)
	var mu sync.Mutex
	var nextIndex int64
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		var proposed rekorProposedEntry
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" || err != nil || json.Unmarshal(raw, &proposed) != nil {
			http.Error(w, "not a hashedrekord entry", http.StatusBadRequest)
			return
		}
		mu.Lock()
		index := nextIndex
		nextIndex++
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(signedRekorReceipt(t, proposed, logKey, logKey.Public(), index))
	}))
	t.Cleanup(rekor.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key": testOperationDigestSigner{DigestSigner: signingKey},
			}},
			TransparencyHandler: &rekorHandler{endpoint: rekor.URL + "/api/v1/log/entries", client: rekor.Client(), logPublicKey: logKey.Public()},
			RekorDestination:    defaultRekorDestination,
		}
	})
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite), string(authz.CertsRead),
	})
	work := t.TempDir()
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), body, 0o644); err != nil { // #nosec G306 G703 -- public payload, signature, bundle and keys the cosign container reads (CWE-22)
			t.Fatal(err)
		}
	}
	cosign := func(rekorKey string, args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		full := []string{"run", "--rm", "--network", network, "-v", work + ":/work:ro", "-w", "/work"}
		if rekorKey != "" {
			full = append(full, "-e", "SIGSTORE_REKOR_PUBLIC_KEY=/work/"+rekorKey)
		}
		full = append(append(full, cosignImage), args...)
		cmd := exec.CommandContext(ctx, "docker", full...) // #nosec G204 G702 -- the lab runner names the network and the local cosign image (CWE-78)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return append(stdout.Bytes(), stderr.Bytes()...), err
	}
	registry := []string{"--allow-insecure-registry", "--allow-http-registry"}
	payload, err := cosign("", append(append([]string{"generate"}, registry...), image)...)
	if err != nil || !bytes.Contains(payload, []byte(`"docker-manifest-digest"`)) {
		t.Fatalf("cosign generate: %v\n%s", err, payload)
	}
	write("payload.json", payload)
	const signRequest = "p9l2-cosign-lab"
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, signRequest, map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image", "digest": crypto.SHA256Sum(payload),
	})
	var signed struct {
		OperationID  string `json:"operation_id"`
		Signature    []byte `json:"signature"`
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &signed) != nil || len(signed.Signature) == 0 || signed.OperationID == "" {
		t.Fatalf("trstctl sign: HTTP %d %s", status, body)
	}
	var bundle struct {
		CosignBundle string `json:"cosign_bundle"`
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/code-signing/identities/"+signed.OperationID+"/rekor-bundle", token, "", nil)
		if status == http.StatusOK && json.Unmarshal(body, &bundle) == nil && bundle.CosignBundle != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rekor-bundle: HTTP %d %s", status, body)
		}
		time.Sleep(time.Second)
	}
	write("payload.sig", []byte(base64.StdEncoding.EncodeToString(signed.Signature)))
	write("trstctl.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signed.PublicKeyDER}))
	write("rekor-bundle.json", []byte(bundle.CosignBundle))
	write("rekor.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: logKey.Public().DER}))
	write("other-rekor.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherLogKey.Public().DER}))

	if out, err := cosign("", append(append([]string{"attach", "signature", "--payload", "payload.json", "--signature", "payload.sig",
		"--rekor-response", "rekor-bundle.json"}, registry...), image)...); err != nil {
		t.Fatalf("cosign attach signature with the bundle: %v\n%s", err, out)
	}
	out, err := cosign("rekor.pub", append(append([]string{"verify", "--key", "trstctl.pub", "--offline=true"}, registry...), image)...)
	if err != nil || !bytes.Contains(out, []byte(`"docker-manifest-digest"`)) || !bytes.Contains(out, []byte("transparency log")) {
		attached, _ := cosign("", append(append([]string{"download", "signature"}, registry...), image)...)
		t.Fatalf("stock cosign verify with the transparency log failed: %v\n%s\nattached: %s\nbundle file: %s", err, out, attached, bundle.CosignBundle)
	}
	t.Logf("stock cosign verify (tlog checked offline): %s", bytes.TrimSpace(out))
	if out, err := cosign("other-rekor.pub", append(append([]string{"verify", "--key", "trstctl.pub", "--offline=true"}, registry...), image)...); err == nil {
		t.Fatalf("cosign verified the bundle under another log key:\n%s", out)
	} else {
		t.Logf("under another log key, cosign refuses: %s", bytes.TrimSpace(out))
	}
}
