// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The module through its C function list, as a PKCS #11 tool loads it: the
// test builds the shared library, compiles a C caller against ck.h, and checks
// the two-call attribute read, the sensitive value, a search, a length query,
// a short buffer and a signature that verifies against the served key.
func TestModuleThroughItsFunctionList(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the shared library")
	}
	cc, err := exec.LookPath("cc")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs a C compiler on Linux or macOS")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "release-ec"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer abi-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/code-signing/keys/release-ec/certificate":
			_ = json.NewEncoder(w).Encode(map[string]any{"key_id": "release-ec", "algorithm": "ECDSA-P256", "public_key_der": spki,
				"chain_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))})
		case "/api/v1/code-signing/sign":
			var req struct {
				Digest       []byte `json:"digest"`
				ArtifactType string `json:"artifact_type"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.ArtifactType != "pkcs11:CKM_ECDSA_SHA256" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sig, _ := ecdsa.SignASN1(rand.Reader, key, req.Digest)
			_ = json.NewEncoder(w).Encode(map[string]any{"algorithm": "ECDSA-P256", "signature": sig})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	dir := t.TempDir()
	lib := filepath.Join(dir, "libtrstctl-pkcs11.so")
	build := exec.Command("go", "build", "-buildmode=c-shared", "-o", lib, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the module: %v\n%s", err, out)
	}
	check := filepath.Join(dir, "abi_check")
	if out, err := exec.Command(cc, "-o", check, filepath.Join("testdata", "abi_check.c")).CombinedOutput(); err != nil { // #nosec G204 -- compiles the in-repo check program
		t.Fatalf("compile the C caller: %v\n%s", err, out)
	}
	run := exec.Command(check, lib, "abi-token") // #nosec G204 -- runs the program just built
	run.Env = append(os.Environ(), "TRSTCTL_URL="+api.URL, "TRSTCTL_PKCS11_KEYS=release-ec", "TRSTCTL_CA_FILE=")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("the C caller failed: %v\n%s", err, out)
	}
	got := map[string]string{}
	for sc := bufio.NewScanner(bytes.NewReader(out)); sc.Scan(); {
		for _, field := range strings.Fields(sc.Text()) {
			if k, v, ok := strings.Cut(field, "="); ok {
				got[k] = v
			}
		}
	}
	for k, want := range map[string]string{
		"ok": "1", "private_keys": "1", "label": "release-ec", "label_len": "10", "id_len": "20", "params_len": "10",
		"extractable": "0", "value_rv": "0x11", "value_len_unavailable": "1", "short_rv": "0x150",
	} {
		if got[k] != want {
			t.Fatalf("%s = %q, want %q\n%s", k, got[k], want, out)
		}
	}
	sig, err := hex.DecodeString(got["signature"])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature %q", got["signature"])
	}
	sum := sha256.Sum256([]byte("abi check message"))
	if !ecdsa.Verify(&key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the module's signature does not verify")
	}
}
