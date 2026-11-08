// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func selfSigned(t *testing.T, name string, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestKSPThroughItsFunctionTable drives the provider through the interface
// CNG loads, as the PKCS #11 module is tested through its function list: the
// test builds the shared library, compiles a C caller against ksp.h, and
// checks the function table, the provider and key properties under the
// two-call convention, key enumeration, the public key blobs, signature
// sizing, a short buffer, the PSS refusal, ECDSA P-256 and RSA PKCS #1 v1.5
// signatures that verify against the served keys, an unknown key, no key
// creation or private export, and a signature trstctl refuses.
func TestKSPThroughItsFunctionTable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the shared library")
	}
	cc, err := exec.LookPath("cc")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs a C compiler on Linux or macOS")
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecSPKI, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	rsaSPKI, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	certs := map[string]map[string]any{
		"release-ec": {"key_id": "release-ec", "algorithm": "ECDSA-P256", "public_key_der": ecSPKI,
			"chain_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t, "release-ec", &ecKey.PublicKey, ecKey)}))},
		"release-rsa": {"key_id": "release-rsa", "algorithm": "RSA-2048", "public_key_der": rsaSPKI,
			"chain_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t, "release-rsa", &rsaKey.PublicKey, rsaKey)}))},
	}
	var mu sync.Mutex
	var artifacts []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if bearer != "Bearer ksp-token" && bearer != "Bearer read-only-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id, ok := strings.CutPrefix(r.URL.Path, "/api/v1/code-signing/keys/"); ok {
			if c, found := certs[strings.TrimSuffix(id, "/certificate")]; found {
				_ = json.NewEncoder(w).Encode(c)
				return
			}
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/api/v1/code-signing/sign" {
			http.NotFound(w, r)
			return
		}
		if bearer == "Bearer read-only-token" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":"keys:write is required to sign"}`))
			return
		}
		var req struct {
			KeyID        string `json:"key_id"`
			Digest       []byte `json:"digest"`
			ArtifactType string `json:"artifact_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		artifacts = append(artifacts, req.KeyID+"="+req.ArtifactType)
		mu.Unlock()
		var sig []byte
		switch req.KeyID {
		case "release-ec":
			sig, _ = ecdsa.SignASN1(rand.Reader, ecKey, req.Digest)
		case "release-rsa":
			sig, _ = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, req.Digest)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"algorithm": req.KeyID, "signature": sig})
	}))
	defer api.Close()

	dir := t.TempDir()
	lib := filepath.Join(dir, "libtrstctl-ksp.so")
	build := exec.Command("go", "build", "-buildmode=c-shared", "-o", lib, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the provider: %v\n%s", err, out)
	}
	check := filepath.Join(dir, "ksp_check")
	if out, err := exec.Command(cc, "-o", check, filepath.Join("testdata", "ksp_check.c")).CombinedOutput(); err != nil { // #nosec G204 -- compiles the in-repo check program
		t.Fatalf("compile the C caller: %v\n%s", err, out)
	}
	sum := sha256.Sum256([]byte("ksp check message"))
	var raw []byte
	run := func(token string, env ...string) map[string]string {
		t.Helper()
		cmd := exec.Command(check, lib, hex.EncodeToString(sum[:]), "release-ec", "release-rsa", "nope") // #nosec G204 -- runs the program just built
		cmd.Env = append(append(os.Environ(), "TRSTCTL_URL="+api.URL, "TRSTCTL_TOKEN="+token, "TRSTCTL_TOKEN_FILE=", "TRSTCTL_CA_FILE=",
			"TRSTCTL_KSP_KEYS=release-ec,release-rsa", "TRSTCTL_APPROVAL_WAIT=0", "TRSTCTL_KSP_TRACE="), env...)
		out, err := cmd.CombinedOutput()
		raw = out
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
		return got
	}

	got := run("ksp-token")
	for k, want := range map[string]string{
		"ok": "1", "interface_rv": "0x0", "version": "1.0", "open_provider_rv": "0x0", "provider_name": "trstctl",
		"algorithms": "2", "listed": "2", "listed_0": "release-ec", "listed_1": "release-rsa",
		"release-ec_open_rv": "0x0", "release-ec_group": "ECDSA", "release-ec_length": "256", "release-ec_export_policy": "0",
		"release-ec_private_export_rv": "0x80090029", "release-ec_signature_length": "64", "release-ec_short_rv": "0x80090028",
		"release-ec_sign_rv": "0x0", "release-ec_verify_rv": "0x0",
		"release-rsa_open_rv": "0x0", "release-rsa_group": "RSA", "release-rsa_length": "2048", "release-rsa_export_policy": "0",
		"release-rsa_signature_length": "256", "release-rsa_short_rv": "0x80090028", "release-rsa_pss_rv": "0x80090029",
		"release-rsa_sign_rv": "0x0", "release-rsa_verify_rv": "0x0",
		"nope_open_rv": "0x80090016", "create_rv": "0x80090029", "free_provider_rv": "0x0",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	// The public blobs carry exactly the served keys.
	ecBlob, _ := hex.DecodeString(got["release-ec_public_blob"])
	if len(ecBlob) != 8+64 || binary.LittleEndian.Uint32(ecBlob) != 0x31534345 || binary.LittleEndian.Uint32(ecBlob[4:]) != 32 ||
		new(big.Int).SetBytes(ecBlob[8:40]).Cmp(ecKey.X) != 0 || new(big.Int).SetBytes(ecBlob[40:]).Cmp(ecKey.Y) != 0 {
		t.Errorf("ECC public blob %x", ecBlob)
	}
	rsaBlob, _ := hex.DecodeString(got["release-rsa_public_blob"])
	if len(rsaBlob) < 24 || binary.LittleEndian.Uint32(rsaBlob) != 0x31415352 || binary.LittleEndian.Uint32(rsaBlob[4:]) != 2048 {
		t.Fatalf("RSA public blob %x", rsaBlob)
	}
	exp, mod := binary.LittleEndian.Uint32(rsaBlob[8:]), binary.LittleEndian.Uint32(rsaBlob[12:])
	if new(big.Int).SetBytes(rsaBlob[24:24+exp]).Int64() != int64(rsaKey.E) || new(big.Int).SetBytes(rsaBlob[24+exp:24+exp+mod]).Cmp(rsaKey.N) != 0 {
		t.Errorf("RSA public blob does not carry the served key")
	}
	// The signatures verify against the served keys.
	ecSig, _ := hex.DecodeString(got["release-ec_signature"])
	if len(ecSig) != 64 || !ecdsa.Verify(&ecKey.PublicKey, sum[:], new(big.Int).SetBytes(ecSig[:32]), new(big.Int).SetBytes(ecSig[32:])) {
		t.Errorf("the ECDSA signature does not verify")
	}
	rsaSig, _ := hex.DecodeString(got["release-rsa_signature"])
	if rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, sum[:], rsaSig) != nil {
		t.Errorf("the RSA signature does not verify")
	}
	mu.Lock()
	recorded := slices.Clone(artifacts)
	mu.Unlock()
	if !slices.Equal(recorded, []string{"release-ec=ksp:ECDSA_P256_SHA256", "release-rsa=ksp:RSA_PKCS1_SHA256"}) {
		t.Errorf("trstctl was asked to sign %v", recorded)
	}

	if strings.Contains(string(raw), "trace ") {
		t.Errorf("the provider traced its calls without TRSTCTL_KSP_TRACE:\n%s", raw)
	}

	// A token trstctl refuses to sign with: the signature is NTE_PERM.
	refused := run("read-only-token")
	if refused["release-ec_sign_rv"] != "0x80090010" || refused["release-rsa_sign_rv"] != "0x80090010" {
		t.Errorf("a refused signature = %q / %q, want NTE_PERM", refused["release-ec_sign_rv"], refused["release-rsa_sign_rv"])
	}

	// TRSTCTL_KSP_TRACE logs each call with its names, flags and result.
	run("ksp-token", "TRSTCTL_KSP_TRACE=1")
	for _, want := range []string{
		`trstctl-ksp: trace OpenProvider("trstctl Key Storage Provider", 0x0) -> 0x0`,
		`trstctl-ksp: trace OpenKey("release-rsa", 0x0, 0x0) -> 0x0`,
		`trstctl-ksp: trace GetKeyProperty("Algorithm Group", 0x0) -> 0x0`,
		`trstctl-ksp: trace ExportKey("RSAFULLPRIVATEBLOB", 0x0) -> 0x80090029`,
		`trstctl-ksp: trace SignHash(0x8) -> 0x80090029`,
		`trstctl-ksp: trace SignHash(0x2) -> 0x0`,
		`trstctl-ksp: trace OpenKey("nope", 0x0, 0x0) -> 0x80090016`,
		`trstctl-ksp: trace CreatePersistedKey("RSA", "new", 0x0, 0x0) -> 0x80090029`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the trace has no %q:\n%s", want, raw)
		}
	}
}
