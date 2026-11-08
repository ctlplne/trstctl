// SPDX-License-Identifier: MPL-2.0

//go:build windows

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/clients/signing/internal/kspinfo"
)

// TestSigntoolSignsThroughTheKSPP9 is P9's signtool run, the windows-latest
// CI job: it installs the trstctl-ksp.dll that job cross-compiled, serves a
// stand-in for trstctl's code-signing API with an ECDSA P-256 key and an RSA
// 3072 key whose certificates chain to a test root, and has the Windows SDK's
// signtool sign two executables through CNG, naming the provider (/csp) and
// the trstctl key (/kc). signtool verify /pa accepts both signatures under the
// trusted root; a token that may not sign leaves its executable unsigned with
// NTE_PERM; uninstall removes the provider. It changes this machine's CNG
// configuration and root store, so it runs only with TRSTCTL_P9_SIGNTOOL=1.
func TestSigntoolSignsThroughTheKSPP9(t *testing.T) {
	if os.Getenv("TRSTCTL_P9_SIGNTOOL") != "1" {
		t.Skip("set TRSTCTL_P9_SIGNTOOL=1 and TRSTCTL_KSP_DLL on a Windows host this test may reconfigure (the windows-latest CI job)")
	}
	dll := os.Getenv("TRSTCTL_KSP_DLL")
	if dll == "" {
		t.Fatal("TRSTCTL_KSP_DLL names the cross-compiled trstctl-ksp.dll")
	}
	signtool := findSigntool(t)
	work := t.TempDir()
	serials := int64(100)
	certificate := func(name string, pub any, issuer *x509.Certificate, issuerKey crypto.Signer, ca bool) *x509.Certificate {
		t.Helper()
		serials++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano() + serials), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		if ca {
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		} else {
			tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}
		if issuer == nil {
			issuer = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := certificate("trstctl P9 signtool test root", &rootKey.PublicKey, nil, rootKey, true)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		cert *x509.Certificate
		sign func(digest []byte) ([]byte, error)
	}
	keys := map[string]key{
		"release-ec": {certificate("release-ec", &ecKey.PublicKey, root, rootKey, false),
			func(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, ecKey, d) }},
		"release-rsa": {certificate("release-rsa", &rsaKey.PublicKey, root, rootKey, false),
			func(d []byte) ([]byte, error) { return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, d) }},
	}
	var mu sync.Mutex
	var signed []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if bearer != "Bearer ksp-token" && bearer != "Bearer read-only-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if id, ok := strings.CutPrefix(r.URL.Path, "/api/v1/code-signing/keys/"); ok {
			k, found := keys[strings.TrimSuffix(id, "/certificate")]
			if !found {
				http.NotFound(w, r)
				return
			}
			chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
			_ = json.NewEncoder(w).Encode(map[string]any{"key_id": strings.TrimSuffix(id, "/certificate"),
				"public_key_der": k.cert.RawSubjectPublicKeyInfo, "chain_pem": string(chain)})
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		k, found := keys[req.KeyID]
		if !found {
			http.NotFound(w, r)
			return
		}
		sig, err := k.sign(req.Digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		signed = append(signed, req.KeyID+"="+req.ArtifactType)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"signature": sig})
	}))
	defer api.Close()

	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	command := func(env []string, name string, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(name, args...) // #nosec G204 -- the Windows SDK's signtool and certutil with test inputs
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Trust the test root, as an organization trusts its code-signing root.
	rootFile := write("root.cer", root.Raw)
	if out, err := command(nil, "certutil", "-addstore", "-f", "Root", rootFile); err != nil {
		t.Fatalf("trust the test root: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = command(nil, "certutil", "-delstore", "Root", root.SerialNumber.Text(16)) })

	var out bytes.Buffer
	if code := run([]string{"install", dll}, &out, &out, platform{}); code != 0 {
		t.Fatalf("install = %d\n%s", code, out.String())
	}
	t.Cleanup(func() { run([]string{"uninstall"}, io.Discard, io.Discard, platform{}) })
	if code := run([]string{"status"}, &out, &out, platform{}); code != 0 {
		t.Fatalf("status after install = %d\n%s", code, out.String())
	}
	t.Logf("%s", out.String())

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := os.ReadFile(self) // #nosec G304 -- this test binary, an unsigned executable to sign
	if err != nil {
		t.Fatal(err)
	}
	env := func(token string) []string {
		return []string{"TRSTCTL_URL=" + api.URL, "TRSTCTL_TOKEN=" + token, "TRSTCTL_TOKEN_FILE=", "TRSTCTL_CA_FILE=",
			"TRSTCTL_KSP_KEYS=release-ec,release-rsa", "TRSTCTL_APPROVAL_WAIT=0", "TRSTCTL_KSP_TRACE=1"}
	}
	for _, id := range []string{"release-ec", "release-rsa"} {
		target := write(id+".exe", unsigned)
		certFile := write(id+".cer", keys[id].cert.Raw)
		got, err := command(env("ksp-token"), signtool, "sign", "/v", "/fd", "sha256", "/f", certFile, "/csp", kspinfo.ProviderName, "/kc", id, target)
		t.Logf("signtool sign with %s:\n%s", id, got)
		if err != nil || !strings.Contains(got, "Successfully signed") {
			t.Fatalf("signtool sign through the provider with %s: %v", id, err)
		}
		got, err = command(nil, signtool, "verify", "/pa", "/v", target)
		t.Logf("signtool verify %s:\n%s", id, got)
		if err != nil || !strings.Contains(got, "Successfully verified") || !strings.Contains(got, "Issued to: "+id) {
			t.Fatalf("signtool verify /pa of the %s signature: %v", id, err)
		}
	}
	mu.Lock()
	recorded := slices.Clone(signed)
	mu.Unlock()
	if !slices.Contains(recorded, "release-ec=ksp:ECDSA_P256_SHA256") || !slices.Contains(recorded, "release-rsa=ksp:RSA_PKCS1_SHA256") {
		t.Fatalf("trstctl signed %v, want both keys through the provider", recorded)
	}

	// A token trstctl refuses to sign with: signtool fails with NTE_PERM and
	// the executable stays unsigned.
	refused := write("refused.exe", unsigned)
	got, err := command(env("read-only-token"), signtool, "sign", "/v", "/fd", "sha256", "/f", filepath.Join(work, "release-rsa.cer"),
		"/csp", kspinfo.ProviderName, "/kc", "release-rsa", refused)
	t.Logf("signtool sign with a token that may not sign:\n%s", got)
	if err == nil || !strings.Contains(strings.ToLower(got), "0x80090010") {
		t.Fatalf("a refused signature: err %v, want signtool to fail with NTE_PERM (0x80090010)", err)
	}
	if got, err := command(nil, signtool, "verify", "/pa", refused); err == nil {
		t.Fatalf("the refused executable verifies:\n%s", got)
	}

	out.Reset()
	if code := run([]string{"uninstall"}, &out, &out, platform{}); code != 0 {
		t.Fatalf("uninstall = %d\n%s", code, out.String())
	}
	if code := run([]string{"status"}, &out, &out, platform{}); code != 1 {
		t.Fatalf("status after uninstall = %d, want 1\n%s", code, out.String())
	}
	t.Log("P9_SIGNTOOL_OK: signtool signed through trstctl-ksp with ECDSA P-256 and RSA 3072 keys, verify /pa accepted both, a token without signing rights got NTE_PERM, and the provider was removed")
}

// findSigntool is TRSTCTL_SIGNTOOL or the newest x64 signtool in the Windows
// SDK.
func findSigntool(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("TRSTCTL_SIGNTOOL"); path != "" {
		return path
	}
	found, _ := filepath.Glob(`C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe`)
	if len(found) == 0 {
		t.Fatal("no signtool.exe in the Windows SDK; set TRSTCTL_SIGNTOOL")
	}
	sort.Strings(found)
	return found[len(found)-1]
}
