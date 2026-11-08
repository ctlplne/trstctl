// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// TestKSPSignsThroughTheServedCodeSigningAPIP9 is P9's Windows signing
// adapter against the served code-signing API. The CNG key storage provider
// in clients/signing/ksp, built for this host from the source make
// signing-ksp-windows cross-compiles, is driven through the function table it
// exports by the C caller in its testdata, as CNG drives it. ECDSA P-256 and
// RSA 3072 keys that never leave trstctl's signer sign a SHA-256 hash: the
// public key blobs carry the served keys, the signatures verify against the
// keys' certificates, each signature completes one code-signing operation,
// and a token without keys:write gets NTE_PERM and completes none.
func TestKSPSignsThroughTheServedCodeSigningAPIP9(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("builds the provider for this host with cgo: needs a C compiler on Linux or macOS")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the provider")
	}
	ca := newP9CA(t)
	keys := map[string]crypto.DigestSigner{}
	chains := map[string][][]byte{}
	leaves := map[string][]byte{}
	for id, algorithm := range map[string]crypto.Algorithm{"release-ec": crypto.ECDSAP256, "release-rsa": crypto.RSA3072} {
		key, err := crypto.GenerateLockedKey(algorithm)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: id, RequestedEKUs: []string{"codeSigning"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf := ca.issue(t, csr, "codeSigning")
		leaves[id] = leaf
		keys[id] = testOperationDigestSigner{DigestSigner: key}
		chains[codeSigningKeyIdentity(servedTestTenant, id)] = [][]byte{leaf, ca.rootDER}
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: keys}, KeyCertificates: chains}
	})
	startServedExternalCADispatcher(t, h)
	signer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	reader := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-reader", []string{string(authz.KeysRead)})

	dir := t.TempDir()
	lib, check := filepath.Join(dir, "libtrstctl-ksp.so"), filepath.Join(dir, "ksp_check")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, goBin, "build", "-buildmode=c-shared", "-o", lib, "./ksp") // #nosec G204 -- test builds the in-repo provider (CWE-78)
	build.Dir = filepath.Join("..", "..", "clients", "signing")
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the provider: %v\n%s", err, out)
	}
	caller := filepath.Join("..", "..", "clients", "signing", "ksp", "testdata", "ksp_check.c")
	if out, err := exec.CommandContext(ctx, cc, "-o", check, caller).CombinedOutput(); err != nil { // #nosec G204 -- test compiles the in-repo C caller (CWE-78)
		t.Fatalf("compile the C caller: %v\n%s", err, out)
	}
	digest := crypto.SHA256Sum([]byte("P9 Windows signing adapter, served"))
	run := func(token string) (map[string]string, string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, check, lib, hex.EncodeToString(digest), "release-ec", "release-rsa", "nope") // #nosec G204 -- test runs the caller it just built (CWE-78)
		cmd.Env = append(os.Environ(), "TRSTCTL_URL="+h.ts.URL, "TRSTCTL_TOKEN="+token, "TRSTCTL_TOKEN_FILE=", "TRSTCTL_CA_FILE=",
			"TRSTCTL_KSP_KEYS=release-ec,release-rsa", "TRSTCTL_APPROVAL_WAIT=0", "TRSTCTL_KSP_TRACE=")
		out, err := cmd.CombinedOutput()
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
		return got, string(out)
	}
	completed := func() int {
		t.Helper()
		n := 0
		if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
			if event.TenantID == h.tenant && event.Type == "codesign.completed" {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	before := completed()
	got, out := run(signer)
	for k, want := range map[string]string{
		"ok": "1", "open_provider_rv": "0x0", "listed": "2", "nope_open_rv": "0x80090016", "create_rv": "0x80090029",
		"release-ec_group": "ECDSA", "release-ec_length": "256", "release-ec_signature_length": "64",
		"release-ec_private_export_rv": "0x80090029", "release-ec_sign_rv": "0x0", "release-ec_verify_rv": "0x0",
		"release-rsa_group": "RSA", "release-rsa_length": "3072", "release-rsa_signature_length": "384",
		"release-rsa_pss_rv": "0x80090029", "release-rsa_sign_rv": "0x0", "release-rsa_verify_rv": "0x0",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q\n%s", k, got[k], want, out)
		}
	}
	// The public key blobs carry the served keys, and the signatures verify
	// against the keys' certificates.
	ecSPKI, err := crypto.PublicKeyDERFromCert(leaves["release-ec"])
	if err != nil {
		t.Fatal(err)
	}
	var spki struct {
		Algorithm asn1.RawValue
		Point     asn1.BitString
	}
	if _, err := asn1.Unmarshal(ecSPKI, &spki); err != nil || len(spki.Point.Bytes) != 65 {
		t.Fatalf("release-ec's certificate key: %v", err)
	}
	ecBlob, _ := hex.DecodeString(got["release-ec_public_blob"])
	if len(ecBlob) != 72 || binary.LittleEndian.Uint32(ecBlob) != 0x31534345 || !bytes.Equal(ecBlob[8:], spki.Point.Bytes[1:]) {
		t.Errorf("the ECC public blob %x is not the served key", ecBlob)
	}
	ecSig, _ := hex.DecodeString(got["release-ec_signature"])
	if len(ecSig) != 64 {
		t.Fatalf("ECDSA signature %x is not r||s", ecSig)
	}
	ecDER, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ecSig[:32]), new(big.Int).SetBytes(ecSig[32:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.ECDSAP256, DER: ecSPKI}, digest, ecDER, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Errorf("the ECDSA signature does not verify against release-ec's certificate: %v", err)
	}
	rsaSPKI, err := crypto.PublicKeyDERFromCert(leaves["release-rsa"])
	if err != nil {
		t.Fatal(err)
	}
	rsaBlob, _ := hex.DecodeString(got["release-rsa_public_blob"])
	if len(rsaBlob) < 24 || binary.LittleEndian.Uint32(rsaBlob) != 0x31415352 {
		t.Fatalf("the RSA public blob %x is not a BCRYPT_RSAPUBLIC_BLOB", rsaBlob)
	}
	exponentLen, modulusLen := int(binary.LittleEndian.Uint32(rsaBlob[8:])), int(binary.LittleEndian.Uint32(rsaBlob[12:]))
	if len(rsaBlob) != 24+exponentLen+modulusLen {
		t.Fatalf("the RSA public blob is %d bytes for a %d-byte exponent and a %d-byte modulus", len(rsaBlob), exponentLen, modulusLen)
	}
	blobDER, err := crypto.RSAPublicKeyDERFromComponents(rsaBlob[24+exponentLen:], rsaBlob[24:24+exponentLen])
	if err != nil || !bytes.Equal(blobDER, rsaSPKI) {
		t.Errorf("the RSA public blob is not the served key (%v)", err)
	}
	rsaSig, _ := hex.DecodeString(got["release-rsa_signature"])
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.RSA3072, DER: rsaSPKI}, digest, rsaSig,
		crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err != nil {
		t.Errorf("the RSA signature does not verify against release-rsa's certificate: %v", err)
	}
	after := completed()
	if after-before != 2 {
		t.Fatalf("completed code-signing operations %d -> %d, want one per signature", before, after)
	}

	refused, out := run(reader)
	if refused["release-ec_sign_rv"] != "0x80090010" || refused["release-rsa_sign_rv"] != "0x80090010" || !strings.Contains(out, "HTTP 403") {
		t.Fatalf("a token without keys:write: sign = %q / %q, want NTE_PERM after trstctl's 403\n%s",
			refused["release-ec_sign_rv"], refused["release-rsa_sign_rv"], out)
	}
	if completed() != after {
		t.Fatal("a refused signature completed a code-signing operation")
	}
}
