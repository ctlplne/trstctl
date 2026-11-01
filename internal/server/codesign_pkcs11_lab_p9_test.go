// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
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

// P9 against stock PKCS #11 signing tools: jarsigner (SunPKCS11) and
// osslsigncode (the OpenSSL pkcs11 engine) sign a JAR and a Windows executable
// through libtrstctl-pkcs11 with ECDSA and RSA keys that never leave trstctl's
// signer, and the stock verifiers accept the signatures; a token that may not
// sign gets CKR_FUNCTION_REJECTED and the tool fails. Run by
// runners/p9b-lab-proof.sh, which builds the module for Linux, a sample
// executable and the osslsigncode image; skipped otherwise.
// TRSTCTL_P9_LAB_JAVA_DEBUG passes extra flags to jarsigner, such as -debug.
func TestPKCS11ModuleSignsForJarsignerAndOsslsigncodeP9(t *testing.T) {
	labDir, jdk, ossl := os.Getenv("TRSTCTL_P9_LAB_PKCS11_DIR"), os.Getenv("TRSTCTL_P9_LAB_JDK_IMAGE"), os.Getenv("TRSTCTL_P9_LAB_OSSLSIGNCODE_IMAGE")
	if labDir == "" || jdk == "" || ossl == "" {
		t.Skip("run runners/p9b-lab-proof.sh (the module built for Linux, a JDK image and an osslsigncode image)")
	}
	ca := newP9CA(t)
	keys := map[string]crypto.DigestSigner{}
	chains := map[string][][]byte{}
	work := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), body, mode); err != nil { // #nosec G306 G703 -- public lab inputs the tool containers read (CWE-22)
			t.Fatal(err)
		}
	}
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
		keys[id] = testOperationDigestSigner{DigestSigner: key}
		chains[codeSigningKeyIdentity(servedTestTenant, id)] = [][]byte{leaf, ca.rootDER}
		write(strings.TrimPrefix(id, "release-")+"-chain.pem", append(crypto.EncodeCertificatePEM(leaf), crypto.EncodeCertificatePEM(ca.rootDER)...), 0o644)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: keys}, KeyCertificates: chains}
	})
	startServedExternalCADispatcher(t, h)
	signer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	reader := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-reader", []string{string(authz.KeysRead)})

	for _, name := range []string{"libtrstctl-pkcs11.so", "hello.exe"} {
		raw, err := os.ReadFile(filepath.Join(labDir, name)) // #nosec G304 G703 -- the lab runner's build output (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		write(name, raw, 0o755)
	}
	write("root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.rootDER}), 0o644)
	write("pkcs11.cfg", []byte("name = trstctl\nlibrary = /work/libtrstctl-pkcs11.so\nslotListIndex = 0\n"), 0o644)
	write("hello.txt", []byte("P9 lab artifact\n"), 0o644)
	controlPlane := strings.Replace(h.ts.URL, "127.0.0.1", "host.docker.internal", 1)
	run := func(image, apiToken, script string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-v", work+":/work", "-w", "/work", // #nosec G204 G702 -- the lab runner names the local tool images (CWE-78)
			"-e", "TRSTCTL_URL="+controlPlane, "-e", "TRSTCTL_PKCS11_KEYS=release-ec,release-rsa", "-e", "TOKEN="+apiToken,
			"-e", "JDEBUG="+os.Getenv("TRSTCTL_P9_LAB_JAVA_DEBUG"),
			image, "sh", "-c", script)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	before := countP9CodeSigningEvents(t, h)

	const jarsign = "jarsigner $JDEBUG -keystore NONE -storetype PKCS11 -addprovider SunPKCS11 -providerArg /work/pkcs11.cfg -storepass:env TOKEN"
	out, err := run(jdk, signer, `set -e
jar cf app.jar hello.txt
`+jarsign+` -sigalg SHA256withECDSA -signedjar app-ec.jar app.jar release-ec
`+jarsign+` -sigalg SHA256withRSA -signedjar app-rsa.jar app.jar release-rsa
keytool -importcert -noprompt -alias root -file root.pem -keystore trust.p12 -storetype PKCS12 -storepass changeit
jarsigner -verify -strict -keystore trust.p12 -storepass changeit app-ec.jar
jarsigner -verify -strict -keystore trust.p12 -storepass changeit app-rsa.jar`)
	if err != nil || strings.Count(out, "jar verified.") != 2 {
		t.Fatalf("jarsigner through the module: %v\n%s", err, out)
	}
	t.Logf("jarsigner: %s", out)

	out, err = run(ossl, signer, `set -e
for key in rsa ec; do
  osslsigncode sign -pkcs11module /work/libtrstctl-pkcs11.so -certs $key-chain.pem \
    -key "pkcs11:object=release-$key;type=private" -pass "$TOKEN" -h sha256 -n "P9 lab" -in hello.exe -out hello-$key.exe
  osslsigncode verify -CAfile root.pem -in hello-$key.exe
done`)
	if err != nil || strings.Count(out, "Signature verification: ok") != 2 {
		t.Fatalf("osslsigncode through the module: %v\n%s", err, out)
	}
	t.Logf("osslsigncode: %s", out)
	if after := countP9CodeSigningEvents(t, h); after-before < 4 {
		t.Fatalf("code-signing events %d -> %d: the four signatures did not all go through trstctl", before, after)
	}

	out, err = run(jdk, reader, jarsign+` -sigalg SHA256withECDSA -signedjar app-denied.jar app.jar release-ec`)
	if err == nil || !strings.Contains(out, "CKR_FUNCTION_REJECTED") || !strings.Contains(out, "HTTP 403") {
		t.Fatalf("a token without keys:write signed through the module: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(work, "app-denied.jar")); statErr == nil {
		t.Fatal("jarsigner wrote a signed JAR for a refused signature")
	}
}
