// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The exact-predecessor reader understands every file layout the host
// connectors write (A38): separate certificate and key files, the HAProxy
// certificate+key bundle, and the Postfix/Dovecot pair of pairs.
func TestInstalledHostPredecessorReadsEveryFileLayout(t *testing.T) {
	root := t.TempDir()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "layout issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(name string) ([]byte, []byte) {
		subject, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		defer subject.Destroy()
		der, err := crypto.SignLeafFromCSR(caDER, ca, subject.CSRDER, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := subject.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
	}
	certPEM, keyPEM := leaf("example.test")
	defer secret.Wipe(keyPEM)
	otherCert, otherKey := leaf("other.test")
	secret.Wipe(otherKey)
	write := func(name string, data []byte) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}}
	want, _ := certinfo.Inspect(certPEM)
	check := func(name string, connectorName string, target HostTargetConfig) {
		t.Helper()
		gotCert, gotKey, err := readInstalledHostPredecessor(profile, connectorName, target)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer secret.Wipe(gotKey)
		info, err := certinfo.Inspect(gotCert)
		if err != nil || info.SHA256Fingerprint != want.SHA256Fingerprint {
			t.Fatalf("%s: read certificate %+v (%v); want the installed leaf", name, info, err)
		}
		if err := crypto.VerifyCertKeyMatchPEM(gotCert, gotKey); err != nil {
			t.Fatalf("%s: read key does not match the certificate: %v", name, err)
		}
	}
	check("separate files", "nginx", HostTargetConfig{CertPath: write("cert.pem", certPEM), KeyPath: write("key.pem", keyPEM)})
	bundle := append(append([]byte(nil), certPEM...), keyPEM...)
	check("haproxy bundle", "haproxy", HostTargetConfig{CRTPath: write("site.pem", bundle), ConfigPath: write("haproxy.cfg", []byte("global\n"))})
	check("postfix pair", "postfix", HostTargetConfig{
		PostfixCertPath: write("postfix.crt", certPEM), PostfixKeyPath: write("postfix.key", keyPEM),
		DovecotCertPath: write("dovecot.crt", certPEM), DovecotKeyPath: write("dovecot.key", keyPEM),
	})

	if _, _, err := readInstalledHostPredecessor(profile, "postfix", HostTargetConfig{
		PostfixCertPath: write("postfix2.crt", certPEM), PostfixKeyPath: write("postfix2.key", keyPEM),
		DovecotCertPath: write("dovecot2.crt", otherCert), DovecotKeyPath: write("dovecot2.key", keyPEM),
	}); err == nil || !strings.Contains(err.Error(), "Dovecot") {
		t.Fatalf("a Postfix/Dovecot pair serving two different certificates was read as one predecessor: %v", err)
	}
	if _, _, err := readInstalledHostPredecessor(profile, "haproxy", HostTargetConfig{CRTPath: write("certonly.pem", certPEM)}); err == nil {
		t.Fatal("a HAProxy bundle without a private key was read as a predecessor")
	}
	if _, _, err := readInstalledHostPredecessor(profile, "java-keystore", HostTargetConfig{KeystorePath: write("store.p12", []byte("x"))}); err == nil {
		t.Fatal("a Java keystore was read without a reader")
	}
	for name, supported := range map[string]bool{"haproxy": true, "postfix": true, "nginx": true, "java-keystore": false, "iis": false, "envoy": false} {
		if SupportsPQCCertificatePredecessor(name) != supported {
			t.Errorf("SupportsPQCCertificatePredecessor(%s) = %v, want %v", name, !supported, supported)
		}
	}

	// Through the adoption path: the HAProxy layout is read and checked before
	// the listener probe, which is the first thing that fails here.
	state, err := NewHostRollbackStore(filepath.Join(root, "rollback"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(HostTargetConfig{CRTPath: filepath.Join(root, "site.pem"), ConfigPath: filepath.Join(root, "haproxy.cfg")})
	if err != nil {
		t.Fatal(err)
	}
	intent := DeployIntent{Connector: "haproxy", TargetID: "target-a", TargetConfig: config,
		VerifyAddress: "127.0.0.1:1", VerifyServerName: "example.test", PQCRunID: "run-a", PQCAssetID: "asset-a",
		PQCPredecessorFingerprint: want.SHA256Fingerprint}
	if err := adoptPQCPredecessor(context.Background(), profile, state, intent); err == nil || !strings.Contains(err.Error(), "verify served predecessor") {
		t.Fatalf("HAProxy predecessor adoption stopped before the listener probe: %v", err)
	}
}
