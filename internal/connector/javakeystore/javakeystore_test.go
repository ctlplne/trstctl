package javakeystore_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/pluginhost"
)

// A real ECDSA P-256 key (PKCS#8) and self-signed certificate — the keystore
// encoders parse them, so opaque bytes will not do.
const (
	keyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguSjwYXld9WA6+GXM
uiBvryiQ90RZx9HA7kPBwGKEmiihRANCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiF
tC/tbv9HKUb/KCNxLa7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0G
-----END PRIVATE KEY-----
`
	certPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUcx0QtLdtk6up3COWRwqCyBvODsYwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNa2V5c3RvcmUudGVzdDAeFw0yNjA1MzAxNTQwMjdaFw0zNjA1
MjcxNTQwMjdaMBgxFjAUBgNVBAMMDWtleXN0b3JlLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiFtC/tbv9HKUb/KCNx
La7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0Go1MwUTAdBgNVHQ4EFgQUxCW/
Ky+OGKi2+qs6KAJc8H3T6cgwHwYDVR0jBBgwFoAUxCW/Ky+OGKi2+qs6KAJc8H3T
6cgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAsEewyxjXXOdT
Z574YJ/lLHBNf0zuGD0O54dwWStiBj0CIDtTvKZum/bUwvzvfEkaP9M9LonMANo4
4fmuDJ38Fgsy
-----END CERTIFICATE-----
`
	password = "changeit"
	alias    = "server"
)

func deploy(t *testing.T, c *javakeystore.Connector) *connector.MemoryOps {
	t.Helper()
	ops := connector.NewMemoryOps()
	dep := connector.NewDeployment("app", []byte(certPEM), []byte(keyPEM))
	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return ops
}

// Deploy writes a PKCS#12 keystore that decodes back to the renewed key and
// certificate under the configured password.
func TestDeployWritesPKCS12Keystore(t *testing.T) {
	const ksPath = "/etc/app/keystore.p12"
	ops := deploy(t, javakeystore.New(ksPath, password, alias))

	blob, ok := ops.File(ksPath)
	if !ok {
		t.Fatalf("no keystore written at %s", ksPath)
	}
	gotKey, gotCert, err := pfx.Decode(blob, password)
	if err != nil {
		t.Fatalf("decode PKCS#12: %v", err)
	}
	if !bytes.Equal(der(t, gotCert), der(t, []byte(certPEM))) || !bytes.Equal(der(t, gotKey), der(t, []byte(keyPEM))) {
		t.Error("PKCS#12 keystore does not contain the renewed credential")
	}
}

// Deploy writes a JKS keystore (selected by the .jks extension) that decodes
// back to the renewed credential under the configured alias and password.
func TestDeployWritesJKSKeystore(t *testing.T) {
	const ksPath = "/etc/app/keystore.jks"
	ops := deploy(t, javakeystore.New(ksPath, password, alias))

	blob, ok := ops.File(ksPath)
	if !ok {
		t.Fatalf("no keystore written at %s", ksPath)
	}
	if len(blob) < 4 || blob[0] != 0xFE || blob[1] != 0xED {
		t.Fatalf("not a JKS file (bad magic)")
	}
	gotKey, gotCert, err := jks.Decode(blob, password, alias)
	if err != nil {
		t.Fatalf("decode JKS: %v", err)
	}
	if !bytes.Equal(der(t, gotCert), der(t, []byte(certPEM))) || !bytes.Equal(der(t, gotKey), der(t, []byte(keyPEM))) {
		t.Error("JKS keystore does not contain the renewed credential")
	}
}

// Format follows the file extension, and WithFormat overrides it.
func TestFormatFromExtensionAndOverride(t *testing.T) {
	// .bin extension defaults to PKCS#12...
	binOps := deploy(t, javakeystore.New("/etc/app/store.bin", password, alias))
	blob, _ := binOps.File("/etc/app/store.bin")
	if _, _, err := pfx.Decode(blob, password); err != nil {
		t.Errorf("unknown extension should default to PKCS#12: %v", err)
	}
	// ...but WithFormat(JKS) overrides it.
	ovOps := deploy(t, javakeystore.New("/etc/app/store.bin", password, alias, javakeystore.WithFormat(javakeystore.FormatJKS)))
	blob, _ = ovOps.File("/etc/app/store.bin")
	if _, _, err := jks.Decode(blob, password, alias); err != nil {
		t.Errorf("WithFormat(JKS) should produce a JKS keystore: %v", err)
	}
}

// Redeploying the same credential writes byte-identical bytes — the deployment
// is idempotent.
func TestDeployIsDeterministic(t *testing.T) {
	for _, ksPath := range []string{"/etc/app/k.p12", "/etc/app/k.jks"} {
		c := javakeystore.New(ksPath, password, alias)
		a, _ := deploy(t, c).File(ksPath)
		b, _ := deploy(t, c).File(ksPath)
		if !bytes.Equal(a, b) {
			t.Errorf("%s: redeploy produced different bytes (not idempotent)", ksPath)
		}
	}
}

// Least privilege: fs.write to the keystore directory only — no network, no
// exec, and not other directories.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := javakeystore.New("/etc/app/keystore.p12", password, alias)
	grant := c.Capabilities()
	if grant.Has(pluginhost.CapNetDial) {
		t.Error("keystore connector must not request net.dial")
	}
	if grant.Has(connector.CapExec) {
		t.Error("keystore connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapFSWrite) {
		t.Fatal("keystore connector must request fs.write")
	}
	if !grant.Allows(pluginhost.CapFSWrite, "/etc/app/keystore.p12") {
		t.Error("fs.write must allow the keystore path")
	}
	if grant.Allows(pluginhost.CapFSWrite, "/etc/other/secrets.p12") {
		t.Error("fs.write must be scoped to the keystore directory, not anywhere")
	}
}

// The connector satisfies the shared connector conformance suite.
func TestJavaKeystorePassesConformance(t *testing.T) {
	c := javakeystore.New("/etc/app/keystore.p12", password, alias)
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}

func der(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}
