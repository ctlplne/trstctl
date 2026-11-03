// SPDX-License-Identifier: BUSL-1.1

package pfx_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestJavaAliasSurvivesAuthenticatedPKCS12RoundTrip(t *testing.T) {
	cert, key := credential(t)
	defer secret.Wipe(key)
	for _, alias := range []string{"payments", "payments-é", "付款"} {
		t.Run(alias, func(t *testing.T) {
			password := []byte("qa-only-é-password")
			blob, err := pfx.EncodeDeterministicAliasBytes(key, cert, password, alias)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(blob)
			// The independent SSLMate decoder verifies the MAC and decrypts
			// both safes. Stock keytool separately proves selection by alias.
			gotKey, gotChain, err := pfx.Decode(blob, string(password))
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(gotKey)
			if !bytes.Equal(derOf(t, gotKey), derOf(t, key)) || !bytes.Equal(gotChain, cert) {
				t.Fatal("alias encoding changed the private key or certificate chain")
			}
			if _, _, err := pfx.Decode(blob, "wrong"); err == nil {
				t.Fatal("wrong password accepted")
			}
			again, err := pfx.EncodeDeterministicAliasBytes(key, cert, password, alias)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(again)
			if !bytes.Equal(blob, again) {
				t.Fatal("identical deployment changed the keystore")
			}
		})
	}
}

func TestJavaAliasRejectsUnrepresentableNames(t *testing.T) {
	cert, key := credential(t)
	defer secret.Wipe(key)
	for _, alias := range []string{"a\x00b", "\xff", "payments-🔐", strings.Repeat("x", 1025)} {
		blob, err := pfx.EncodeDeterministicAliasBytes(key, cert, []byte("qa-password"), alias)
		if err == nil || blob != nil {
			t.Fatal("unrepresentable alias returned a keystore")
		}
	}
	old, err := pfx.EncodeDeterministicBytes(key, cert, []byte("qa-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(old)
	unnamed, err := pfx.EncodeDeterministicAliasBytes(key, cert, []byte("qa-password"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(unnamed)
	if !bytes.Equal(old, unnamed) {
		t.Fatal("empty alias changed legacy output")
	}
}

// This test uses the JDK's actual key-entry importer, independent of the Go
// encoder/decoder. Set TRSTCTL_REQUIRE_KEYTOOL=1 in an interoperability run so a
// missing JDK is a failure; ordinary Go-only environments report an explicit skip.
func TestJavaAliasStockKeytoolImportsPrivateKeyAndChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keytool, err := exec.LookPath("keytool")
	if err == nil {
		err = exec.CommandContext(ctx, keytool, "-help").Run()
	} // #nosec G204 -- runs the locally installed JDK tool with fixed arguments (CWE-78).
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_KEYTOOL") == "1" {
			t.Fatalf("stock keytool required: %v", err)
		}
		t.Skip("stock Java keytool unavailable")
	}
	cert, key := credential(t)
	defer secret.Wipe(key)
	for _, alias := range []string{"payments", "付款-é"} {
		t.Run(alias, func(t *testing.T) {
			// SunJCE's PBES2 password conversion requires ASCII, even though
			// the PKCS#12 metadata and the friendlyName support BMP characters.
			password := []byte("qa-only-password")
			blob, err := pfx.EncodeDeterministicAliasBytes(key, cert, password, alias)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(blob)
			// Not t.TempDir: its path carries this subtest's Unicode name,
			// which keytool on Windows cannot open (owner decision
			// 2026-11-02, item 2g e). The alias inside stays Unicode.
			dir, err := os.MkdirTemp("", "pfx-keytool-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			source, dest, pass := filepath.Join(dir, "source.p12"), filepath.Join(dir, "imported.p12"), filepath.Join(dir, "password")
			if err := os.WriteFile(source, blob, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pass, password, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-importkeystore", "-noprompt", "-srckeystore", source, "-srcstoretype", "PKCS12", "-srcstorepass:file", pass,
				"-destkeystore", dest, "-deststoretype", "PKCS12", "-deststorepass:file", pass}
			// keytool on Windows receives its arguments in the ANSI code page,
			// which has no 付款, so there no alias is named: keytool imports the
			// entry under the alias it reads from the file, which the check
			// below finds in the result (owner decision 2026-11-02, item 2g e).
			byFile := runtime.GOOS == "windows" && !isASCII(alias)
			if !byFile {
				args = append(args, "-srcalias", alias, "-destalias", "restored")
			}
			if output, err := exec.CommandContext(ctx, keytool, args...).CombinedOutput(); err != nil { // #nosec G204 -- stock JDK import uses disposable test paths and a password file, never a shell or secret argv (CWE-78).
				t.Fatalf("stock keytool import failed: %v: %s", err, output)
			}
			imported, err := os.ReadFile(dest) // #nosec G304 -- reads the stock JDK output inside this test's private temporary directory (CWE-22).
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(imported)
			if byFile && !bytes.Contains(imported, bmpString(alias)) {
				t.Fatal("keytool did not keep the entry's Unicode alias")
			}
			gotKey, gotChain, err := pfx.Decode(imported, string(password))
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(gotKey)
			if !bytes.Equal(derOf(t, gotKey), derOf(t, key)) || !bytes.Equal(gotChain, cert) {
				t.Fatal("JDK did not import the exact private key and full chain")
			}
		})
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// bmpString is s as a PKCS#12 friendlyName carries it: UTF-16 big-endian. A
// keystore keytool writes keeps its key bags' attributes in the clear.
func bmpString(s string) []byte {
	var out []byte
	for _, unit := range utf16.Encode([]rune(s)) {
		out = binary.BigEndian.AppendUint16(out, unit)
	}
	return out
}
