// SPDX-License-Identifier: BUSL-1.1

package hostsource_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/hostsource"
)

func TestScanFlagsWeakProtocolAndCipher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nginx.conf")
	conf := "# tls config\n" +
		"ssl_protocols TLSv1 TLSv1.2;\n" +
		"ssl_ciphers DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256;\n"
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}

	findings, err := hostsource.New(path).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p := cbom.DefaultPolicy()
	var weakProto, okProto, weakCipher, okCipher bool
	for _, f := range findings {
		c := cbom.Classify(f, p)
		switch {
		case f.Protocol == "TLSv1.0" && c.Strength == cbom.StrengthWeak && c.OutOfPolicy:
			weakProto = true
		case f.Protocol == "TLSv1.2" && c.Strength != cbom.StrengthWeak:
			okProto = true
		case strings.Contains(f.Cipher, "DES-CBC3") && c.Strength == cbom.StrengthWeak:
			weakCipher = true
		case strings.Contains(f.Cipher, "AES128-GCM") && c.Strength != cbom.StrengthWeak:
			okCipher = true
		}
	}
	if !weakProto {
		t.Error("did not flag TLSv1.0 as weak")
	}
	if !okProto {
		t.Error("incorrectly flagged TLSv1.2")
	}
	if !weakCipher {
		t.Error("did not flag the 3DES cipher as weak")
	}
	if !okCipher {
		t.Error("incorrectly flagged the AES-GCM cipher")
	}
}

func TestScanApacheSSLProtocolOrderAndModifiers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "httpd.conf")
	// The first directive is the partner lab's actual mod_ssl configuration.
	// A later directive proves that subtraction removes a previously enabled
	// version instead of recording an out-of-policy false positive.
	conf := "SSLProtocol -all +TLSv1.2 +TLSv1.3\n" +
		"SSLProtocol -all +TLSv1 +TLSv1.2 -TLSv1 +TLSv1.3\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := hostsource.New(path).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("Apache protocol findings = %#v, want two enabled versions per directive", findings)
	}
	for i, want := range []string{"TLSv1.2", "TLSv1.3", "TLSv1.2", "TLSv1.3"} {
		if findings[i].Protocol != want || findings[i].Location != path {
			t.Errorf("finding %d = %#v, want %s at %s", i, findings[i], want, path)
		}
	}
}

func TestScanApacheSSLProtocolAllMinusDeprecated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "httpd.conf")
	if err := os.WriteFile(path, []byte("SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := hostsource.New(path).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Protocol != "TLSv1.2" || findings[1].Protocol != "TLSv1.3" {
		t.Fatalf("Apache all-minus findings = %#v, want TLSv1.2 and TLSv1.3", findings)
	}
}

func TestScanReportsMissingFilesWithoutFindings(t *testing.T) {
	findings, err := hostsource.New("/nonexistent/*.conf").Scan(context.Background())
	var partial *cbom.PartialScanError
	if !errors.As(err, &partial) || partial.Failures != 1 {
		t.Fatalf("missing selector error = %v, want one visible partial failure", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestScanRejectsOversizedFileWithinBoundedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.conf")
	data := make([]byte, hostsource.DefaultMaxFileBytes+1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := hostsource.New(path).Scan(context.Background())
	var partial *cbom.PartialScanError
	if !errors.As(err, &partial) || partial.Failures != 1 || len(findings) != 0 {
		t.Fatalf("oversized scan findings=%d err=%v, want one visible bounded-read failure", len(findings), err)
	}
}
