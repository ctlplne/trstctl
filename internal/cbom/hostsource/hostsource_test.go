// SPDX-License-Identifier: MPL-2.0

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
