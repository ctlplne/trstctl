// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLib(t *testing.T, path string, parts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	body := "\x7fELF padding\x00" + strings.Join(parts, "\x00filler\x00") + "\x00tail"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// X2-L4: libraries beyond OpenSSL and Go, and ML-KEM a provider adds. The
// version strings and group names are those of the Alpine builds read in
// the lab (GnuTLS 3.8.13: "Enabled GnuTLS 3.8.13 logging..." and no hybrid
// group; NSS 3.124: libsoftokn3 "Generic NSS 3.124 Basic ECC Unvalidated",
// libnss3 naming X25519MLKEM768; OpenSSL 3.5.9: libcrypto's OPENSSLDIR and
// MODULESDIR lines).
func TestCryptoLibrariesBeyondOpenSSLAndGoX2L4(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "usr", "lib")
	// GnuTLS: a build without a post-quantum backend, one that names the
	// hybrid group, and a version before 3.8.8.
	writeLib(t, filepath.Join(lib, "libgnutls.so.30"), "Enabled GnuTLS 3.8.13 logging...", "ML-KEM-768", "ML-KEM-1024")
	writeLib(t, filepath.Join(root, "opt", "pq", "libgnutls.so.30"), "Enabled GnuTLS 3.8.10 logging...", "X25519-MLKEM768", "libleancrypto.so.1")
	writeLib(t, filepath.Join(root, "opt", "old", "libgnutls.so.30"), "Enabled GnuTLS 3.7.9 logging...")
	// NSS: the software token names the version; libnss3 beside it the groups.
	writeLib(t, filepath.Join(lib, "libsoftokn3.so"), "Generic NSS 3.124 Basic ECC Unvalidated")
	writeLib(t, filepath.Join(lib, "libnss3.so"), "NSS_3.117", "X25519MLKEM768", "SECP256R1MLKEM768")
	writeLib(t, filepath.Join(root, "opt", "nss-old", "libsoftokn3.so"), "NSS 3.98 Basic ECC")
	writeLib(t, filepath.Join(root, "opt", "nss-old", "libnss3.so"), "NSS_3.98", "X25519")
	writeLib(t, filepath.Join(root, "opt", "nss-alone", "libsoftokn3.so"), "NSS 3.110 Basic ECC")
	// LibreSSL by its release notes.
	writeLib(t, filepath.Join(root, "opt", "libressl41", "libcrypto.so.55"), "LibreSSL 4.1.0")
	writeLib(t, filepath.Join(root, "opt", "libressl43", "libcrypto.so.56"), "LibreSSL 4.3.0")

	// OpenSSL 3.0 with oqsprovider activated in its own OPENSSLDIR, with
	// and without an ML-KEM group in the default list, and with its module
	// missing.
	provider := func(dir, groups string, module bool) string {
		ssl := filepath.Join(root, dir, "ssl")
		modules := filepath.Join(root, dir, "ossl-modules")
		cnf := "openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_sect\n\n" +
			"[provider_sect]\ndefault = default_sect\noqsprovider = oqs_sect # adds ML-KEM\n\n[default_sect]\nactivate = 1\n\n" +
			"[oqs_sect]\nactivate = 1\n\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\n"
		if groups != "" {
			cnf += "Groups = " + groups + "\n"
		}
		if err := os.MkdirAll(ssl, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ssl, "openssl.cnf"), []byte(cnf), 0o600); err != nil {
			t.Fatal(err)
		}
		if module {
			writeLib(t, filepath.Join(modules, "oqsprovider.so"), "oqsprovider")
		}
		return `OPENSSLDIR: "` + ssl + `"` + "\x00" + `MODULESDIR: "` + modules + `"`
	}
	writeLib(t, filepath.Join(root, "opt", "oqs-groups", "libcrypto.so.3"), "OpenSSL 3.0.13 30 Jan 2024", provider("opt/oqs-groups", "X25519MLKEM768:x25519:secp256r1", true))
	writeLib(t, filepath.Join(root, "opt", "oqs-default", "libcrypto.so.3"), "OpenSSL 3.0.13 30 Jan 2024", provider("opt/oqs-default", "", true))
	writeLib(t, filepath.Join(root, "opt", "oqs-missing", "libcrypto.so.3"), "OpenSSL 3.0.13 30 Jan 2024", provider("opt/oqs-missing", "X25519MLKEM768", false))
	writeLib(t, filepath.Join(root, "opt", "plain30", "libcrypto.so.3"), "OpenSSL 3.0.13 30 Jan 2024", `OPENSSLDIR: "`+filepath.Join(root, "nowhere")+`"`)

	found, err := NewCryptoLibrarySource([]string{root}, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LibraryFound{}
	for _, f := range found {
		rel, _ := filepath.Rel(root, f.Location)
		got[filepath.ToSlash(rel)] = f
	}
	for path, want := range map[string]struct{ library, version, pq, basis string }{
		"usr/lib/libgnutls.so.30":        {"gnutls", "3.8.13", PQHybridNo, "names no ML-KEM hybrid group"},
		"opt/pq/libgnutls.so.30":         {"gnutls", "3.8.10", PQHybridYes, "names the X25519MLKEM768 group"},
		"opt/old/libgnutls.so.30":        {"gnutls", "3.7.9", PQHybridNo, "before 3.8.8"},
		"usr/lib/libsoftokn3.so":         {"nss", "3.124", PQHybridYes, "libnss3 beside it names the X25519MLKEM768 group"},
		"opt/nss-old/libsoftokn3.so":     {"nss", "3.98", PQHybridNo, "names no X25519MLKEM768 group"},
		"opt/nss-alone/libsoftokn3.so":   {"nss", "3.110", PQHybridUnknown, "was not found"},
		"opt/libressl41/libcrypto.so.55": {"libressl", "4.1.0", PQHybridNo, "before 4.3.0"},
		"opt/libressl43/libcrypto.so.56": {"libressl", "4.3.0", PQHybridYes, "4.3.0 and later"},
		"opt/oqs-groups/libcrypto.so.3":  {"openssl", "3.0.13", PQHybridYes, "activates oqsprovider, which adds ML-KEM, and its Groups list names an ML-KEM hybrid"},
		"opt/oqs-default/libcrypto.so.3": {"openssl", "3.0.13", PQHybridUnknown, "its Groups list names none"},
		"opt/oqs-missing/libcrypto.so.3": {"openssl", "3.0.13", PQHybridNo, "is missing"},
		"opt/plain30/libcrypto.so.3":     {"openssl", "3.0.13", PQHybridNo, "activates no provider"},
	} {
		f, ok := got[path]
		if !ok {
			t.Fatalf("%s was not inventoried (found %v)", path, found)
		}
		if f.Library != want.library || f.Version != want.version || f.PQHybrid != want.pq || !strings.Contains(f.Basis, want.basis) {
			t.Fatalf("%s = %+v; want %s %s %s (%q)", path, f, want.library, want.version, want.pq, want.basis)
		}
	}
	if _, ok := got["usr/lib/libnss3.so"]; ok {
		t.Fatal("libnss3 was reported as a library of its own; NSS is reported once, by its software token")
	}
	if len(found) != 12 {
		t.Fatalf("%d libraries found; want 12: %+v", len(found), found)
	}
}
