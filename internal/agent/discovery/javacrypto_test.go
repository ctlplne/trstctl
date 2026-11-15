// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The twelve providers Alpine's OpenJDK 21 and 25 list, in order.
var alpineJDKProviders = []string{"SUN", "SunRsaSign", "SunEC", "SunJSSE", "SunJCE", "SunJGSS", "SunSASL", "XMLDSig", "SunPCSC", "JdkLDAP", "JdkSASL", "SunPKCS11"}

// writeJDK lays out a Java installation's home: its release file, its
// java.security at rel, and its module image (none when modules is nil).
func writeJDK(t *testing.T, home, version, rel string, providers []string, modules []byte) {
	t.Helper()
	var conf strings.Builder
	conf.WriteString("#\n# The list of providers and their preference orders:\n#\n")
	for i, p := range providers {
		conf.WriteString("security.provider." + strconv.Itoa(i+1) + "=" + p + "\n")
	}
	conf.WriteString("#security.provider.13=SunMSCAPI\nsecurerandom.source=file:/dev/random\n")
	files := map[string][]byte{
		"release": []byte("IMPLEMENTOR=\"Alpine\"\nJAVA_RUNTIME_VERSION=\"" + version + "+1-alpine-r0\"\nJAVA_VERSION=\"" + version + "\"\n"),
		rel:       []byte(conf.String()),
	}
	if modules != nil {
		files["lib/modules"] = modules
	}
	for name, body := range files {
		path := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// writeJar writes a jar of the given entries.
func writeJar(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bcManifest(module, version string) []byte {
	return []byte("Manifest-Version: 1.0\r\nAutomatic-Module-Name: " + module + "\r\nImplementation-Version: " + version + "\r\nSpecification-Version: 1.1\r\n\r\nName: org/bouncycastle/\r\nSealed: true\r\n")
}

func namedGroupClass(groups ...string) []byte {
	return []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34" + strings.Join(groups, "\x01\x00\x06") + "\x00")
}

// X2-L4R: Java installations and BouncyCastle jars are inventoried. The
// installations hold what Alpine's openjdk25-jre-headless 25.0.5 and
// openjdk21-jre-headless 21.0.13 hold: JAVA_VERSION in the release file,
// java.security's twelve providers in order, and a module image that names
// TLS_AES_128_GCM_SHA256 and, in 25.0.5 only, X25519MLKEM768 (here across the
// scanner's 1 MiB reads). In the lab, JDK 25.0.5's client offered
// X25519MLKEM768 first and completed a handshake that needed it, and JDK
// 21.0.13's offered no hybrid and failed it. A Java 8 layout and a module
// image that names no suite are not rated. The jars hold what Debian 12's
// and Ubuntu 24.04's libbcprov-java and libbctls-java 1.72 and 1.77 hold:
// manifests naming org.bouncycastle.provider and org.bouncycastle.tls with
// Implementation-Version 1.72.0 and 1.77.00.0, and NamedGroup classes that
// name x25519 and no hybrid; a bctls naming X25519MLKEM768 stands for later
// releases. A symbolic link to a jar is not read twice, and a file that is
// not a jar is skipped.
func TestJavaInstallationsAndBouncyCastleJarsAreInventoriedX2L4R(t *testing.T) {
	root := t.TempDir()
	jvm := filepath.Join(root, "usr", "lib", "jvm")
	pad := bytes.Repeat([]byte{0x5a}, 1<<20-5)
	writeJDK(t, filepath.Join(jvm, "java-25-openjdk"), "25.0.5.0.3", "conf/security/java.security", alpineJDKProviders,
		slices.Concat([]byte("jimage\x00TLS_AES_128_GCM_SHA256\x00"), pad, []byte("X25519MLKEM768\x00tail")))
	writeJDK(t, filepath.Join(jvm, "java-21-openjdk"), "21.0.13.0.3", "conf/security/java.security", alpineJDKProviders,
		slices.Concat([]byte("jimage\x00"), pad, []byte("TLS_AES_128_GCM_SHA256\x00x25519\x00")))
	writeJDK(t, filepath.Join(jvm, "java-8"), "1.8.0_452", "jre/lib/security/java.security", []string{"sun.security.provider.Sun", "sun.security.rsa.SunRsaSign"}, nil)
	writeJDK(t, filepath.Join(jvm, "compressed"), "25.0.1", "conf/security/java.security", alpineJDKProviders, []byte("jimage\x00\x78\x9c compressed resources"))

	java := filepath.Join(root, "usr", "share", "java")
	writeJar(t, filepath.Join(java, "bcprov-1.72.jar"), map[string][]byte{"META-INF/MANIFEST.MF": bcManifest("org.bouncycastle.provider", "1.72.0")})
	writeJar(t, filepath.Join(java, "bctls-1.72.jar"), map[string][]byte{"META-INF/MANIFEST.MF": bcManifest("org.bouncycastle.tls", "1.72.0"),
		"org/bouncycastle/tls/NamedGroup.class": namedGroupClass("X25519", "x25519", "secp256r1")})
	if err := os.Symlink("bcprov-1.72.jar", filepath.Join(java, "bcprov.jar")); err != nil {
		t.Fatal(err)
	}
	writeJar(t, filepath.Join(root, "noble", "bctls-1.77.jar"), map[string][]byte{"META-INF/MANIFEST.MF": bcManifest("org.bouncycastle.tls", "1.77.00.0"),
		"org/bouncycastle/tls/NamedGroup.class": namedGroupClass("X25519", "x25519")})
	writeJar(t, filepath.Join(root, "app", "WEB-INF", "lib", "bctls-jdk18on-1.81.jar"), map[string][]byte{"META-INF/MANIFEST.MF": bcManifest("org.bouncycastle.tls", "1.81.0"),
		"org/bouncycastle/tls/NamedGroup.class": namedGroupClass("x25519", "X25519MLKEM768", "SecP256r1MLKEM768")})
	if err := os.WriteFile(filepath.Join(java, "bcprov-broken.jar"), []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	found, err := NewCryptoLibrarySource(nil, nil).WithJava(jvm, java, filepath.Join(root, "noble", "*.jar"), filepath.Join(root, "app")).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LibraryFound{}
	for _, f := range found {
		rel, _ := filepath.Rel(root, f.Location)
		got[filepath.ToSlash(rel)] = f
	}
	for rel, want := range map[string]struct {
		library, version, pq string
		providers            []string
	}{
		"usr/lib/jvm/java-25-openjdk":            {"java", "25.0.5.0.3", PQHybridYes, alpineJDKProviders},
		"usr/lib/jvm/java-21-openjdk":            {"java", "21.0.13.0.3", PQHybridNo, alpineJDKProviders},
		"usr/lib/jvm/java-8":                     {"java", "1.8.0_452", PQHybridUnknown, []string{"sun.security.provider.Sun", "sun.security.rsa.SunRsaSign"}},
		"usr/lib/jvm/compressed":                 {"java", "25.0.1", PQHybridUnknown, alpineJDKProviders},
		"usr/share/java/bcprov-1.72.jar":         {"bcprov", "1.72", PQHybridUnknown, nil},
		"usr/share/java/bctls-1.72.jar":          {"bctls", "1.72", PQHybridNo, nil},
		"noble/bctls-1.77.jar":                   {"bctls", "1.77", PQHybridNo, nil},
		"app/WEB-INF/lib/bctls-jdk18on-1.81.jar": {"bctls", "1.81", PQHybridYes, nil},
	} {
		f, ok := got[rel]
		if !ok || f.Library != want.library || f.Version != want.version || f.PQHybrid != want.pq || f.Basis == "" || !slices.Equal(f.Providers, want.providers) {
			t.Errorf("%s = %+v; want %s %s, pq %s, providers %v", rel, f, want.library, want.version, want.pq, want.providers)
		}
	}
	if len(got) != 8 {
		t.Errorf("found %d, want 8 (the symbolic link and the broken jar are not read): %v", len(got), got)
	}

	// The scanner finds a name across two reads, and stops at its bound.
	big := filepath.Join(root, "big")
	if err := os.WriteFile(big, slices.Concat(pad, []byte("X25519MLKEM768")), 0o600); err != nil {
		t.Fatal(err)
	}
	if names, err := containsAll(big, 1<<21, hybridGroup); err != nil || !names[0] {
		t.Errorf("a name across two reads: %v, %v", names, err)
	}
	if names, err := containsAll(big, 1<<20, hybridGroup); err != nil || names[0] {
		t.Errorf("a name past the bound was found: %v, %v", names, err)
	}
	if trimZeroComponents("1.77.00.0") != "1.77" || trimZeroComponents("1.80.1") != "1.80.1" || trimZeroComponents("2.0.0") != "2.0" {
		t.Error("version components trimmed wrongly")
	}
}
