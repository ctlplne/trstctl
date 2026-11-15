// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Java (X2-L4R): a Java installation's TLS and its security providers, and
// the BouncyCastle jars an application ships. Everything is read from the
// files, nothing is run: an installation's release file names its version,
// its java.security lists its providers in order, and its module image names
// the TLS groups its JSSE knows; a jar's manifest names its version, and
// bctls's NamedGroup class the groups BouncyCastle's JSSE knows.

const (
	// maxJavaModulesSize bounds the module image scanned for TLS group
	// names; a full JDK's is about 150 MB.
	maxJavaModulesSize = 1 << 30
	// maxJarSize bounds a jar read; maxJarEntry one entry inflated from it.
	maxJarSize  = 64 << 20
	maxJarEntry = 4 << 20
	// maxJavaProviders bounds the providers listed for one installation.
	maxJavaProviders = 64
)

var (
	javaVersionLine  = regexp.MustCompile(`(?m)^JAVA_VERSION="([^"\r\n]{1,64})"`)
	javaProviderLine = regexp.MustCompile(`(?m)^[ \t]*security\.provider\.(\d{1,3})[ \t]*=[ \t]*(\S{1,256})`)
	bouncyCastleJar  = regexp.MustCompile(`^(bcprov|bctls|bc-fips|bctls-fips)([-._][-._a-z0-9]*)?\.jar$`)
	// tlsSuiteMarker is a TLS 1.3 suite every JSSE names: a module image in
	// which it cannot be read (compressed) says nothing about groups.
	tlsSuiteMarker = []byte("TLS_AES_128_GCM_SHA256")
	hybridGroup    = []byte("X25519MLKEM768")
)

// WithJava also reads the Java installations (a JDK or JRE home) and the
// BouncyCastle jars (bcprov, bctls and their FIPS editions) at the given
// files, directories or globs (X2-L4R).
func (s *CryptoLibrarySource) WithJava(paths ...string) *CryptoLibrarySource {
	s.javaPaths = append(s.javaPaths, paths...)
	return s
}

// discoverJava walks the Java paths: a release file naming JAVA_VERSION marks
// an installation's home, and a jar named like a BouncyCastle artifact is
// read for its version.
func (s *CryptoLibrarySource) discoverJava(ctx context.Context, seen map[string]bool) ([]LibraryFound, error) {
	var out []LibraryFound
	err := walkPaths(ctx, s.javaPaths, func(path string, _ bool) {
		if seen[path] {
			return
		}
		switch base := filepath.Base(path); {
		case base == "release":
			seen[path] = true
			if found, ok := javaInstallation(filepath.Dir(path)); ok {
				out = append(out, found)
			}
		case bouncyCastleJar.MatchString(base):
			seen[path] = true
			if found, ok := bouncyCastle(path); ok {
				out = append(out, found)
			}
		}
	})
	return out, err
}

// javaInstallation reads the installation at home: its version, its
// security providers, and whether its JSSE knows X25519MLKEM768.
func javaInstallation(home string) (LibraryFound, bool) {
	release, err := readBounded(filepath.Join(home, "release"), 64<<10)
	if err != nil {
		return LibraryFound{}, false
	}
	m := javaVersionLine.FindSubmatch(release)
	if m == nil {
		return LibraryFound{}, false
	}
	found := LibraryFound{Location: home, Library: "java", Version: string(m[1])}
	for _, rel := range []string{"conf/security/java.security", "jre/lib/security/java.security", "lib/security/java.security"} {
		if conf, err := readBounded(filepath.Join(home, filepath.FromSlash(rel)), 1<<20); err == nil {
			found.Providers = javaProviders(conf)
			break
		}
	}
	modules := filepath.Join(home, "lib", "modules")
	if _, err := os.Stat(modules); err != nil {
		found.PQHybrid = PQHybridUnknown
		found.Basis = "this Java installation has no module image (the layout of Java 8 and earlier), so its TLS groups are not read"
		return found, true
	}
	names, err := containsAll(modules, maxJavaModulesSize, tlsSuiteMarker, hybridGroup)
	switch {
	case err != nil || !names[0]:
		found.PQHybrid = PQHybridUnknown
		found.Basis = "this Java installation's module image does not name its TLS suites where the agent can read them (it may be compressed), so its TLS groups are not read"
	case names[1]:
		found.PQHybrid = PQHybridYes
		found.Basis = "this Java installation's modules name the X25519MLKEM768 group: its JSSE can negotiate it (jdk.tls.namedGroups decides whether it is offered)"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "this Java installation's modules name its TLS suites and no X25519MLKEM768 group"
	}
	return found, true
}

// javaProviders lists java.security's providers by their number, at most
// maxJavaProviders; a provider given as a class name is listed so.
func javaProviders(conf []byte) []string {
	type provider struct {
		n    int
		name string
	}
	var listed []provider
	for _, m := range javaProviderLine.FindAllSubmatch(conf, maxJavaProviders) {
		n, _ := strconv.Atoi(string(m[1]))
		listed = append(listed, provider{n, string(m[2])})
	}
	sort.SliceStable(listed, func(i, j int) bool { return listed[i].n < listed[j].n })
	names := make([]string, 0, len(listed))
	for _, p := range listed {
		names = append(names, p.name)
	}
	return names
}

// containsAll reports, for each needle, whether the first limit bytes of the
// file at path contain it, reading a fixed buffer at a time (a needle that
// crosses two reads is found).
func containsAll(path string, limit int64, needles ...[]byte) ([]bool, error) {
	f, err := os.Open(path) // #nosec G304 -- the agent inventories operator-configured Java installations; reading them is the product function (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	longest := 0
	for _, n := range needles {
		longest = max(longest, len(n))
	}
	found := make([]bool, len(needles))
	buf := make([]byte, 0, 1<<20+longest)
	r := io.LimitReader(f, limit)
	chunk := make([]byte, 1<<20)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		all := true
		for i, needle := range needles {
			found[i] = found[i] || bytes.Contains(buf, needle)
			all = all && found[i]
		}
		if all {
			return found, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return found, nil
			}
			return found, err
		}
		// Keep the tail a needle could start in.
		if keep := longest - 1; len(buf) > keep {
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
	}
}

// bouncyCastle reads a BouncyCastle jar: which artifact and version its
// manifest names, and for bctls whether its NamedGroup class names
// X25519MLKEM768. bcprov is a cryptography provider without TLS; whether
// TLS offers the hybrid is bctls's answer.
func bouncyCastle(path string) (LibraryFound, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxJarSize {
		return LibraryFound{}, false
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		return LibraryFound{}, false
	}
	defer func() { _ = z.Close() }()
	manifest, ok := jarEntry(&z.Reader, "META-INF/MANIFEST.MF")
	if !ok {
		return LibraryFound{}, false
	}
	attrs := manifestAttributes(manifest)
	version := attrs["Implementation-Version"]
	if version == "" {
		version = attrs["Bundle-Version"]
	}
	artifact := bouncyCastleArtifact(attrs["Automatic-Module-Name"], filepath.Base(path))
	if version == "" || artifact == "" {
		return LibraryFound{}, false
	}
	found := LibraryFound{Location: path, Library: artifact, Version: trimZeroComponents(version)}
	switch artifact {
	case "bctls", "bctls-fips":
		class, ok := jarEntry(&z.Reader, "org/bouncycastle/tls/NamedGroup.class")
		switch {
		case !ok:
			found.PQHybrid = PQHybridUnknown
			found.Basis = "this jar has no org.bouncycastle.tls.NamedGroup class to read its TLS groups from"
		case bytes.Contains(class, hybridGroup):
			found.PQHybrid = PQHybridYes
			found.Basis = "this BouncyCastle TLS (BCJSSE) names the X25519MLKEM768 group"
		default:
			found.PQHybrid = PQHybridNo
			found.Basis = "this BouncyCastle TLS (BCJSSE) names no X25519MLKEM768 group"
		}
	default:
		found.PQHybrid = PQHybridUnknown
		found.Basis = "a BouncyCastle cryptography provider, without TLS: whether TLS offers X25519MLKEM768 is bctls's (BCJSSE's) answer"
	}
	return found, true
}

// bouncyCastleArtifact names the artifact from the manifest's module name,
// or from the file name.
func bouncyCastleArtifact(module, base string) string {
	switch module {
	case "org.bouncycastle.provider":
		return "bcprov"
	case "org.bouncycastle.tls":
		return "bctls"
	case "org.bouncycastle.fips.core":
		return "bc-fips"
	case "org.bouncycastle.fips.tls":
		return "bctls-fips"
	}
	if m := bouncyCastleJar.FindStringSubmatch(base); m != nil {
		return m[1]
	}
	return ""
}

// jarEntry inflates one entry of a jar, at most maxJarEntry bytes.
func jarEntry(z *zip.Reader, name string) ([]byte, bool) {
	for _, f := range z.File {
		if f.Name != name {
			continue
		}
		if f.UncompressedSize64 > maxJarEntry {
			return nil, false
		}
		rc, err := f.Open()
		if err != nil {
			return nil, false
		}
		defer func() { _ = rc.Close() }()
		data, err := io.ReadAll(io.LimitReader(rc, maxJarEntry))
		return data, err == nil
	}
	return nil, false
}

// manifestAttributes reads a jar manifest's main attributes; a line starting
// with a space continues the one before it.
func manifestAttributes(manifest []byte) map[string]string {
	attrs := map[string]string{}
	var last string
	for _, line := range strings.Split(strings.ReplaceAll(string(manifest), "\r\n", "\n"), "\n") {
		if line == "" {
			break // the main section ends at the first blank line
		}
		if strings.HasPrefix(line, " ") && last != "" {
			attrs[last] += line[1:]
			continue
		}
		if name, value, ok := strings.Cut(line, ":"); ok {
			last = strings.TrimSpace(name)
			attrs[last] = strings.TrimSpace(value)
		}
	}
	return attrs
}

// trimZeroComponents drops trailing all-zero version components: 1.77.00.0
// reads 1.77, 1.80.1 stays.
func trimZeroComponents(v string) string {
	parts := strings.Split(v, ".")
	for len(parts) > 2 && strings.Trim(parts[len(parts)-1], "0") == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, ".")
}
