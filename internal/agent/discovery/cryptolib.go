// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SourceCryptoLibrary is the agent inventory source for the TLS libraries
// installed on a host and the Go programs it runs (X2): each with its version
// and whether that version can negotiate the X25519MLKEM768 hybrid key
// exchange. Versions are read from the files themselves (the library's
// version string, a Go binary's build information); nothing is executed or
// loaded.
const SourceCryptoLibrary = "crypto-library"

const maxLibraryFileSize = 64 << 20

// Post-quantum capability answers. "unknown" means the version alone does not
// settle it, and nothing is claimed.
const (
	PQHybridYes     = "yes"
	PQHybridNo      = "no"
	PQHybridUnknown = "unknown"
)

// LibraryFound is one TLS library or Go program and its post-quantum
// capability.
type LibraryFound struct {
	Location string
	// Library is openssl, libressl, boringssl, aws-lc, wolfssl, gnutls,
	// nss, go, java, bcprov, bctls, bc-fips or bctls-fips.
	Library string
	Version string
	// PQHybrid says whether this version can negotiate X25519MLKEM768.
	PQHybrid string
	// Basis says why, in a sentence an operator can check.
	Basis string
	// Providers are a Java installation's security providers in the order
	// its java.security lists them (X2-L4R).
	Providers []string
}

// libraryNames are the file names a directory walk reads as TLS libraries; a
// path named directly is always read.
var libraryNames = regexp.MustCompile(`^(lib(crypto|ssl)[-.0-9a-z_]*\.(so[.0-9]*|dylib|dll)|lib(crypto|ssl)\.so[.0-9]*|libgnutls\.so[.0-9]*|libsoftokn3\.(so|dylib)|libwolfssl\.(so[.0-9]*|dylib))$`)

var (
	openSSLVersion   = regexp.MustCompile(`OpenSSL (\d+)\.(\d+)\.(\d+)([a-z]?)(?:[-+][0-9A-Za-z.+~-]*)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}`)
	libreSSLVersion  = regexp.MustCompile(`LibreSSL (\d+\.\d+\.\d+)`)
	boringSSLVersion = []byte("(compatible; BoringSSL)")
	goVersion        = regexp.MustCompile(`^go(\d+)\.(\d+)`)
	// X2-L4: GnuTLS names its version in its own log banner; NSS's
	// software token names it in its module description.
	gnuTLSVersion = regexp.MustCompile(`Enabled GnuTLS (\d+)\.(\d+)\.(\d+) logging`)
	nssVersion    = regexp.MustCompile(`NSS (\d+\.\d+(?:\.\d+)?) Basic ECC`)
	// hybridGroupName is the X25519MLKEM768 group as libraries spell it in
	// their group tables (X25519MLKEM768, X25519-MLKEM768).
	hybridGroupName = regexp.MustCompile(`(?i)x25519[-_]?mlkem768`)
	// X2-L4R: AWS-LC names its release; wolfSSL names its version beside
	// its name, or alone in a build without its OpenSSL-compatible text;
	// BoringSSL calls itself BoringSSL; and the pre-standard Kyber768
	// hybrids (X25519Kyber768Draft00) are what a BoringSSL cut before
	// X25519MLKEM768 offers instead.
	awsLCVersion    = regexp.MustCompile(`AWS-LC (\d+\.\d+\.\d+)`)
	wolfSSLVersion  = regexp.MustCompile(`wolfSSL (\d+\.\d+\.\d+)`)
	wolfSSLAPI      = []byte("wolfSSL_lib_version")
	bareVersion     = regexp.MustCompile(`\x00(\d+\.\d+\.\d+)\x00`)
	boringSSLName   = []byte("\x00BoringSSL\x00")
	kyberDraftGroup = regexp.MustCompile(`(?i)(x25519|p256|p384)kyber768`)
	// classicGroupName is X25519 as a TLS group table names it.
	classicGroupName = regexp.MustCompile(`\x00[Xx]25519\x00`)
	// A libcrypto names where it reads its configuration and providers.
	openSSLDir     = regexp.MustCompile(`OPENSSLDIR: "([^"\x00]{1,512})"`)
	openSSLModules = regexp.MustCompile(`MODULESDIR: "([^"\x00]{1,512})"`)
)

// CryptoLibrarySource reads TLS libraries and Go binaries at the given files,
// directories or globs.
type CryptoLibrarySource struct {
	// cryptoPolicyRoot is where the system crypto policy is read (X2-L6);
	// empty reads none.
	cryptoPolicyRoot string
	libraries        []string
	goBinaries       []string
	// javaPaths are Java installations and BouncyCastle jars (X2-L4R).
	javaPaths []string
	maxSize   int64
}

// NewCryptoLibrarySource inventories TLS libraries under libraries and the Go
// programs named by goBinaries.
func NewCryptoLibrarySource(libraries, goBinaries []string) *CryptoLibrarySource {
	return &CryptoLibrarySource{libraries: libraries, goBinaries: goBinaries, maxSize: maxLibraryFileSize}
}

// Kind names the source.
func (s *CryptoLibrarySource) Kind() string { return SourceCryptoLibrary }

// Discover returns every TLS library and Go program it can identify. A file it
// cannot identify is skipped, never reported as a library without a version.
func (s *CryptoLibrarySource) Discover(ctx context.Context) ([]LibraryFound, error) {
	var out []LibraryFound
	seen := map[string]bool{}
	err := walkPaths(ctx, s.libraries, func(path string, direct bool) {
		if seen[path] || (!direct && !libraryNames.MatchString(filepath.Base(path))) {
			return
		}
		seen[path] = true
		if found, ok := s.library(path); ok {
			out = append(out, found)
		}
	})
	if err != nil {
		return out, err
	}
	err = walkPaths(ctx, s.goBinaries, func(path string, _ bool) {
		if seen[path] {
			return
		}
		seen[path] = true
		if found, ok := goProgram(path); ok {
			out = append(out, found)
		}
	})
	if err != nil {
		return out, err
	}
	// X2-L4R: Java installations and BouncyCastle jars.
	java, err := s.discoverJava(ctx, seen)
	out = append(out, java...)
	// X2-L6: the host's system crypto policy, which decides what the
	// libraries above offer by default.
	if s.cryptoPolicyRoot != "" {
		if found, ok := ReadCryptoPolicy(s.cryptoPolicyRoot); ok {
			out = append(out, found)
		}
	}
	return out, err
}

// WithCryptoPolicy also reads the system crypto policy under root (X2-L6).
func (s *CryptoLibrarySource) WithCryptoPolicy(root string) *CryptoLibrarySource {
	s.cryptoPolicyRoot = root
	return s
}

func (s *CryptoLibrarySource) library(path string) (LibraryFound, bool) {
	f, err := os.Open(path) // #nosec G304 -- the agent inventories operator-configured library paths; reading them is the product function (CWE-22)
	if err != nil {
		return LibraryFound{}, false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, s.maxSize))
	if err != nil {
		return LibraryFound{}, false
	}
	return identifyLibrary(path, data)
}

// identifyLibrary reads a TLS library's version string. AWS-LC, BoringSSL,
// wolfSSL and LibreSSL are checked first because each can also carry
// OpenSSL-compatible strings, AWS-LC before the BoringSSL it derives from.
func identifyLibrary(path string, data []byte) (LibraryFound, bool) {
	if bytes.Contains(data, wolfSSLAPI) {
		if found, ok := wolfSSL(path, data); ok {
			return found, true
		}
	}
	switch {
	case awsLCVersion.Match(data):
		found := LibraryFound{Location: path, Library: "aws-lc", Version: string(awsLCVersion.FindSubmatch(data)[1])}
		found.PQHybrid, found.Basis = groupTableAnswer("AWS-LC", withSiblingSSL(path, data))
		return found, true
	case bytes.Contains(data, boringSSLVersion) || bytes.Contains(data, boringSSLName):
		found := LibraryFound{Location: path, Library: "boringssl", Version: "unversioned"}
		found.PQHybrid, found.Basis = groupTableAnswer("BoringSSL", withSiblingSSL(path, data))
		found.Basis += " (BoringSSL has no release versions)"
		return found, true
	case libreSSLVersion.Match(data):
		return libreSSL(path, data), true
	case gnuTLSVersion.Match(data):
		return gnuTLS(path, data), true
	case nssVersion.Match(data):
		return nss(path, data), true
	}
	m := openSSLVersion.FindSubmatch(data)
	if m == nil {
		return LibraryFound{}, false
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	version := string(m[1]) + "." + string(m[2]) + "." + string(m[3]) + string(m[4])
	found := LibraryFound{Location: path, Library: "openssl", Version: version}
	if major > 3 || (major == 3 && minor >= 5) {
		found.PQHybrid = PQHybridYes
		found.Basis = "OpenSSL 3.5 and later include ML-KEM and offer X25519MLKEM768 among the default TLS groups"
	} else {
		found.PQHybrid, found.Basis = openSSLProviderMLKEM(data)
	}
	return found, true
}

// wolfSSL rates wolfSSL by what the build carries (X2-L4R): it negotiates
// X25519MLKEM768 only when built with ML-KEM, and such a build names the
// group. Its version is the one beside its name, or, in a library file a
// build left without that text, the version string alone.
func wolfSSL(path string, data []byte) (LibraryFound, bool) {
	var version string
	if m := wolfSSLVersion.FindSubmatch(data); m != nil {
		version = string(m[1])
	} else if strings.HasPrefix(filepath.Base(path), "libwolfssl") {
		if m := bareVersion.FindSubmatch(data); m != nil {
			version = string(m[1])
		}
	}
	if version == "" {
		return LibraryFound{}, false
	}
	found := LibraryFound{Location: path, Library: "wolfssl", Version: version}
	if hybridGroupName.Match(data) {
		found.PQHybrid = PQHybridYes
		found.Basis = "this wolfSSL build names the X25519MLKEM768 group: it was built with ML-KEM"
	} else {
		found.PQHybrid = PQHybridNo
		found.Basis = "this wolfSSL build names no ML-KEM hybrid group: wolfSSL negotiates X25519MLKEM768 only when built with ML-KEM"
	}
	return found, true
}

// groupTableAnswer rates a BoringSSL-family build by the TLS groups it names
// (X2-L4R): X25519MLKEM768 in a build that offers it, only the pre-standard
// Kyber768 hybrids in one cut before it, X25519 alone in one older still. A
// build that names no TLS group at all is not rated.
func groupTableAnswer(name string, data []byte) (string, string) {
	switch {
	case hybridGroupName.Match(data):
		return PQHybridYes, "this " + name + " build names the X25519MLKEM768 group in its TLS group table"
	case kyberDraftGroup.Match(data):
		return PQHybridNo, "this " + name + " build names only the pre-standard Kyber768 hybrids (X25519Kyber768Draft00), not X25519MLKEM768"
	case classicGroupName.Match(data):
		return PQHybridNo, "this " + name + " build's TLS group table names X25519 and no ML-KEM hybrid group"
	}
	return PQHybridUnknown, "this " + name + " build names no TLS group the agent can read"
}

// withSiblingSSL adds, to a libcrypto's bytes, those of the libssl beside it,
// which holds the TLS group table (X2-L4R).
func withSiblingSSL(path string, data []byte) []byte {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "libcrypto") {
		return data
	}
	sibling, err := readBounded(filepath.Join(filepath.Dir(path), "libssl"+strings.TrimPrefix(base, "libcrypto")), maxLibraryFileSize)
	if err != nil {
		return data
	}
	return append(append(append([]byte(nil), data...), 0), sibling...)
}

// libreSSL rates LibreSSL by its release notes: 4.3.0 added the
// X25519MLKEM768 key share (MLKEM768_X25519) to TLS 1.3, and 4.4.0 made it
// libtls's preferred group (X2-L4). A build that names the group is rated
// so whatever its version.
func libreSSL(path string, data []byte) LibraryFound {
	m := libreSSLVersion.FindSubmatch(data)
	found := LibraryFound{Location: path, Library: "libressl", Version: string(m[1])}
	parts := strings.SplitN(found.Version, ".", 3)
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	switch {
	case major > 4 || (major == 4 && minor >= 3) || hybridGroupName.Match(data):
		found.PQHybrid = PQHybridYes
		found.Basis = "LibreSSL 4.3.0 and later support the X25519MLKEM768 key share in TLS 1.3 (4.4.0 makes it libtls's preferred group)"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "LibreSSL before 4.3.0 has no ML-KEM key share in TLS"
	}
	return found
}

// gnuTLS rates GnuTLS by what the build names (X2-L4): GnuTLS 3.8.8 added
// X25519MLKEM768 as experimental, available only when built with a
// post-quantum backend (leancrypto; liboqs before 3.8.10), and a build
// without one carries no hybrid group.
func gnuTLS(path string, data []byte) LibraryFound {
	m := gnuTLSVersion.FindSubmatch(data)
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	patch, _ := strconv.Atoi(string(m[3]))
	found := LibraryFound{Location: path, Library: "gnutls", Version: string(m[1]) + "." + string(m[2]) + "." + string(m[3])}
	atLeast388 := major > 3 || (major == 3 && (minor > 8 || (minor == 8 && patch >= 8)))
	switch {
	case !atLeast388:
		found.PQHybrid = PQHybridNo
		found.Basis = "GnuTLS before 3.8.8 has no X25519MLKEM768"
	case hybridGroupName.Match(data):
		found.PQHybrid = PQHybridYes
		found.Basis = "this GnuTLS build names the X25519MLKEM768 group (experimental since 3.8.8; its priority string decides whether it is offered)"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "this GnuTLS build names no ML-KEM hybrid group: GnuTLS 3.8.8 and later offer X25519MLKEM768 only when built with a post-quantum backend"
	}
	return found
}

// nss rates NSS (X2-L4). Its software token names the version; whether the
// installation knows the X25519MLKEM768 group is read from libnss3 beside
// it, which names the groups NSS supports.
func nss(path string, data []byte) LibraryFound {
	found := LibraryFound{Location: path, Library: "nss", Version: string(nssVersion.FindSubmatch(data)[1])}
	sibling := filepath.Join(filepath.Dir(path), "libnss3"+filepath.Ext(path))
	lib, err := readBounded(sibling, maxLibraryFileSize)
	switch {
	case err != nil:
		found.PQHybrid = PQHybridUnknown
		found.Basis = "libnss3, which names the groups NSS supports, was not found beside this software token"
	case hybridGroupName.Match(lib):
		found.PQHybrid = PQHybridYes
		found.Basis = "libnss3 beside it names the X25519MLKEM768 group"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "libnss3 beside it names no X25519MLKEM768 group"
	}
	return found
}

// openSSLProviderMLKEM rates an OpenSSL before 3.5, which has no built-in
// ML-KEM, by the configuration it reads (X2-L4): its OPENSSLDIR's
// openssl.cnf can activate oqsprovider, which adds the ML-KEM hybrid groups;
// they are offered by default only when the configuration's Groups list names
// one. An OPENSSL_CONF set for a single program is not seen.
func openSSLProviderMLKEM(data []byte) (string, string) {
	const none = "OpenSSL before 3.5 has no built-in ML-KEM, and its configuration activates no provider that adds it"
	m := openSSLDir.FindSubmatch(data)
	if m == nil {
		return PQHybridNo, none
	}
	cnfPath := filepath.Join(string(m[1]), "openssl.cnf")
	raw, err := readBounded(cnfPath, 1<<20)
	if err != nil {
		return PQHybridNo, none
	}
	cnf := parseOpenSSLConfig(raw)
	init := cnf.get("", "openssl_conf")
	provider, module := "", ""
	for name, section := range cnf.sections[cnf.get(init, "providers")] {
		if !strings.Contains(strings.ToLower(name+" "+cnf.get(section, "module")), "oqs") || !truthy(cnf.get(section, "activate")) {
			continue
		}
		provider, module = name, cnf.get(section, "module")
		break
	}
	if provider == "" {
		return PQHybridNo, none
	}
	if module == "" {
		if dir := openSSLModules.FindSubmatch(data); dir != nil {
			module = filepath.Join(string(dir[1]), "oqsprovider.so")
		}
	}
	if fi, err := os.Stat(module); module == "" || err != nil || !fi.Mode().IsRegular() {
		return PQHybridNo, cnfPath + " activates " + provider + ", but its module " + module + " is missing, so no ML-KEM is added"
	}
	groups := cnf.get(cnf.get(cnf.get(init, "ssl_conf"), "system_default"), "Groups")
	if groups == "" {
		groups = cnf.get(cnf.get(cnf.get(init, "ssl_conf"), "system_default"), "Curves")
	}
	if strings.Contains(strings.ToLower(groups), "mlkem") {
		return PQHybridYes, cnfPath + " activates " + provider + ", which adds ML-KEM, and its Groups list names an ML-KEM hybrid"
	}
	return PQHybridUnknown, cnfPath + " activates " + provider + ", which adds the ML-KEM hybrid groups, but its Groups list names none, so a program offers them only if it sets its own groups"
}

// openSSLConfig is an openssl.cnf's sections and their name = value pairs;
// "" is the section before the first header.
type openSSLConfig struct {
	sections map[string]map[string]string
}

func parseOpenSSLConfig(raw []byte) openSSLConfig {
	cnf := openSSLConfig{sections: map[string]map[string]string{"": {}}}
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "."):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
			if cnf.sections[section] == nil {
				cnf.sections[section] = map[string]string{}
			}
		default:
			name, value, ok := strings.Cut(line, "=")
			if ok {
				cnf.sections[section][strings.TrimSpace(name)] = strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
	}
	return cnf
}

func (c openSSLConfig) get(section, name string) string {
	if section == "" && name != "openssl_conf" {
		return ""
	}
	return c.sections[section][name]
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a file named by the library being inventoried (its OPENSSLDIR or a sibling library) (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// goProgram reads a Go binary's build information.
func goProgram(path string) (LibraryFound, bool) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return LibraryFound{}, false
	}
	m := goVersion.FindStringSubmatch(info.GoVersion)
	if m == nil {
		return LibraryFound{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	found := LibraryFound{Location: path, Library: "go", Version: strings.TrimPrefix(info.GoVersion, "go")}
	switch {
	case godebugDisablesMLKEM(info):
		found.PQHybrid = PQHybridNo
		found.Basis = "built with tlsmlkem=0, which turns X25519MLKEM768 off"
	case major > 1 || (major == 1 && minor >= 24):
		found.PQHybrid = PQHybridYes
		found.Basis = "Go 1.24 and later offer X25519MLKEM768 by default in crypto/tls"
	case major == 1 && minor == 23:
		found.PQHybrid = PQHybridNo
		found.Basis = "Go 1.23 offers only the pre-standard X25519Kyber768Draft00"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "Go before 1.23 has no post-quantum key exchange in crypto/tls"
	}
	return found, true
}

func godebugDisablesMLKEM(info *buildinfo.BuildInfo) bool {
	for _, setting := range info.Settings {
		if setting.Key == "DefaultGODEBUG" && strings.Contains(","+setting.Value+",", ",tlsmlkem=0,") {
			return true
		}
	}
	return false
}

// walkPaths visits each file named by paths (a file, a directory walked
// recursively, or a glob). direct is true for a file named outright.
func walkPaths(ctx context.Context, paths []string, visit func(path string, direct bool)) error {
	for _, root := range paths {
		matches, err := filepath.Glob(root)
		if err != nil || len(matches) == 0 {
			matches = []string{root}
		}
		for _, match := range matches {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fi, err := os.Stat(match)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				if fi.Mode().IsRegular() {
					visit(match, true)
				}
				continue
			}
			err = filepath.WalkDir(match, func(path string, d fs.DirEntry, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil || !d.Type().IsRegular() {
					return nil
				}
				visit(path, false)
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
