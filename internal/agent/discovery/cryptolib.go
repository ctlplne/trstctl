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
	Library  string // openssl, libressl, boringssl or go
	Version  string
	// PQHybrid says whether this version can negotiate X25519MLKEM768.
	PQHybrid string
	// Basis says why, in a sentence an operator can check.
	Basis string
}

// libraryNames are the file names a directory walk reads as TLS libraries; a
// path named directly is always read.
var libraryNames = regexp.MustCompile(`^(lib(crypto|ssl)[-.0-9a-z_]*\.(so[.0-9]*|dylib|dll)|lib(crypto|ssl)\.so[.0-9]*)$`)

var (
	openSSLVersion   = regexp.MustCompile(`OpenSSL (\d+)\.(\d+)\.(\d+)([a-z]?)(?:[-+][0-9A-Za-z.+~-]*)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}`)
	libreSSLVersion  = regexp.MustCompile(`LibreSSL (\d+\.\d+\.\d+)`)
	boringSSLVersion = []byte("(compatible; BoringSSL)")
	goVersion        = regexp.MustCompile(`^go(\d+)\.(\d+)`)
)

// CryptoLibrarySource reads TLS libraries and Go binaries at the given files,
// directories or globs.
type CryptoLibrarySource struct {
	libraries  []string
	goBinaries []string
	maxSize    int64
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
	return out, err
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

// identifyLibrary reads a TLS library's version string. BoringSSL and LibreSSL
// are checked first because both also carry OpenSSL-compatible strings.
func identifyLibrary(path string, data []byte) (LibraryFound, bool) {
	switch {
	case bytes.Contains(data, boringSSLVersion):
		return LibraryFound{Location: path, Library: "boringssl", Version: "unversioned", PQHybrid: PQHybridUnknown,
			Basis: "BoringSSL has no release versions; whether this build offers X25519MLKEM768 depends on when it was cut"}, true
	case libreSSLVersion.Match(data):
		v := string(libreSSLVersion.FindSubmatch(data)[1])
		return LibraryFound{Location: path, Library: "libressl", Version: v, PQHybrid: PQHybridUnknown,
			Basis: "trstctl does not rate LibreSSL versions for X25519MLKEM768; check its release notes"}, true
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
		found.PQHybrid = PQHybridNo
		found.Basis = "OpenSSL before 3.5 has no built-in ML-KEM; a loaded provider could add it, which this inventory does not check"
	}
	return found, true
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
