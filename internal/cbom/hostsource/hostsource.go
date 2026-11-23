// SPDX-License-Identifier: BUSL-1.1

// Package hostsource is a CBOM source that reads host TLS configuration files
// (nginx, Apache, sshd-style; since X2 also HAProxy, Envoy, the OpenSSL
// configuration file and java.security) and reports the protocol versions and
// cipher suites they declare in use — read-only, non-invasive file reads (F52).
package hostsource

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/safefile"
)

// Source scans a set of config files or globs.
type Source struct {
	paths []string
	// roots are canonical operator-approved directories. Without them this
	// source cannot read any tenant-selected host path.
	roots []string
	// expected is the operator-pinned directory identity from server startup.
	// A replaced root path must not silently widen a tenant's scan authority.
	expected map[string]os.FileInfo
	// packageDBs are where a scan reads product versions from (X2-L7); nil
	// means dpkg's status file and apk's installed database.
	packageDBs []string
	mu         sync.Mutex
	resolved   []string
}

const (
	// DefaultMaxFiles caps glob expansion and DefaultMaxFileBytes caps every
	// individual read. Both limits apply to all callers, including older ones
	// that use New directly.
	DefaultMaxFiles     = 256
	DefaultMaxFileBytes = int64(1 << 20)
)

// New returns a host-config source over the given file paths or globs.
func New(paths ...string) *Source { return &Source{paths: paths} }

// WithAllowedRoots confines every selector, glob expansion and file open to
// operator-approved host directories. The caller validates roots at startup.
func (s *Source) WithAllowedRoots(roots ...string) *Source {
	approved, err := safefile.HostRoots(roots)
	if err != nil {
		s.roots = nil // invalid direct callers fail closed on every selector
	} else {
		s.roots = approved
	}
	return s
}

// WithPinnedRoots binds the allowed paths to directory identities captured at
// control-plane startup. OpenRoot descriptors are compared before any walk.
func (s *Source) WithPinnedRoots(expected map[string]os.FileInfo) *Source {
	s.expected = expected
	return s
}

// WithPackageDatabases sets the package databases a scan reads the product
// versions that decide a default from (X2-L7); none means no default is
// claimed.
func (s *Source) WithPackageDatabases(paths ...string) *Source {
	s.packageDBs = append([]string{}, paths...)
	return s
}

// Name identifies the source.
func (s *Source) Name() string { return "host-config" }

// ResolvedPaths returns the concrete files selected by the last scan. A caller
// must use these exact paths when reconciling current CBOM facts after a complete
// scan; a glob selector is not itself an asset location.
func (s *Source) ResolvedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.resolved...)
}

var protocolDirectives = map[string]bool{"ssl_protocols": true, "sslprotocol": true, "protocols": true}
var cipherDirectives = map[string]bool{"ssl_ciphers": true, "sslciphersuite": true, "ciphers": true}

// Scan reads each config file and reports the protocols and ciphers it declares.
// Missing or unreadable files are skipped.
func (s *Source) Scan(ctx context.Context) ([]cbom.Finding, error) {
	var out []cbom.Finding
	files, failures, closeRoots := expandConfined(ctx, s.roots, s.expected, s.paths, DefaultMaxFiles)
	defer closeRoots()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.path)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	s.mu.Lock()
	s.resolved = append([]string(nil), paths...)
	s.mu.Unlock()
	// Product versions are read once, and only when a file leaves a
	// product default in force (X2-L7).
	var pkgs packageVersions
	versions := func() packageVersions {
		if pkgs == nil {
			dbs := s.packageDBs
			if dbs == nil {
				dbs = defaultPackageDatabases
			}
			pkgs = readPackageVersions(dbs)
		}
		return pkgs
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		data, err := safefile.ReadRegularFileNoFollow(ctx, file.root, file.rel, DefaultMaxFileBytes)
		if err != nil {
			failures++
			continue
		}
		out = append(out, parseConfig(file.path, data)...)
		out = append(out, parseExtended(file.path, data)...)
		out = append(out, parseDefaults(file.path, data, versions)...)
		secret.Wipe(data)
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if failures > 0 {
		return out, &cbom.PartialScanError{Failures: failures, Err: errors.New("one or more CBOM host config selectors could not be read within safety limits")}
	}
	return out, nil
}

func parseConfig(path string, data []byte) []cbom.Finding {
	var out []cbom.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	// ReadRegularFile already limits the entire file to 1 MiB. Let Scanner accept a
	// line up to that same ceiling so a long but valid cipher declaration cannot
	// stop parsing early at bufio.Scanner's much smaller default token limit.
	sc.Buffer(make([]byte, 64*1024), int(DefaultMaxFileBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, ";") // nginx statements end with ;
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch {
		case protocolDirectives[key]:
			for _, name := range configuredProtocols(key, fields[1:]) {
				out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Protocol: name, Library: "tls-config"})
			}
		case cipherDirectives[key]:
			for _, tok := range fields[1:] {
				for _, c := range splitList(tok) {
					c = strings.TrimSpace(c)
					if c == "" || strings.HasPrefix(c, "!") || strings.HasPrefix(c, "-") || strings.HasPrefix(c, "@") {
						continue // OpenSSL exclusion/macro, not a cipher in use
					}
					out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Cipher: c, Library: "tls-config"})
				}
			}
		}
	}
	return out
}

// configuredProtocols evaluates one declaration in order. Apache mod_ssl uses
// + and - to modify the enabled set, including the all macro. Reporting a
// removed version as enabled would produce a false weak-crypto finding.
func configuredProtocols(directive string, tokens []string) []string {
	var enabled []string
	for _, tok := range tokens {
		for _, raw := range splitList(tok) {
			operation := byte('+')
			if directive == "sslprotocol" && len(raw) > 0 && (raw[0] == '+' || raw[0] == '-') {
				operation, raw = raw[0], raw[1:]
			}
			var names []string
			if directive == "sslprotocol" && strings.EqualFold(raw, "all") {
				// Apache's documented all macro includes every version available
				// to its OpenSSL build. This is the declared maximum; the live
				// endpoint scan determines what can actually negotiate.
				names = []string{"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
			} else if name := normalizeProtocol(raw); name != "" {
				names = []string{name}
			}
			for _, name := range names {
				if operation == '-' {
					for i, current := range enabled {
						if current == name {
							enabled = append(enabled[:i], enabled[i+1:]...)
							break
						}
					}
					continue
				}
				present := false
				for _, current := range enabled {
					if current == name {
						present = true
						break
					}
				}
				if !present {
					enabled = append(enabled, name)
				}
			}
		}
	}
	return enabled
}

// splitList splits an OpenSSL/nginx cipher or protocol list on ':' and ','.
func splitList(tok string) []string {
	return strings.FieldsFunc(tok, func(r rune) bool { return r == ':' || r == ',' })
}

// normalizeProtocol maps a declared protocol token to a canonical version name,
// or "" if it is not a recognized concrete version.
func normalizeProtocol(p string) string {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "TLSV1", "TLSV1.0":
		return "TLSv1.0"
	case "TLSV1.1":
		return "TLSv1.1"
	case "TLSV1.2":
		return "TLSv1.2"
	case "TLSV1.3":
		return "TLSv1.3"
	case "SSLV3", "SSLV3.0":
		return "SSLv3"
	default:
		return ""
	}
}
