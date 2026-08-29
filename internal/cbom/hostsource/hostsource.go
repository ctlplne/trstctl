// SPDX-License-Identifier: MPL-2.0

// Package hostsource is a CBOM source that reads host TLS configuration files
// (nginx, Apache, sshd-style) and reports the protocol versions and cipher
// suites they declare in use — read-only, non-invasive file reads (F52).
package hostsource

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
)

// Source scans a set of config files or globs.
type Source struct {
	paths []string
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

// Name identifies the source.
func (s *Source) Name() string { return "host-config" }

var protocolDirectives = map[string]bool{"ssl_protocols": true, "sslprotocol": true, "protocols": true}
var cipherDirectives = map[string]bool{"ssl_ciphers": true, "sslciphersuite": true, "ciphers": true}

// Scan reads each config file and reports the protocols and ciphers it declares.
// Missing or unreadable files are skipped.
func (s *Source) Scan(_ context.Context) ([]cbom.Finding, error) {
	var out []cbom.Finding
	paths, failures := expandGlobs(s.paths, DefaultMaxFiles)
	for _, path := range paths {
		data, err := readBounded(path, DefaultMaxFileBytes)
		if err != nil {
			failures++
			continue
		}
		out = append(out, parseConfig(path, data)...)
	}
	if failures > 0 {
		return out, &cbom.PartialScanError{Failures: failures, Err: errors.New("one or more CBOM host config selectors could not be read within safety limits")}
	}
	return out, nil
}

func readBounded(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- an authorized, previewed discovery selector; the read is size-bounded below (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("host config exceeds CBOM read limit")
	}
	return data, nil
}

func parseConfig(path string, data []byte) []cbom.Finding {
	var out []cbom.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	// readBounded already limits the entire file to 1 MiB. Let Scanner accept a
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
			for _, tok := range fields[1:] {
				for _, p := range splitList(tok) {
					if name := normalizeProtocol(p); name != "" {
						out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Protocol: name, Library: "tls-config"})
					}
				}
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

func expandGlobs(paths []string, maxFiles int) ([]string, int) {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(paths))
	failures := 0
	for _, p := range paths {
		matches, err := filepath.Glob(p)
		if err != nil {
			failures++
			continue
		}
		if len(matches) == 0 {
			failures++
			continue
		}
		sort.Strings(matches)
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			if len(out) == maxFiles {
				failures++
				return out, failures
			}
			seen[match] = struct{}{}
			out = append(out, match)
		}
	}
	return out, failures
}
