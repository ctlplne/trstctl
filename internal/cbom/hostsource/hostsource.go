// Package hostsource is a CBOM source that reads host TLS configuration files
// (nginx, Apache, sshd-style) and reports the protocol versions and cipher
// suites they declare in use — read-only, non-invasive file reads (F52).
package hostsource

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
)

// Source scans a set of config files or globs.
type Source struct {
	paths []string
}

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
	for _, path := range expandGlobs(s.paths) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		out = append(out, parseConfig(path, data)...)
	}
	return out, nil
}

func parseConfig(path string, data []byte) []cbom.Finding {
	var out []cbom.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
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

func expandGlobs(paths []string) []string {
	var out []string
	for _, p := range paths {
		matches, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		out = append(out, matches...)
	}
	return out
}
