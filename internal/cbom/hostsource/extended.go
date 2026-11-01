// SPDX-License-Identifier: BUSL-1.1

package hostsource

import (
	"bufio"
	"bytes"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
)

// Host configuration beyond nginx, Apache and sshd (X2): HAProxy, Envoy, the
// OpenSSL configuration file and Java's java.security. Each reports the lowest
// protocol version a statement explicitly allows, one finding per statement,
// so a HAProxy file that allows TLS 1.0 raises one weak TLSv1.0 finding. A
// version a product would only reach through its built-in default is not
// claimed: defaults differ between releases, and the live endpoint scan
// answers what actually negotiates.

// protocolOrder is the order versions are compared in.
var protocolOrder = []string{"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

func parseExtended(path string, data []byte) []cbom.Finding {
	var out []cbom.Finding
	lines := logicalLines(data)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch {
		case key == "ssl-default-bind-options" || key == "ssl-default-server-options":
			out = append(out, haproxyProtocol(path, fields[1:])...)
		case (key == "bind" || key == "server" || key == "default-server") && hasToken(fields, "ssl"):
			out = append(out, haproxyProtocol(path, fields[1:])...)
			out = append(out, haproxyCiphers(path, fields[1:])...)
		case key == "ssl-default-bind-ciphers" || key == "ssl-default-bind-ciphersuites" ||
			key == "ssl-default-server-ciphers" || key == "ssl-default-server-ciphersuites":
			out = append(out, cipherFindings(path, "haproxy", strings.Join(fields[1:], ""))...)
		case key == "tls_minimum_protocol_version:" && len(fields) > 1:
			if name := normalizeEnvoyProtocol(fields[1]); name != "" {
				out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Protocol: name, Library: "envoy"})
			}
		case key == "cipher_suites:":
			items, consumed := yamlList(lines, i, strings.Join(fields[1:], " "))
			i += consumed
			for _, item := range items {
				out = append(out, cipherFindings(path, "envoy", item)...)
			}
		}
		// key=value forms: OpenSSL configuration and java.security.
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "MinProtocol":
			if p := normalizeProtocol(strings.TrimSpace(value)); p != "" {
				out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Protocol: p, Library: "openssl-config"})
			}
		case "jdk.tls.disabledAlgorithms":
			out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Protocol: javaLowestEnabled(value), Library: "java-security"})
		}
	}
	return out
}

// logicalLines splits a file into trimmed, non-comment lines, joining a line
// that ends in a backslash with the next (java.security and Apache style).
func logicalLines(data []byte) []string {
	var out []string
	var pending strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), int(DefaultMaxFileBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if pending.Len() == 0 && (line == "" || strings.HasPrefix(line, "#")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			pending.WriteString(strings.TrimSuffix(line, "\\"))
			pending.WriteString(" ")
			continue
		}
		pending.WriteString(line)
		out = append(out, strings.TrimSpace(pending.String()))
		pending.Reset()
	}
	if pending.Len() > 0 {
		out = append(out, strings.TrimSpace(pending.String()))
	}
	return out
}

func hasToken(fields []string, token string) bool {
	for _, f := range fields {
		if strings.EqualFold(f, token) {
			return true
		}
	}
	return false
}

// haproxyProtocol reports the lowest version one HAProxy statement explicitly
// allows: a force-* option pins it, otherwise ssl-min-ver sets it.
func haproxyProtocol(path string, options []string) []cbom.Finding {
	lowest := ""
	for i, option := range options {
		option = strings.ToLower(option)
		switch {
		case strings.HasPrefix(option, "force-"):
			if p := haproxyVersion(strings.TrimPrefix(option, "force-")); p != "" {
				lowest = p
			}
		case option == "ssl-min-ver" && i+1 < len(options) && lowest == "":
			lowest = normalizeProtocol(options[i+1])
		}
	}
	if lowest == "" {
		return nil
	}
	return []cbom.Finding{{Kind: cbom.AssetHostConfig, Location: path, Protocol: lowest, Library: "haproxy"}}
}

func haproxyCiphers(path string, options []string) []cbom.Finding {
	var out []cbom.Finding
	for i, option := range options {
		if (strings.EqualFold(option, "ciphers") || strings.EqualFold(option, "ciphersuites")) && i+1 < len(options) {
			out = append(out, cipherFindings(path, "haproxy", options[i+1])...)
		}
	}
	return out
}

// haproxyVersion maps HAProxy's sslv3/tlsv10/tlsv11/tlsv12/tlsv13 tokens.
func haproxyVersion(token string) string {
	switch token {
	case "sslv3":
		return "SSLv3"
	case "tlsv10":
		return "TLSv1.0"
	case "tlsv11":
		return "TLSv1.1"
	case "tlsv12":
		return "TLSv1.2"
	case "tlsv13":
		return "TLSv1.3"
	}
	return ""
}

// normalizeEnvoyProtocol maps Envoy's TLSv1_0..TLSv1_3; TLS_AUTO claims nothing.
func normalizeEnvoyProtocol(v string) string {
	return normalizeProtocol(strings.ReplaceAll(strings.Trim(v, `"'`), "_", "."))
}

// javaLowestEnabled reads jdk.tls.disabledAlgorithms and returns the lowest
// TLS version it leaves enabled.
func javaLowestEnabled(value string) string {
	disabled := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		words := strings.Fields(item)
		if len(words) == 0 {
			continue
		}
		if p := normalizeProtocol(words[0]); p != "" {
			disabled[p] = true
		}
	}
	for _, p := range protocolOrder[1:] {
		if !disabled[p] {
			return p
		}
	}
	return "TLSv1.3"
}

func cipherFindings(path, library, list string) []cbom.Finding {
	var out []cbom.Finding
	for _, c := range splitList(strings.Trim(list, `"'[] `)) {
		c = strings.Trim(strings.TrimSpace(c), `"'`)
		if c == "" || strings.HasPrefix(c, "!") || strings.HasPrefix(c, "-") || strings.HasPrefix(c, "@") {
			continue
		}
		out = append(out, cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Cipher: c, Library: library})
	}
	return out
}

// yamlList reads an Envoy list: inline ([a, b]) or the "- item" lines that
// follow the key. It returns the items and how many following lines it read.
func yamlList(lines []string, at int, inline string) ([]string, int) {
	if strings.HasPrefix(inline, "[") {
		return []string{inline}, 0
	}
	var items []string
	consumed := 0
	for j := at + 1; j < len(lines) && strings.HasPrefix(lines[j], "- "); j++ {
		items = append(items, strings.TrimSpace(strings.TrimPrefix(lines[j], "- ")))
		consumed++
	}
	return items, consumed
}
