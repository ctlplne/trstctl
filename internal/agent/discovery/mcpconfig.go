// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/decoy"
	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// MCP client configuration (P7). Desktop assistants and IDEs list the MCP
// servers they start or call in JSON configuration files, and some in TOML or
// YAML (P7-L1). This source finds those files under operator-configured roots
// by their format — an "mcpServers" object, or a "servers" object at the top
// level or under "mcp" whose entries carry a command or a URL; in TOML,
// [mcp_servers.<name>] tables; in YAML, an mcpServers, mcp_servers or servers
// mapping or sequence of named entries — never by product, and reports each
// configured server: its transport, the program it starts or the host it
// calls, and whether its configuration carries a static credential, named by
// field. A credential's value is never reported, hashed or kept: values are
// classified as bytes and the file's bytes are wiped once read.

// SourceMCPClientConfig is the agent inventory source for MCP client
// configuration files; FindingKindMCPServer is the kind of each server found.
const (
	SourceMCPClientConfig = "mcp-client-config"
	FindingKindMCPServer  = "mcp_server"
	maxMCPConfigFileSize  = 1 << 20
	maxMCPConfigDepth     = 8
)

// MCPServerFound is one MCP server a client configuration names.
type MCPServerFound struct {
	ConfigPath string
	// Format is the object that lists the server: mcpServers, servers or
	// mcp.servers.
	Format    string
	Name      string
	Transport string // stdio, http, sse, websocket or unknown
	// Command is the base name of the program a stdio server starts.
	Command string
	Args    int
	// URLHost is scheme://host[:port] of a remote server: never its path,
	// query or user information.
	URLHost string
	// StaticCredential is a credential written into the configuration as a
	// literal rather than a reference; CredentialFields names where.
	StaticCredential bool
	CredentialFields []string
	// CredentialValidity is each checked credential field's verdict (P14-L2),
	// when the source has a credential checker; never the value.
	CredentialValidity []CredentialVerdict
	// Fingerprint is over the non-secret description, so a rescan of an
	// unchanged configuration finds the same server.
	Fingerprint string
}

// MCPClientConfigSource walks roots for MCP client configuration files.
type MCPClientConfigSource struct {
	roots   []string
	maxSize int64
	checker CredentialChecker
}

// CredentialChecker checks a static credential where the agent found it
// (P14-L2): it names the provider and the verdict, or reports false when no
// check covers the value or its provider is not enabled. It must not keep the
// value.
type CredentialChecker interface {
	CheckCredential(ctx context.Context, value []byte) (provider, state, detail string, ok bool)
}

// CredentialVerdict is one checked credential field's verdict: the field as
// reported, the provider, valid, invalid, unknown or unchecked, and the
// provider's detail (a user or workspace, never the value).
type CredentialVerdict struct {
	Field, Provider, State, Detail string
}

// NewMCPClientConfigSource discovers MCP client configuration under roots.
func NewMCPClientConfigSource(roots ...string) *MCPClientConfigSource {
	return &MCPClientConfigSource{roots: roots, maxSize: maxMCPConfigFileSize}
}

// WithCredentialChecker checks each static credential found with c while the
// file's bytes are still held (P14-L2); only the verdict is kept.
func (s *MCPClientConfigSource) WithCredentialChecker(c CredentialChecker) *MCPClientConfigSource {
	s.checker = c
	return s
}

// Kind names the source.
func (s *MCPClientConfigSource) Kind() string { return SourceMCPClientConfig }

// skippedMCPDirs are trees that hold packages and history, never a client's
// own configuration.
var skippedMCPDirs = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "__pycache__": true}

// Discover returns every MCP server the configuration files under the roots
// name, in path and name order.
func (s *MCPClientConfigSource) Discover(ctx context.Context) ([]MCPServerFound, error) {
	var out []MCPServerFound
	for _, root := range s.roots {
		root = filepath.Clean(root)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if path != root && (skippedMCPDirs[d.Name()] || strings.Count(strings.TrimPrefix(path, root), string(filepath.Separator)) > maxMCPConfigDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !mcpConfigExtension(path) || decoy.Is(path) {
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil || !fi.Mode().IsRegular() || fi.Size() > s.maxSize {
				return nil
			}
			data, rerr := os.ReadFile(path) // #nosec G122 G304 -- the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367)
			if rerr != nil {
				return nil
			}
			out = append(out, parseMCPClientConfig(ctx, path, data, s.checker)...)
			secret.Wipe(data)
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ConfigPath != out[j].ConfigPath {
			return out[i].ConfigPath < out[j].ConfigPath
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// mcpServerEntry keeps every value as raw bytes, so a credential is never
// turned into a string.
type mcpServerEntry struct {
	Command   json.RawMessage            `json:"command"`
	Args      []json.RawMessage          `json:"args"`
	Env       map[string]json.RawMessage `json:"env"`
	URL       json.RawMessage            `json:"url"`
	ServerURL json.RawMessage            `json:"serverUrl"`
	Headers   map[string]json.RawMessage `json:"headers"`
	Type      json.RawMessage            `json:"type"`
	Transport json.RawMessage            `json:"transport"`
}

func (e *mcpServerEntry) wipe() {
	wipeRaw := func(raw json.RawMessage) { secret.Wipe(raw) }
	wipeRaw(e.Command)
	wipeRaw(e.URL)
	wipeRaw(e.ServerURL)
	for _, a := range e.Args {
		wipeRaw(a)
	}
	for _, v := range e.Env {
		wipeRaw(v)
	}
	for _, v := range e.Headers {
		wipeRaw(v)
	}
}

// mcpConfigExtension reports whether a file may be MCP client configuration:
// JSON, or TOML or YAML (P7-L1).
func mcpConfigExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".toml", ".yaml", ".yml":
		return true
	}
	return false
}

// parseMCPClientConfig reads one file's servers; a file in another format,
// or one that does not parse, names none. With a checker (P14-L2), each
// server's static credentials are checked before the entry is wiped.
func parseMCPClientConfig(ctx context.Context, path string, data []byte, checker CredentialChecker) []MCPServerFound {
	var formatted []mcpFormatServer
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		pairs, ok := parseTOMLPairs(data)
		if !ok {
			return nil
		}
		formatted = tomlMCPServers(pairs)
		for i := range pairs {
			pairs[i].val.wipe()
		}
	case ".yaml", ".yml":
		root := parseYAMLTree(data)
		if root == nil {
			return nil
		}
		formatted = yamlMCPServers(root)
		root.wipe()
	default:
		return parseMCPClientJSON(ctx, path, data, checker)
	}
	var out []MCPServerFound
	for i := range formatted {
		f := &formatted[i]
		if found, ok := describeMCPServer(path, f.format, f.name, &f.entry); ok {
			if checker != nil && found.StaticCredential {
				found.CredentialValidity = checkMCPCredentials(ctx, checker, &f.entry)
			}
			out = append(out, found)
		}
		f.entry.wipe()
	}
	return out
}

// parseMCPClientJSON reads a JSON (or JSON-with-comments) file's servers.
func parseMCPClientJSON(ctx context.Context, path string, data []byte, checker CredentialChecker) []MCPServerFound {
	clean := stripJSONC(data)
	defer secret.Wipe(clean)
	var top map[string]json.RawMessage
	if json.Unmarshal(clean, &top) != nil {
		return nil
	}
	defer func() {
		for _, v := range top {
			secret.Wipe(v)
		}
	}()
	var out []MCPServerFound
	add := func(format string, raw json.RawMessage) {
		var servers map[string]json.RawMessage
		if json.Unmarshal(raw, &servers) != nil {
			return
		}
		for name, entryRaw := range servers {
			var entry mcpServerEntry
			if json.Unmarshal(entryRaw, &entry) == nil {
				if f, ok := describeMCPServer(path, format, name, &entry); ok {
					if checker != nil && f.StaticCredential {
						f.CredentialValidity = checkMCPCredentials(ctx, checker, &entry)
					}
					out = append(out, f)
				}
				entry.wipe()
			}
			secret.Wipe(entryRaw)
		}
	}
	if raw, ok := top["mcpServers"]; ok {
		add("mcpServers", raw)
	}
	if raw, ok := top["servers"]; ok {
		add("servers", raw)
	}
	if raw, ok := top["mcp"]; ok {
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) == nil {
			if servers, ok := nested["servers"]; ok {
				add("mcp.servers", servers)
			}
			for _, v := range nested {
				secret.Wipe(v)
			}
		}
	}
	return out
}

// describeMCPServer describes one server entry; an entry with neither a
// command nor a URL is not a server.
func describeMCPServer(path, format, name string, e *mcpServerEntry) (MCPServerFound, bool) {
	command, hasCommand := rawJSONString(e.Command)
	urlRaw := e.URL
	if len(bytes.TrimSpace(urlRaw)) == 0 || string(bytes.TrimSpace(urlRaw)) == "null" {
		urlRaw = e.ServerURL
	}
	urlBytes, hasURL := rawJSONBytes(urlRaw)
	if !hasCommand && !hasURL {
		return MCPServerFound{}, false
	}
	f := MCPServerFound{ConfigPath: path, Format: format, Name: name, Args: len(e.Args)}
	declared := ""
	for _, raw := range []json.RawMessage{e.Type, e.Transport} {
		if s, ok := rawJSONString(raw); ok && declared == "" {
			declared = strings.ToLower(strings.TrimSpace(s))
		}
	}
	switch {
	case declared == "stdio":
		f.Transport = "stdio"
	case declared == "sse":
		f.Transport = "sse"
	case declared == "http" || declared == "streamable-http" || declared == "streamablehttp":
		f.Transport = "http"
	case declared == "ws" || declared == "websocket":
		f.Transport = "websocket"
	case hasCommand:
		f.Transport = "stdio"
	case hasURL:
		f.Transport = "http"
	default:
		f.Transport = "unknown"
	}
	if hasCommand {
		f.Command = filepath.Base(strings.TrimSpace(command))
	}
	var fields []string
	if hasURL {
		host, credential := classifyMCPURL(urlBytes)
		f.URLHost = host
		fields = append(fields, credential...)
	}
	for envName, raw := range e.Env {
		if value, ok := rawJSONBytes(raw); ok && literalCredential(envName, value) {
			fields = append(fields, "env:"+fieldName(envName))
		}
	}
	for header, raw := range e.Headers {
		if value, ok := rawJSONBytes(raw); ok && credentialHeader(header) && literalValue(value) {
			fields = append(fields, "header:"+fieldName(header))
		}
	}
	fields = append(fields, argCredentials(e.Args)...)
	sort.Strings(fields)
	f.CredentialFields = fields
	f.StaticCredential = len(fields) > 0
	f.Fingerprint = cryptoboundary.SHA256Hex([]byte(strings.Join([]string{path, format, name, f.Transport, f.Command,
		strconv.Itoa(f.Args), f.URLHost, strconv.FormatBool(f.StaticCredential), strings.Join(fields, ",")}, "\x00")))
	return f, true
}

// checkMCPCredentials checks the literal credentials describeMCPServer names
// (environment entries, headers and arguments; a URL's query is not a token
// a provider can check), each under the same field name, in field order.
func checkMCPCredentials(ctx context.Context, checker CredentialChecker, e *mcpServerEntry) []CredentialVerdict {
	var out []CredentialVerdict
	check := func(field string, value []byte) {
		if provider, state, detail, ok := checker.CheckCredential(ctx, value); ok {
			out = append(out, CredentialVerdict{Field: field, Provider: provider, State: state, Detail: detail})
		}
	}
	for envName, raw := range e.Env {
		if value, ok := rawJSONBytes(raw); ok && literalCredential(envName, value) {
			check("env:"+fieldName(envName), value)
		}
	}
	for header, raw := range e.Headers {
		if value, ok := rawJSONBytes(raw); ok && credentialHeader(header) && literalValue(value) {
			check("header:"+fieldName(header), value)
		}
	}
	for i := 0; i < len(e.Args); i++ {
		arg, ok := rawJSONBytes(e.Args[i])
		if !ok {
			continue
		}
		flagPart, valuePart, hasEq := bytes.Cut(arg, []byte("="))
		name := string(flagPart)
		switch {
		case credentialFlag.MatchString(name) && hasEq:
			if literalValue(valuePart) {
				check("arg:"+fieldName(name), valuePart)
			}
		case credentialFlag.MatchString(name) && i+1 < len(e.Args):
			if next, ok := rawJSONBytes(e.Args[i+1]); ok && literalValue(next) && !bytes.HasPrefix(next, []byte("-")) {
				check("arg:"+fieldName(name), next)
				i++
			}
		case tokenShaped(arg):
			check("arg:#"+strconv.Itoa(i), arg)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// rawJSONString reads a JSON string that is not a secret (a command, a type).
func rawJSONString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

// rawJSONBytes returns a JSON string's contents as bytes inside raw, without
// unescaping it into a new string; a value that is not a string is none.
func rawJSONBytes(raw json.RawMessage) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	inner := raw[1 : len(raw)-1]
	return inner, len(bytes.TrimSpace(inner)) > 0
}

var fieldNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.:#-]`)

// fieldName is a field's name as reported: names only, at most 80 characters.
func fieldName(name string) string {
	name = fieldNameUnsafe.ReplaceAllString(name, "_")
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

var secretLikeName = regexp.MustCompile(`(?i)(token|secret|passw|pwd|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential|bearer|cookie|(^|[_-])(auth|session|pat)([_-]|$))`)

// referencePrefixes mark a value that names where a credential lives rather
// than holding it.
var referencePrefixes = [][]byte{[]byte("${"), []byte("$("), []byte("env:"), []byte("secret://"), []byte("op://"), []byte("vault:")}

// literalValue reports whether a value is written out rather than referenced.
func literalValue(value []byte) bool {
	v := bytes.TrimSpace(value)
	if len(v) == 0 {
		return false
	}
	for _, prefix := range referencePrefixes {
		if bytes.HasPrefix(v, prefix) {
			return false
		}
	}
	// $NAME refers to the environment.
	if v[0] == '$' && len(v) > 1 && (v[1] == '_' || (v[1] >= 'A' && v[1] <= 'Z')) && bytes.IndexByte(v, ' ') < 0 {
		return false
	}
	return true
}

// tokenPrefixes are well-known prefixes of issued API tokens.
var tokenPrefixes = [][]byte{[]byte("ghp_"), []byte("gho_"), []byte("ghs_"), []byte("github_pat_"), []byte("glpat-"),
	[]byte("xoxb-"), []byte("xoxp-"), []byte("sk-"), []byte("sk_live_"), []byte("rk_live_"), []byte("AKIA"), []byte("ASIA"),
	[]byte("AIza"), []byte("ya29."), []byte("eyJ")}

// tokenShaped reports whether a value looks like an issued token: a known
// prefix, or a long run of mixed letters and digits with no spaces.
func tokenShaped(value []byte) bool {
	v := bytes.TrimSpace(value)
	for _, prefix := range tokenPrefixes {
		if bytes.HasPrefix(v, prefix) && len(v) > len(prefix)+8 {
			return true
		}
	}
	if len(v) < 24 || bytes.ContainsAny(v, " /\\") {
		return false
	}
	var upper, lower, digit bool
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return digit && (upper || lower) && (upper && lower || len(v) >= 32)
}

// literalCredential reports whether an environment entry carries a credential
// as a literal: a secret-like name or a token-shaped value, not a reference.
func literalCredential(name string, value []byte) bool {
	if !literalValue(value) {
		return false
	}
	return secretLikeName.MatchString(name) || tokenShaped(value)
}

func credentialHeader(name string) bool {
	n := strings.ToLower(name)
	return n == "authorization" || n == "proxy-authorization" || n == "cookie" || secretLikeName.MatchString(n)
}

var credentialFlag = regexp.MustCompile(`(?i)^--?(token|access[-_]?token|api[-_]?key|apikey|key|secret|client[-_]?secret|password|passwd|pass|auth|bearer|pat)$`)

// argCredentials names the arguments that carry a credential: a credential
// flag followed by (or set to) a literal, or a token-shaped argument.
func argCredentials(args []json.RawMessage) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		arg, ok := rawJSONBytes(args[i])
		if !ok {
			continue
		}
		flagPart, valuePart, hasEq := bytes.Cut(arg, []byte("="))
		name := string(flagPart)
		switch {
		case credentialFlag.MatchString(name) && hasEq:
			if literalValue(valuePart) {
				out = append(out, "arg:"+fieldName(name))
			}
		case credentialFlag.MatchString(name) && i+1 < len(args):
			if next, ok := rawJSONBytes(args[i+1]); ok && literalValue(next) && !bytes.HasPrefix(next, []byte("-")) {
				out = append(out, "arg:"+fieldName(name))
				i++
			}
		case tokenShaped(arg):
			out = append(out, "arg:#"+strconv.Itoa(i))
		}
	}
	return out
}

var credentialQueryParam = regexp.MustCompile(`(?i)^(token|access_token|api_key|apikey|key|secret|password|auth|sig|signature|code)$`)

// classifyMCPURL returns scheme://host[:port] of a server URL and the parts of
// it that carry a credential (user information, credential query parameters),
// reading the URL's bytes without building strings of them.
func classifyMCPURL(u []byte) (string, []string) {
	u = bytes.TrimSpace(u)
	scheme, rest, ok := bytes.Cut(u, []byte("://"))
	if !ok {
		return "", nil
	}
	end := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority, tail := rest[:end], rest[end:]
	var fields []string
	if at := bytes.LastIndexByte(authority, '@'); at >= 0 {
		if bytes.IndexByte(authority[:at], ':') >= 0 {
			fields = append(fields, "url:userinfo")
		}
		authority = authority[at+1:]
	}
	if q := bytes.IndexByte(tail, '?'); q >= 0 {
		query := tail[q+1:]
		if h := bytes.IndexByte(query, '#'); h >= 0 {
			query = query[:h]
		}
		for _, pair := range bytes.Split(query, []byte("&")) {
			key, value, _ := bytes.Cut(pair, []byte("="))
			if credentialQueryParam.Match(key) && literalValue(value) {
				fields = append(fields, "url:query:"+fieldName(string(key)))
			}
		}
	}
	host := strings.ToLower(string(scheme)) + "://" + strings.ToLower(string(authority))
	if len(host) > 200 {
		host = host[:200]
	}
	return host, fields
}

// stripJSONC removes // and /* */ comments, then trailing commas, outside
// strings, so configuration written as JSON with comments parses; it returns
// a new buffer the caller wipes.
func stripJSONC(in []byte) []byte {
	noComments := make([]byte, 0, len(in))
	inString, escaped := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			noComments = append(noComments, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			noComments = append(noComments, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				noComments = append(noComments, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i++
		default:
			noComments = append(noComments, c)
		}
	}
	out := make([]byte, 0, len(noComments))
	inString, escaped = false, false
	for i, c := range noComments {
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
		}
		if c == ',' {
			j := i + 1
			for j < len(noComments) && (noComments[j] == ' ' || noComments[j] == '\t' || noComments[j] == '\n' || noComments[j] == '\r') {
				j++
			}
			if j < len(noComments) && (noComments[j] == '}' || noComments[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	secret.Wipe(noComments)
	return out
}

// MCPInventoryFinding is one server as the agent reports it: identifiers and
// non-secret metadata only.
type MCPInventoryFinding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]string
}

// MCPInventoryFindings describes found servers for the inventory report. A
// server configured with a static credential is rated higher.
func MCPInventoryFindings(found []MCPServerFound) []MCPInventoryFinding {
	out := make([]MCPInventoryFinding, 0, len(found))
	for _, f := range found {
		risk := 30
		if f.StaticCredential {
			risk = 80
		}
		// P14-L2: the verdicts are reported beside the fields; the risk stays
		// the static credential's, so a later verdict does not re-rate the
		// finding.
		var states, details []string
		for _, v := range f.CredentialValidity {
			states = append(states, v.Field+"="+v.Provider+":"+v.State)
			details = append(details, v.Field+": "+v.Detail)
		}
		meta := map[string]string{
			"config_path": f.ConfigPath, "format": f.Format, "server_name": f.Name, "transport": f.Transport,
			"args": strconv.Itoa(f.Args), "static_credential": strconv.FormatBool(f.StaticCredential),
			"credential_values": "not_collected",
		}
		if f.Command != "" {
			meta["command"] = f.Command
		}
		if f.URLHost != "" {
			meta["url_host"] = f.URLHost
		}
		if len(f.CredentialFields) > 0 {
			meta["credential_fields"] = strings.Join(f.CredentialFields, ",")
		}
		if v := joinWithin(states, ",", 512); v != "" {
			meta["credential_validity"] = v
		}
		if v := joinWithin(details, "; ", 512); v != "" {
			meta["credential_validity_detail"] = v
		}
		out = append(out, MCPInventoryFinding{Ref: f.ConfigPath + "#" + f.Name,
			Provenance: SourceMCPClientConfig + ":" + f.ConfigPath, Fingerprint: f.Fingerprint, RiskScore: risk, Metadata: meta})
	}
	return out
}

// joinWithin joins whole parts while they fit the 512 characters a metadata
// value may hold at the control plane; parts past the limit are left out
// rather than cut.
func joinWithin(parts []string, sep string, limit int) string {
	out := ""
	for _, p := range parts {
		next := p
		if out != "" {
			next = out + sep + p
		}
		if len(next) > limit {
			break
		}
		out = next
	}
	return out
}

// MCPInventoryDigest is over every server found and each checked credential's
// verdict, so an unchanged rescan has the same digest and the agent sends
// nothing, and a token revoked since the last report is reported again.
func MCPInventoryDigest(found []MCPServerFound) string {
	parts := make([]string, 0, len(found))
	for _, f := range found {
		part := f.ConfigPath + "#" + f.Name + "=" + f.Fingerprint
		for _, v := range f.CredentialValidity {
			part += "|" + v.Field + "=" + v.Provider + ":" + v.State
		}
		parts = append(parts, part)
	}
	sort.Strings(parts)
	return cryptoboundary.SHA256Hex([]byte(strings.Join(parts, "\n")))
}
