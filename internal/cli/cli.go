// SPDX-License-Identifier: MPL-2.0

// Package cli implements trstctl's command-line interface: a thin, scriptable
// client at parity with the REST API (F11). Every core API operation has a
// command; output is machine-readable JSON; authentication is a CI-friendly API
// token. The command set is data-driven (see command.go) and proven complete by
// a parity test against the API route table.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secretscli"
)

// Env carries the CLI's connection configuration and an optional injected HTTP
// client (for tests). Flags override these.
type Env struct {
	Server         string
	Token          string
	Tenant         string
	CAFile         string
	IdempotencyKey string
	HTTPClient     *http.Client
}

// Run parses args, performs the requested API operation, prints the JSON
// response to stdout, and returns a process exit code: 0 on success, 1 on a
// request/response error, 2 on a usage error.
func Run(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer) int {
	if commandHelpRequested(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("trstctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", env.Server, "control-plane base URL (env TRSTCTL_SERVER)")
	token := fs.String("token", env.Token, "API token (env TRSTCTL_TOKEN)")
	tenant := fs.String("tenant", env.Tenant, "tenant id for header auth (env TRSTCTL_TENANT)")
	caFile := fs.String("ca-file", env.CAFile, "PEM CA bundle for control-plane TLS (env TRSTCTL_CA_FILE)")
	idem := fs.String("idempotency-key", env.IdempotencyKey, "Idempotency-Key for a mutation (generated if unset)")
	globalForce := fs.Bool("force", false, "allow a destructive command")
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	if rest[0] == "version" {
		_, _ = fmt.Fprintln(stdout, buildinfo.String("trstctl"))
		return 0
	}
	if rest[0] == "run" {
		return runWithSecrets(ctx, rest[1:], env, stdin, stdout, stderr, *server, *token, *tenant, *caFile)
	}
	if len(rest) >= 2 && hasPrefix(rest, []string{"audit", "verify"}) {
		if commandHelpRequested(rest[2:]) {
			auditVerifyUsage(stdout)
			return 0
		}
		return runAuditVerify(rest[2:], stdin, stdout, stderr)
	}
	if len(rest) >= 3 && hasPrefix(rest, []string{"secrets", "scans", "staged-diff"}) {
		if commandHelpRequested(rest[3:]) {
			secretScanStagedDiffUsage(stdout)
			return 0
		}
		return runSecretScanStagedDiff(ctx, rest[3:], stdout, stderr)
	}
	if len(rest) >= 4 && hasPrefix(rest, []string{"secrets", "scans", "pre-commit", "install"}) {
		if commandHelpRequested(rest[4:]) {
			secretScanPreCommitInstallUsage(stdout)
			return 0
		}
		return runSecretScanPreCommitInstall(ctx, rest[4:], stdout, stderr)
	}

	cmd, cmdArgs, ok := matchCommand(rest)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "error: unknown command %q (try 'trstctl version' or --help)\n", strings.Join(rest, " "))
		return 2
	}
	if commandHelpRequested(cmdArgs) {
		commandUsage(stdout, cmd)
		return 0
	}
	if *server == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or TRSTCTL_SERVER) is required")
		return 2
	}

	path, query, body, force, err := buildRequest(cmd, cmdArgs, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if cmd.Destructive() && !*globalForce && !force {
		_, _ = fmt.Fprintf(stderr, "error: %s is destructive; rerun with --force after reviewing the command-specific help\n", strings.Join(cmd.Name, " "))
		return 2
	}

	// Mutations require an Idempotency-Key (AN-5); generate a fresh one per
	// invocation unless the caller supplies a stable key for safe retries.
	idemKey := ""
	if cmd.Method != http.MethodGet && !cmd.ReadOnly {
		idemKey = *idem
		if idemKey == "" {
			idemKey = generateIdempotencyKey()
		}
	}

	client, err := httpClientForEnv(env, *caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: CA file: %v\n", err)
		return 2
	}
	status, respBody, err := do(ctx, client, *server, cmd.Method, path, query, body, *token, *tenant, idemKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	writeJSON(stdout, respBody)
	if status/100 != 2 {
		_, _ = fmt.Fprintf(stderr, "error: server returned status %d\n", status)
		return 1
	}
	return 0
}

func httpClientForEnv(env Env, caFile string) (*http.Client, error) {
	if env.HTTPClient != nil {
		return env.HTTPClient, nil
	}
	if caFile == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- the operator explicitly names the public trust-bundle path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", caFile, err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, nil
}

func runWithSecrets(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	fs := flag.NewFlagSet("trstctl run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var secretFlags runSecretFlags
	fs.Var(&secretFlags, "secret", "secret mapping in ENV=secret/path form (repeatable)")
	fs.Var(&secretFlags, "env", "alias for --secret")
	resolve := fs.Bool("resolve", false, "resolve ${secret.path} references before injection")
	fs.Usage = func() { runUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		runUsage(stderr)
		return 2
	}
	if len(secretFlags) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: trstctl run needs at least one --secret ENV=secret/path mapping")
		return 2
	}
	if server == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or TRSTCTL_SERVER) is required")
		return 2
	}

	mappings := make([]runSecretMapping, 0, len(secretFlags))
	seen := map[string]bool{}
	for _, raw := range secretFlags {
		mapping, err := parseRunSecretMapping(raw)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if seen[mapping.EnvVar] {
			_, _ = fmt.Fprintf(stderr, "error: duplicate secret env var %s\n", mapping.EnvVar)
			return 2
		}
		seen[mapping.EnvVar] = true
		mappings = append(mappings, mapping)
	}

	httpClient, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: CA file: %v\n", err)
		return 2
	}
	client := secretAPIClient{
		client:  httpClient,
		server:  server,
		token:   token,
		tenant:  tenant,
		resolve: *resolve,
	}
	runner := secretscli.New(tenant, client, auditsink.Nop{})
	secrets := make(map[string][]byte, len(mappings))
	defer func() {
		for _, value := range secrets {
			secret.Wipe(value)
		}
	}()
	for _, mapping := range mappings {
		value, err := runner.Fetch(ctx, mapping.Path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		secrets[mapping.EnvVar] = value
	}

	if err := runner.InjectIO(ctx, secrets, argv, stdin, stdout, stderr); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

type runSecretFlags []string

func (f *runSecretFlags) String() string { return strings.Join(*f, ",") }

func (f *runSecretFlags) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("--secret requires ENV=secret/path")
	}
	*f = append(*f, value)
	return nil
}

type runSecretMapping struct {
	EnvVar string
	Path   string
}

func parseRunSecretMapping(raw string) (runSecretMapping, error) {
	envVar, path, ok := strings.Cut(strings.TrimSpace(raw), "=")
	envVar = strings.TrimSpace(envVar)
	path = strings.TrimSpace(path)
	if !ok || envVar == "" || path == "" {
		return runSecretMapping{}, fmt.Errorf("--secret must be ENV=secret/path")
	}
	if !validEnvName(envVar) {
		return runSecretMapping{}, fmt.Errorf("invalid environment variable name %q", envVar)
	}
	return runSecretMapping{EnvVar: envVar, Path: path}, nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')
		if !ok || (i == 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

type secretAPIClient struct {
	client  *http.Client
	server  string
	token   string
	tenant  string
	resolve bool
}

func (c secretAPIClient) Fetch(ctx context.Context, path string) ([]byte, error) {
	query := url.Values{}
	if c.resolve {
		query.Set("resolve", "true")
	}
	status, body, err := do(ctx, c.client, c.server, http.MethodGet, secretStorePath(path), query, nil, c.token, c.tenant, "")
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(body)
	if status/100 != 2 {
		return nil, fmt.Errorf("fetch secret %q: server returned status %d", path, status)
	}
	var decoded struct {
		Value secretjson.StringBytes `json:"value"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		secret.Wipe(decoded.Value)
		return nil, fmt.Errorf("fetch secret %q: decode response: %w", path, err)
	}
	return []byte(decoded.Value), nil
}

func (c secretAPIClient) Set(context.Context, string, []byte) error {
	return errors.New("secret API client Set is not used by trstctl run")
}

func secretStorePath(name string) string {
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return "/api/v1/secrets/store/" + strings.Join(parts, "/")
}

// buildRequest resolves the path (substituting path params), query string, and
// request body for a command from its arguments.
func buildRequest(cmd Command, args []string, stdin io.Reader) (path string, query url.Values, body []byte, force bool, err error) {
	positionals, query, bodyFilePath, force, err := splitArgs(args, cmd.Query)
	if err != nil {
		return "", nil, nil, false, err
	}

	if cmd.Body == bodyCypher {
		if len(positionals) == 0 {
			return "", nil, nil, false, fmt.Errorf("%s needs a query argument", strings.Join(cmd.Name, " "))
		}
		body, err = json.Marshal(map[string]string{"query": strings.Join(positionals, " ")})
		if err != nil {
			return "", nil, nil, false, err
		}
		return cmd.Path, query, body, force, nil
	}

	params := cmd.pathParams()
	bodyParams := []string(nil)
	switch cmd.Body {
	case bodyIntentDigest:
		bodyParams = []string{"intent_digest"}
	case bodyIntentDigestReason:
		bodyParams = []string{"intent_digest", "reason"}
	}
	expectedParams := append(append([]string(nil), params...), bodyParams...)
	if len(positionals) != len(expectedParams) {
		return "", nil, nil, false, fmt.Errorf("%s expects %d argument(s) (%s), got %d",
			strings.Join(cmd.Name, " "), len(expectedParams), strings.Join(expectedParams, ", "), len(positionals))
	}
	path = cmd.Path
	for i, p := range params {
		path = strings.Replace(path, "{"+p+"}", url.PathEscape(positionals[i]), 1)
	}

	if cmd.Body == bodyFile || cmd.Body == bodyApprovalFile {
		if bodyFilePath == "" {
			return "", nil, nil, false, fmt.Errorf("%s needs a request body: -f <file> or -f - for stdin", strings.Join(cmd.Name, " "))
		}
		body, err = readBody(bodyFilePath, stdin)
		if err != nil {
			return "", nil, nil, false, err
		}
		if cmd.Body == bodyApprovalFile {
			if err := validateExactApprovalBody(cmd, body); err != nil {
				return "", nil, nil, false, err
			}
		}
	} else if cmd.Body == bodyOptionalFile && bodyFilePath != "" {
		body, err = readBody(bodyFilePath, stdin)
		if err != nil {
			return "", nil, nil, false, err
		}
	} else if cmd.Body == bodyIntentDigest {
		body, err = json.Marshal(map[string]string{"intent_digest": positionals[len(params)]})
		if err != nil {
			return "", nil, nil, false, err
		}
	} else if cmd.Body == bodyIntentDigestReason {
		body, err = json.Marshal(map[string]string{
			"intent_digest": positionals[len(params)],
			"reason":        positionals[len(params)+1],
		})
		if err != nil {
			return "", nil, nil, false, err
		}
	}
	return path, query, body, force, nil
}

func validateExactApprovalBody(cmd Command, body []byte) error {
	var decision struct {
		Action       string `json:"action"`
		RequestID    string `json:"request_id"`
		IntentDigest string `json:"intent_digest"`
	}
	if err := json.Unmarshal(body, &decision); err != nil {
		return fmt.Errorf("%s request body must be valid JSON: %w", strings.Join(cmd.Name, " "), err)
	}
	if strings.TrimSpace(decision.Action) == "" || strings.TrimSpace(decision.RequestID) == "" || strings.TrimSpace(decision.IntentDigest) == "" {
		return fmt.Errorf("%s request body requires action, request_id, and intent_digest", strings.Join(cmd.Name, " "))
	}
	if cmd.Action != "" && decision.Action != cmd.Action {
		return fmt.Errorf("%s request body action must be %q", strings.Join(cmd.Name, " "), cmd.Action)
	}
	return nil
}

// splitArgs separates positional arguments, recognized query flags, and the -f
// body file from a command's arguments, in any order.
func splitArgs(args, queryNames []string) (positionals []string, query url.Values, bodyFile string, force bool, err error) {
	allowed := map[string]bool{}
	for _, q := range queryNames {
		allowed[q] = true
	}
	query = url.Values{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--file":
			i++
			if i >= len(args) {
				return nil, nil, "", false, fmt.Errorf("-f requires a value")
			}
			bodyFile = args[i]
		case strings.HasPrefix(a, "-f="):
			bodyFile = strings.TrimPrefix(a, "-f=")
		case a == "--force":
			force = true
		case strings.HasPrefix(a, "--force="):
			val := strings.TrimPrefix(a, "--force=")
			if val != "true" {
				return nil, nil, "", false, fmt.Errorf("--force only accepts true when specified with a value")
			}
			force = true
		case strings.HasPrefix(a, "--"):
			name := strings.TrimPrefix(a, "--")
			var val string
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name, val = name[:eq], name[eq+1:]
			} else {
				i++
				if i >= len(args) {
					return nil, nil, "", false, fmt.Errorf("flag --%s requires a value", name)
				}
				val = args[i]
			}
			if !allowed[name] {
				return nil, nil, "", false, fmt.Errorf("unknown flag --%s", name)
			}
			query.Set(name, val)
		default:
			positionals = append(positionals, a)
		}
	}
	return positionals, query, bodyFile, force, nil
}

// readBody reads a request body from a file, or stdin when the path is "-".
func readBody(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path) // #nosec G304 -- operator-passed local file argument on their own command line (CWE-22)
}

// do performs the HTTP request and returns the status and response body.
// generateIdempotencyKey returns a fresh key. It needs uniqueness, not
// unpredictability, so math/rand/v2 (not crypto/*) keeps this outside the crypto
// boundary (AN-3).
func generateIdempotencyKey() string {
	return fmt.Sprintf("cli-%016x%016x", rand.Uint64(), rand.Uint64()) // #nosec G404 -- idempotency-key uniqueness suffix; deliberately outside the AN-3 boundary, not a secret (CWE-338)
}

func do(ctx context.Context, client *http.Client, server, method, path string, query url.Values, body []byte, token, tenant, idem string) (int, []byte, error) {
	u := strings.TrimRight(server, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// writeJSON pretty-prints a JSON response, or writes it verbatim if it is not
// JSON. Either way the output is scriptable.
func writeJSON(w io.Writer, body []byte) {
	if len(bytes.TrimSpace(body)) == 0 {
		return
	}
	var v any
	if json.Unmarshal(body, &v) == nil {
		if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
			_, _ = w.Write(pretty)
			_, _ = w.Write([]byte("\n"))
			return
		}
	}
	_, _ = w.Write(body)
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "trstctl — command-line interface for the trstctl control plane")
	_, _ = fmt.Fprintln(w, "\nUsage: trstctl [--server URL] [--token TOKEN] [--tenant ID] [--ca-file PATH] <command> [args]")
	_, _ = fmt.Fprintln(w, "\nCommands:")
	for _, c := range Commands() {
		_, _ = fmt.Fprintf(w, "  %-26s %s\n", strings.Join(c.Name, " "), c.Summary)
	}
	_, _ = fmt.Fprintln(w, "  version                    Print version information")
	_, _ = fmt.Fprintln(w, "\nRun 'trstctl <command> --help' for command-specific arguments and an example.")
}

func commandHelpRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")
}

func commandUsage(w io.Writer, cmd Command) {
	name := strings.Join(cmd.Name, " ")
	_, _ = fmt.Fprintf(w, "Usage: trstctl %s", name)
	for _, p := range cmd.pathParams() {
		_, _ = fmt.Fprintf(w, " <%s>", p)
	}
	if cmd.Body == bodyFile || cmd.Body == bodyApprovalFile {
		_, _ = fmt.Fprint(w, " -f <file|->")
	}
	if cmd.Body == bodyIntentDigest {
		_, _ = fmt.Fprint(w, " <intent_digest>")
	}
	if cmd.Body == bodyIntentDigestReason {
		_, _ = fmt.Fprint(w, " <intent_digest> <reason>")
	}
	if cmd.Body == bodyOptionalFile {
		_, _ = fmt.Fprint(w, " [-f <file|->]")
	}
	if cmd.Body == bodyCypher {
		_, _ = fmt.Fprint(w, " <query>")
	}
	for _, q := range cmd.Query {
		_, _ = fmt.Fprintf(w, " [--%s value]", q)
	}
	if cmd.Destructive() {
		_, _ = fmt.Fprint(w, " --force")
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "\n%s\n", cmd.Summary)
	_, _ = fmt.Fprintf(w, "\nExample: %s\n", commandExample(cmd))
}

func commandExample(cmd Command) string {
	parts := []string{"trstctl"}
	parts = append(parts, cmd.Name...)
	for _, p := range cmd.pathParams() {
		parts = append(parts, "<"+p+">")
	}
	if cmd.Body == bodyFile || cmd.Body == bodyApprovalFile {
		parts = append(parts, "-f", "request.json")
	}
	if cmd.Body == bodyIntentDigest {
		parts = append(parts, "<intent_digest>")
	}
	if cmd.Body == bodyIntentDigestReason {
		parts = append(parts, "<intent_digest>", "\"review reason\"")
	}
	if cmd.Body == bodyOptionalFile {
		parts = append(parts, "-f", "request.json")
	}
	if cmd.Body == bodyCypher {
		parts = append(parts, "\"MATCH (n) RETURN n\"")
	}
	if len(cmd.Query) > 0 {
		parts = append(parts, "--"+cmd.Query[0], "value")
	}
	if cmd.Destructive() {
		parts = append(parts, "--force")
	}
	return strings.Join(parts, " ")
}

func runUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl [--server URL] [--token TOKEN] [--tenant ID] run --secret ENV=secret/path [--secret ENV2=path] [--resolve] -- <cmd> [args]")
	_, _ = fmt.Fprintln(w, "\nFetches named secrets from /api/v1/secrets/store/{name} and injects them only into the child process environment.")
}
