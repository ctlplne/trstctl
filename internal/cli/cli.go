// Package cli implements certctl's command-line interface: a thin, scriptable
// client at parity with the REST API (F11). Every core API operation has a
// command; output is machine-readable JSON; authentication is a CI-friendly API
// token. The command set is data-driven (see command.go) and proven complete by
// a parity test against the API route table.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"certctl.io/certctl/internal/buildinfo"
)

// Env carries the CLI's connection configuration and an optional injected HTTP
// client (for tests). Flags override these.
type Env struct {
	Server         string
	Token          string
	Tenant         string
	IdempotencyKey string
	HTTPClient     *http.Client
}

// Run parses args, performs the requested API operation, prints the JSON
// response to stdout, and returns a process exit code: 0 on success, 1 on a
// request/response error, 2 on a usage error.
func Run(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", env.Server, "control-plane base URL (env CERTCTL_SERVER)")
	token := fs.String("token", env.Token, "API token (env CERTCTL_TOKEN)")
	tenant := fs.String("tenant", env.Tenant, "tenant id for header auth (env CERTCTL_TENANT)")
	idem := fs.String("idempotency-key", env.IdempotencyKey, "Idempotency-Key for a mutation (generated if unset)")
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	if rest[0] == "version" {
		_, _ = fmt.Fprintln(stdout, buildinfo.String("certctl"))
		return 0
	}

	cmd, cmdArgs, ok := matchCommand(rest)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "error: unknown command %q (try 'certctl version' or --help)\n", strings.Join(rest, " "))
		return 2
	}
	if *server == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or CERTCTL_SERVER) is required")
		return 2
	}

	path, query, body, err := buildRequest(cmd, cmdArgs, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// Mutations require an Idempotency-Key (AN-5); generate a fresh one per
	// invocation unless the caller supplies a stable key for safe retries.
	idemKey := *idem
	if idemKey == "" && cmd.Method != http.MethodGet {
		idemKey = generateIdempotencyKey()
	}

	client := env.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
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

// buildRequest resolves the path (substituting path params), query string, and
// request body for a command from its arguments.
func buildRequest(cmd Command, args []string, stdin io.Reader) (path string, query url.Values, body []byte, err error) {
	positionals, query, bodyFilePath, err := splitArgs(args, cmd.Query)
	if err != nil {
		return "", nil, nil, err
	}

	if cmd.Body == bodyCypher {
		if len(positionals) == 0 {
			return "", nil, nil, fmt.Errorf("%s needs a query argument", strings.Join(cmd.Name, " "))
		}
		body, err = json.Marshal(map[string]string{"query": strings.Join(positionals, " ")})
		if err != nil {
			return "", nil, nil, err
		}
		return cmd.Path, query, body, nil
	}

	params := cmd.pathParams()
	if len(positionals) != len(params) {
		return "", nil, nil, fmt.Errorf("%s expects %d argument(s) (%s), got %d",
			strings.Join(cmd.Name, " "), len(params), strings.Join(params, ", "), len(positionals))
	}
	path = cmd.Path
	for i, p := range params {
		path = strings.Replace(path, "{"+p+"}", url.PathEscape(positionals[i]), 1)
	}

	if cmd.Body == bodyFile {
		if bodyFilePath == "" {
			return "", nil, nil, fmt.Errorf("%s needs a request body: -f <file> or -f - for stdin", strings.Join(cmd.Name, " "))
		}
		body, err = readBody(bodyFilePath, stdin)
		if err != nil {
			return "", nil, nil, err
		}
	}
	return path, query, body, nil
}

// splitArgs separates positional arguments, recognized query flags, and the -f
// body file from a command's arguments, in any order.
func splitArgs(args, queryNames []string) (positionals []string, query url.Values, bodyFile string, err error) {
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
				return nil, nil, "", fmt.Errorf("-f requires a value")
			}
			bodyFile = args[i]
		case strings.HasPrefix(a, "-f="):
			bodyFile = strings.TrimPrefix(a, "-f=")
		case strings.HasPrefix(a, "--"):
			name := strings.TrimPrefix(a, "--")
			var val string
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name, val = name[:eq], name[eq+1:]
			} else {
				i++
				if i >= len(args) {
					return nil, nil, "", fmt.Errorf("flag --%s requires a value", name)
				}
				val = args[i]
			}
			if !allowed[name] {
				return nil, nil, "", fmt.Errorf("unknown flag --%s", name)
			}
			query.Set(name, val)
		default:
			positionals = append(positionals, a)
		}
	}
	return positionals, query, bodyFile, nil
}

// readBody reads a request body from a file, or stdin when the path is "-".
func readBody(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// do performs the HTTP request and returns the status and response body.
// generateIdempotencyKey returns a fresh key. It needs uniqueness, not
// unpredictability, so math/rand/v2 (not crypto/*) keeps this outside the crypto
// boundary (AN-3).
func generateIdempotencyKey() string {
	return fmt.Sprintf("cli-%016x%016x", rand.Uint64(), rand.Uint64())
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
	_, _ = fmt.Fprintln(w, "certctl — command-line interface for the certctl control plane")
	_, _ = fmt.Fprintln(w, "\nUsage: certctl [--server URL] [--token TOKEN] [--tenant ID] <command> [args]")
	_, _ = fmt.Fprintln(w, "\nCommands:")
	for _, c := range commandTable {
		_, _ = fmt.Fprintf(w, "  %-26s %s\n", strings.Join(c.Name, " "), c.Summary)
	}
	_, _ = fmt.Fprintln(w, "  version                    Print version information")
}
