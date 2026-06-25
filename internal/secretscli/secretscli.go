// Package secretscli is the developer secrets CLI core (S19.1, F64): it injects
// secrets into a child process's environment at runtime — never writing them to
// disk (AN-8) — plus fetch/set over the secrets client. Requests and fetches are
// audited (AN-2). (The interactive self-service portal is the UI shell's job; this
// is the command-line injection/fetch core it and developers share.)
package secretscli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/secrettext"
)

// Client is the secrets backend the CLI talks to.
type Client interface {
	Fetch(ctx context.Context, path string) ([]byte, error)
	Set(ctx context.Context, path string, value []byte) error
}

// CLI is the secrets command-line core.
type CLI struct {
	tenantID string
	client   Client
	audit    auditsink.Auditor
}

// New constructs a CLI.
func New(tenantID string, client Client, audit auditsink.Auditor) *CLI {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &CLI{tenantID: tenantID, client: client, audit: audit}
}

// Fetch retrieves a secret (audited).
func (c *CLI) Fetch(ctx context.Context, path string) ([]byte, error) {
	v, err := c.client.Fetch(ctx, path)
	_ = auditsink.Emit(ctx, c.audit, nil, "secretscli.fetch", c.tenantID, []byte(fmt.Sprintf(`{"path":%q}`, path)))
	return v, err
}

// Set writes a secret (audited).
func (c *CLI) Set(ctx context.Context, path string, value []byte) error {
	err := c.client.Set(ctx, path, value)
	_ = auditsink.Emit(ctx, c.audit, nil, "secretscli.set", c.tenantID, []byte(fmt.Sprintf(`{"path":%q}`, path)))
	return err
}

// Inject runs argv with the given secrets added to the process environment at
// runtime, never writing them to disk (AN-8). It returns the child's combined
// output. Only secret *names* are audited, never values.
func (c *CLI) Inject(ctx context.Context, secrets map[string]string, argv []string) ([]byte, error) {
	byteSecrets := make(map[string][]byte, len(secrets))
	for k, v := range secrets {
		byteSecrets[k] = []byte(v)
	}
	return c.InjectBytes(ctx, byteSecrets, argv)
}

// InjectBytes runs argv with byte-backed secrets added to the process
// environment. It returns the child's combined output for library callers that
// need a compact result.
func (c *CLI) InjectBytes(ctx context.Context, secrets map[string][]byte, argv []string) ([]byte, error) {
	var out bytes.Buffer
	err := c.InjectIO(ctx, secrets, argv, nil, &out, &out)
	return out.Bytes(), err
}

// InjectIO runs argv with byte-backed secrets added to the process environment,
// wiring the child process to caller-provided streams. Secret bytes stay as
// []byte until the final exec environment boundary; only variable names are
// audited, never values.
func (c *CLI) InjectIO(ctx context.Context, secrets map[string][]byte, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(argv) == 0 {
		return fmt.Errorf("secretscli: no command to run")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	env := os.Environ()
	names := make([]string, 0, len(secrets))
	for k, v := range secrets {
		env = append(env, secrettext.Prefixed(k+"=", v))
		names = append(names, k)
	}
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	sort.Strings(names)
	_ = auditsink.Emit(ctx, c.audit, nil, "secretscli.inject", c.tenantID, []byte(fmt.Sprintf(`{"vars":[%q]}`, strings.Join(names, `","`))))
	return err
}
