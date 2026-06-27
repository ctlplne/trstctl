// Package shellca is the shell-command escape hatch CA plugin. It implements the
// CA-specific backend behind internal/ca/catemplate by writing the CSR to a
// temporary file, executing one configured argv command, and reading the PEM
// chain written by that command.
//
// This adapter deliberately does not invoke a shell: Command and Args are passed
// to exec.CommandContext as literal argv entries after strict metacharacter
// validation. The command itself should run in an operator-provided signer
// sandbox (dedicated user/container/chroot), never on the hot API path. trstctl
// still routes this CA through ca.IssuanceService for idempotency/outbox evidence
// (AN-5/AN-6), and this package handles no private-key material itself (AN-8).
package shellca

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
)

const (
	defaultName    = "shellca"
	defaultTimeout = 30 * time.Second
)

// Config holds the literal command line used to sign a CSR.
//
// The command is invoked as:
//
//	Command Args... <csr_pem_path> <certificate_output_pem_path>
//
// The command must write a PEM certificate chain, leaf first, to the output path.
type Config struct {
	Name    string
	Command string
	Args    []string
	Env     []string
	Timeout time.Duration
}

type backend struct {
	cfg Config
}

// New builds the shell CA plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config) *catemplate.Plugin {
	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name == "" {
		cfg.Name = defaultName
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	return catemplate.New(&backend{cfg: cfg})
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue runs the configured signing command over temp-file CSR/input paths.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if err := ValidateConfig(b.cfg); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "trstctl-shellca-*")
	if err != nil {
		return nil, fmt.Errorf("shellca: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	csrPath := filepath.Join(dir, "request.csr.pem")
	certPath := filepath.Join(dir, "certificate.pem")
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	if err := os.WriteFile(csrPath, csrPEM, 0o600); err != nil {
		return nil, fmt.Errorf("shellca: write CSR: %w", err)
	}
	if err := b.run(ctx, csrPath, certPath); err != nil {
		return nil, err
	}
	chain, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("shellca: read signed certificate: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("shellca: sign command produced an empty certificate")
	}
	return chain, nil
}

func (b *backend) run(ctx context.Context, csrPath, certPath string) error {
	runCtx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	args := append([]string(nil), b.cfg.Args...)
	args = append(args, csrPath, certPath)
	cmd := exec.CommandContext(runCtx, b.cfg.Command, args...)
	cmd.Env = append(os.Environ(), b.cfg.Env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if runCtx.Err() != nil {
			return fmt.Errorf("shellca: sign command timed out: %w", runCtx.Err())
		}
		return fmt.Errorf("shellca: sign command failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ValidateConfig rejects command strings that would be meaningful to a shell.
// Even though shellca does not invoke a shell, validating the operator-provided
// argv keeps accidental "sh -c ..." and copied shell pipelines out of config.
func ValidateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Command) == "" {
		return fmt.Errorf("shellca: command is required")
	}
	if err := validateArgvToken("command", cfg.Command); err != nil {
		return err
	}
	if shellName(cfg.Command) {
		return fmt.Errorf("shellca: command %q is a shell interpreter; configure the signer binary directly", cfg.Command)
	}
	for i, arg := range cfg.Args {
		if err := validateArgvToken(fmt.Sprintf("arg[%d]", i), arg); err != nil {
			return err
		}
	}
	for i, env := range cfg.Env {
		if err := validateEnv(fmt.Sprintf("env[%d]", i), env); err != nil {
			return err
		}
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("shellca: timeout cannot be negative")
	}
	return nil
}

func validateArgvToken(label, value string) error {
	if value == "" {
		return fmt.Errorf("shellca: %s cannot be empty", label)
	}
	if strings.ContainsAny(value, "\x00\r\n;&|`$<>{}[]*?") {
		return fmt.Errorf("shellca: %s %q contains shell metacharacters", label, value)
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("shellca: %s %q contains whitespace; configure argv tokens explicitly", label, value)
		}
	}
	return nil
}

func validateEnv(label, value string) error {
	key, _, ok := strings.Cut(value, "=")
	if !ok || key == "" {
		return fmt.Errorf("shellca: %s must be KEY=value", label)
	}
	for _, r := range key {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return fmt.Errorf("shellca: %s has invalid environment key %q", label, key)
		}
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("shellca: %s contains a newline or NUL", label)
	}
	return nil
}

func shellName(command string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}
