// SPDX-License-Identifier: BUSL-1.1

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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	Name      string
	Command   string
	Args      []string
	Env       []string
	SecretFDs []SecretFD
	Timeout   time.Duration
}

// SecretFD is byte-native authority passed to the signer command through an
// inherited anonymous-pipe descriptor. The child receives only NAME_FD=<n> in
// its environment; the secret itself is never converted to a Go string, copied
// into exec.Cmd.Env, or written to a filesystem path. Value is consumed and
// wiped after the child attempt (AN-8).
type SecretFD struct {
	Name  string
	Value []byte
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
	defer secret.Wipe(csrPEM)
	if err := os.WriteFile(csrPath, csrPEM, 0o600); err != nil {
		return nil, fmt.Errorf("shellca: write CSR: %w", err)
	}
	if err := b.run(ctx, csrPath, certPath); err != nil {
		return nil, err
	}
	chain, err := os.ReadFile(certPath) // #nosec G304 -- operator-configured shell-CA output path; the shell CA is an explicit operator integration (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("shellca: read signed certificate: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("shellca: sign command produced an empty certificate")
	}
	return chain, nil
}

func (b *backend) run(ctx context.Context, csrPath, certPath string) error {
	defer wipeSecretFDs(b.cfg.SecretFDs)
	runCtx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	args := append([]string(nil), b.cfg.Args...)
	args = append(args, csrPath, certPath)
	cmd := exec.CommandContext(runCtx, b.cfg.Command, args...) // #nosec G204 -- the shell-CA backend exists to run the operator's configured signing command (CWE-78)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}, b.cfg.Env...)
	readers, writers, descriptors, err := openSecretPipes(b.cfg.SecretFDs)
	if err != nil {
		return err
	}
	cmd.ExtraFiles = readers
	cmd.Env = append(cmd.Env, descriptors...)
	// A signer command is untrusted enough to echo authority material. Give the
	// child raw OS pipes and drain their read ends through our own wiping buffers.
	// This avoids io.Writer's rule that a writer may not modify exec's pooled input
	// slice, while still preventing output larger than a pipe from deadlocking.
	outputReaders, outputWriters, err := openOutputPipes()
	if err != nil {
		closeFiles(readers)
		closeFiles(writers)
		return err
	}
	cmd.Stdout = outputWriters[0]
	cmd.Stderr = outputWriters[1]
	if err := cmd.Start(); err != nil {
		closeFiles(readers)
		closeFiles(writers)
		closeFiles(outputReaders)
		closeFiles(outputWriters)
		return fmt.Errorf("shellca: start sign command: %w", err)
	}
	closeFiles(outputWriters)
	outputResults := make(chan error, len(outputReaders))
	for _, reader := range outputReaders {
		go func(reader *os.File) {
			outputResults <- secret.Drain(reader)
		}(reader)
	}
	// Start duplicates the read ends into the child. Close the parent's read
	// copies, then stream each locked byte slice concurrently so a child may read
	// descriptors in any order without a pipe-buffer deadlock.
	closeFiles(readers)
	writeResults := make(chan error, len(writers))
	for index, writer := range writers {
		value := b.cfg.SecretFDs[index].Value
		go func() {
			err := writeAll(writer, value)
			if closeErr := writer.Close(); err == nil {
				err = closeErr
			}
			writeResults <- err
		}()
	}
	waitErr := cmd.Wait()
	// A descendant may inherit an output descriptor. Closing our read ends after
	// the direct child exits wakes every drain goroutine without retaining output.
	closeFiles(outputReaders)
	for range outputReaders {
		<-outputResults
	}
	// Force any still-blocked writer to wake if a failed child (or one of its
	// descendants) kept a read descriptor open without consuming it.
	closeFiles(writers)
	var writeErr error
	for range writers {
		if err := <-writeResults; err != nil && writeErr == nil {
			writeErr = err
		}
	}
	if waitErr != nil {
		if runCtx.Err() != nil {
			return fmt.Errorf("shellca: sign command timed out: %w", runCtx.Err())
		}
		return fmt.Errorf("shellca: sign command failed: %w", waitErr)
	}
	if writeErr != nil {
		return fmt.Errorf("shellca: stream secret descriptor: %w", writeErr)
	}
	return nil
}

func openOutputPipes() ([]*os.File, []*os.File, error) {
	readers := make([]*os.File, 0, 2)
	writers := make([]*os.File, 0, 2)
	for range 2 {
		reader, writer, err := os.Pipe()
		if err != nil {
			closeFiles(readers)
			closeFiles(writers)
			return nil, nil, fmt.Errorf("shellca: create child output pipe: %w", err)
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
	}
	return readers, writers, nil
}

func openSecretPipes(secrets []SecretFD) ([]*os.File, []*os.File, []string, error) {
	readers := make([]*os.File, 0, len(secrets))
	writers := make([]*os.File, 0, len(secrets))
	descriptors := make([]string, 0, len(secrets))
	for index, item := range secrets {
		reader, writer, err := os.Pipe()
		if err != nil {
			closeFiles(readers)
			closeFiles(writers)
			return nil, nil, nil, fmt.Errorf("shellca: create secret pipe: %w", err)
		}
		readers = append(readers, reader)
		writers = append(writers, writer)
		descriptors = append(descriptors, fmt.Sprintf("%s_FD=%d", item.Name, 3+index))
	}
	return readers, writers, descriptors, nil
}

func writeAll(file *os.File, value []byte) error {
	for len(value) > 0 {
		n, err := file.Write(value)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file == nil {
			continue
		}
		_ = file.Close()
	}
}

func wipeSecretFDs(secrets []SecretFD) {
	for index := range secrets {
		secret.Wipe(secrets[index].Value)
	}
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
	seenSecretNames := map[string]bool{}
	for i, secret := range cfg.SecretFDs {
		if err := validateEnvKey(fmt.Sprintf("secret_fd[%d]", i), secret.Name); err != nil {
			return err
		}
		if len(secret.Value) == 0 {
			return fmt.Errorf("shellca: secret_fd[%d] is empty", i)
		}
		if seenSecretNames[secret.Name] {
			return fmt.Errorf("shellca: duplicate secret descriptor name %q", secret.Name)
		}
		seenSecretNames[secret.Name] = true
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
	if err := validateEnvKey(label, key); err != nil {
		return err
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("shellca: %s contains a newline or NUL", label)
	}
	return nil
}

func validateEnvKey(label, key string) error {
	if key == "" || strings.HasSuffix(key, "_FD") {
		return fmt.Errorf("shellca: %s has invalid or reserved environment key %q", label, key)
	}
	for _, r := range key {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return fmt.Errorf("shellca: %s has invalid environment key %q", label, key)
		}
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
