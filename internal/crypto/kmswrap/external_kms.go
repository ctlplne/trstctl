package kmswrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
)

const (
	defaultExternalKMSTimeout = 10 * time.Second
	maxExternalKMSOutput      = 1 << 20
)

var (
	// ErrExternalKMSConfig is returned when the external KMS/HSM wrapper config is
	// incomplete. It is deliberately generic so callers do not log key identifiers
	// or command details as secrets.
	ErrExternalKMSConfig = errors.New("kmswrap: invalid external KMS config")
)

// ExternalKMSConfig configures a signer-local KMS/HSM envelope wrapper. The
// command is invoked without a shell as:
//
//	<wrap-command> wrap|unwrap <provider> <key-ref>
//
// DEK bytes travel only on stdin/stdout; provider and keyRef are identifiers, not
// secrets. This keeps cloud/HSM SDKs out of the sacred signer process while still
// allowing the shipped signer keystore to custody its wrapping operation in a
// production KMS/HSM adapter.
type ExternalKMSConfig struct {
	Provider    string
	KeyRef      string
	WrapCommand string
	Timeout     time.Duration
}

// ValidateExternalKMSConfig rejects incomplete or unsafe external KMS/HSM wrapper
// values before the signer starts.
func ValidateExternalKMSConfig(cfg ExternalKMSConfig) error {
	if strings.TrimSpace(cfg.Provider) == "" {
		return fmt.Errorf("%w: provider is required", ErrExternalKMSConfig)
	}
	if strings.TrimSpace(cfg.KeyRef) == "" {
		return fmt.Errorf("%w: keyRef is required", ErrExternalKMSConfig)
	}
	if strings.TrimSpace(cfg.WrapCommand) == "" {
		return fmt.Errorf("%w: wrapCommand is required", ErrExternalKMSConfig)
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("%w: timeout must not be negative", ErrExternalKMSConfig)
	}
	return nil
}

// ExternalKMSWrapper wraps/unwraps DEKs through an operator-supplied KMS/HSM
// adapter command. It implements seal.KeyWrapper, so the existing sealed-container
// format and signing.KeyStore use it without learning provider SDK details.
type ExternalKMSWrapper struct {
	provider string
	keyRef   string
	command  []string
	timeout  time.Duration
}

var _ seal.KeyWrapper = (*ExternalKMSWrapper)(nil)

// NewExternalKMSWrapper returns a KeyWrapper that delegates DEK custody to a
// signer-local KMS/HSM adapter command.
func NewExternalKMSWrapper(cfg ExternalKMSConfig) (*ExternalKMSWrapper, error) {
	if err := ValidateExternalKMSConfig(cfg); err != nil {
		return nil, err
	}
	command := strings.Fields(cfg.WrapCommand)
	if len(command) == 0 {
		return nil, fmt.Errorf("%w: wrapCommand is required", ErrExternalKMSConfig)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultExternalKMSTimeout
	}
	return &ExternalKMSWrapper{
		provider: strings.TrimSpace(cfg.Provider),
		keyRef:   strings.TrimSpace(cfg.KeyRef),
		command:  command,
		timeout:  timeout,
	}, nil
}

// Provider reports the configured external KMS/HSM provider identifier.
func (w *ExternalKMSWrapper) Provider() string { return w.provider }

// KeyRef reports the configured backend key identifier.
func (w *ExternalKMSWrapper) KeyRef() string { return w.keyRef }

// WrapDEK wraps a DEK using the external adapter.
func (w *ExternalKMSWrapper) WrapDEK(dek []byte) ([]byte, error) {
	return w.run("wrap", dek)
}

// UnwrapDEK unwraps a DEK using the external adapter.
func (w *ExternalKMSWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	return w.run("unwrap", wrapped)
}

func (w *ExternalKMSWrapper) run(operation string, input []byte) ([]byte, error) {
	if w == nil || len(w.command) == 0 {
		return nil, ErrExternalKMSConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()

	args := append([]string{}, w.command[1:]...)
	args = append(args, operation, w.provider, w.keyRef)
	cmd := exec.CommandContext(ctx, w.command[0], args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("kmswrap: external KMS %s timed out: %w", operation, ctx.Err())
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("kmswrap: external KMS %s failed: %w: %s", operation, err, msg)
		}
		return nil, fmt.Errorf("kmswrap: external KMS %s failed: %w", operation, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("kmswrap: external KMS %s returned empty output", operation)
	}
	if len(out) > maxExternalKMSOutput {
		return nil, fmt.Errorf("kmswrap: external KMS %s returned too much output", operation)
	}
	return out, nil
}
