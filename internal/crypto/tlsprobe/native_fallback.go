// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ValidateOpenSSLExecutable checks the operator-owned native probe path without
// running it. The binary and its ancestors must be managed by the local operator;
// no tenant-controlled command or PATH lookup is accepted here.
func ValidateOpenSSLExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("tlsprobe: native executable must be an absolute local path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("tlsprobe: native executable must be a regular executable file")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// The pin names the binary that runs, not a link that can be repointed
		// (Homebrew and alternatives install OpenSSL behind one, B6-2). Name
		// the resolved target so the operator can pin it.
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return fmt.Errorf("tlsprobe: native executable %s is a symbolic link to %s; pin that resolved path", path, resolved)
		}
		return errors.New("tlsprobe: native executable must be a regular executable file, not a symbolic link")
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("tlsprobe: native executable must be a regular executable file")
	}
	return nil
}

// ProbeWithNativeFallback keeps the normal Go inventory probe for supported
// listeners, including TLS 1.2 and application-negotiated TLS. An explicitly
// configured local OpenSSL is tried after a failed direct handshake, so an
// ML-DSA certificate can be observed without changing the requested credential
// algorithm. Both attempts share one deadline and neither sends application data.
// A failed upgrade callback is never skipped or replaced by direct TLS.
func ProbeWithNativeFallback(ctx context.Context, executable, addr string, opts ...Option) (Result, error) {
	if executable == "" {
		return Probe(ctx, addr, opts...)
	}
	if err := ValidateOpenSSLExecutable(executable); err != nil {
		return Result{}, err
	}
	cfg := config{timeout: DefaultTimeout}
	for _, option := range opts {
		option(&cfg)
	}
	if cfg.dialControl != nil {
		// The native executable dials outside the control hook.
		return Probe(ctx, addr, opts...)
	}
	timeout := cfg.timeout
	if timeout <= 0 || timeout > DefaultTimeout {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := Probe(ctx, addr, opts...)
	if err == nil {
		return result, nil
	}
	if cfg.preHandshake != nil {
		return Result{}, &StageError{Stage: StageHandshake, Addr: addr, Err: errors.New("application TLS negotiation failed; the configured native probe supports direct TLS only")}
	}
	if ctx.Err() != nil {
		return Result{}, err
	}
	return ProbeWithOpenSSL(ctx, executable, addr, opts...)
}
