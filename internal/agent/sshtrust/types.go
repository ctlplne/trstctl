// Package sshtrust configures a host to trust the trstctl SSH CA. This file is
// the S13.2 design contract: the seams and types the S13.3 build implements. The
// reviewed design — additive-first changes, validated reload with rollback, the
// enumerated lockout-failure modes and their mitigations, and the break-glass
// recovery path — lives in docs/design/ssh-trust-rewrite.md.
//
// Splitting the contract (S13.2) from the build (S13.3) is deliberate: this is a
// catastrophic-risk area (a bad rewrite can lock operators out), so the design is
// reviewed before any production behavior exists.
package sshtrust

import (
	"context"
	"os"
)

// FileSystem abstracts the host filesystem so the trust rewrite is testable and
// so config writes are atomic (write-temp-then-rename). Production wires the real
// host FS; tests inject a fake to exercise the rollback paths.
type FileSystem interface {
	ReadFile(path string) ([]byte, error)
	WriteFileAtomic(path string, data []byte, mode os.FileMode) error
	Remove(path string) error
	Exists(path string) bool
}

// Reloader validates, reloads, and health-checks sshd. Validate runs `sshd -t`
// before any reload; HealthCheck confirms the daemon is accepting connections
// after a reload (a failure triggers rollback). It is intentionally independent
// of the control plane (L8 in the design).
type Reloader interface {
	Validate(ctx context.Context) error
	Reload(ctx context.Context) error
	HealthCheck(ctx context.Context) error
}

// Config configures the trust Applier (S13.3).
type Config struct {
	FS                    FileSystem
	Reloader              Reloader
	SSHDConfigPath        string
	TrustedUserCAKeysPath string
	// AllowUnconfirmedRemoval opts OUT of the design's lockout protection: when
	// false (the zero value, and the safe default), RemoveCATrust refuses to remove
	// trust unless the caller passes confirm=true. The default is fail-closed because
	// removing SSH CA trust is a lockout-class operation — a default-constructed
	// Config must never allow an unconfirmed removal (SIGNER-007). Only an operator
	// that deliberately sets this true (e.g. an automated teardown that supplies its
	// own confirmation out of band) bypasses the in-code confirmation gate.
	AllowUnconfirmedRemoval bool
}
