// SPDX-License-Identifier: BUSL-1.1

package sshtrust

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// ApplyFailure exposes only closed phase/restoration facts to the fleet worker.
// Cause remains local diagnostic data and must never be placed in a job receipt.
type ApplyFailure struct {
	Phase    string
	Restored bool
	Cause    error
}

func (e *ApplyFailure) Error() string { return e.Cause.Error() }
func (e *ApplyFailure) Unwrap() error { return e.Cause }

func closedApplyPhase(phase string) string {
	switch phase {
	case "validate", "reload", "readback":
		return phase
	case "health-check":
		return "health"
	case "write sshd_config":
		return "write_config"
	default:
		return "preflight"
	}
}

// ApplyEvidence distinguishes an installed/read-back CA from a checked rollback.
// It carries no path, argv, key or arbitrary error text.
type ApplyEvidence struct {
	Changed                 bool
	Phase                   string
	Rollback                string
	CAReadBack              bool
	EffectiveConfigReadBack bool
	TrustFileSHA256         string
	ConfigFileSHA256        string
	Validated               bool
	Reloaded                bool
	Healthy                 bool
}

type observedReloader struct {
	inner    Reloader
	evidence *ApplyEvidence
}

func (r observedReloader) Validate(ctx context.Context) error {
	r.evidence.Phase = "validate"
	err := r.inner.Validate(ctx)
	r.evidence.Validated = err == nil
	return err
}
func (r observedReloader) Reload(ctx context.Context) error {
	r.evidence.Phase = "reload"
	err := r.inner.Reload(ctx)
	r.evidence.Reloaded = err == nil
	return err
}
func (r observedReloader) HealthCheck(ctx context.Context) error {
	r.evidence.Phase = "health"
	err := r.inner.HealthCheck(ctx)
	r.evidence.Healthy = err == nil
	return err
}

// AddCATrustObserved uses the established additive applier, then reads the
// actual public trust/configuration again. A rollback is verified only after
// exact backup readback plus validation, reload and a fresh health check.
func (a *Applier) AddCATrustObserved(ctx context.Context, ca []byte) (ApplyEvidence, error) {
	result := ApplyEvidence{Phase: "preflight", Rollback: "not_needed"}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Phase = "backup"
	trustBefore, trustExisted, err := a.read(a.cfg.TrustedUserCAKeysPath)
	if err != nil {
		return result, err
	}
	configBefore, configExisted, err := a.read(a.cfg.SSHDConfigPath)
	if err != nil {
		return result, err
	}
	info, err := sshkeys.ParsePublicKey(ca)
	if err != nil {
		result.Phase = "preflight"
		return result, err
	}
	// Clone configuration so callers sharing an Applier never see the observer.
	observed := *a
	observed.cfg.Reloader = observedReloader{inner: a.cfg.Reloader, evidence: &result}
	observed.cfg.FS = observedFileSystem{inner: a.cfg.FS, evidence: &result, trustPath: a.cfg.TrustedUserCAKeysPath}
	result.Phase = "preflight"
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Changed, err = observed.AddCATrust(ctx, ca)
	if err != nil {
		result.Rollback = "not_available"
		var failure *ApplyFailure
		if errors.As(err, &failure) {
			result.Phase = failure.Phase
			result.Rollback = "failed"
			if failure.Restored {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
				defer cancel()
				if a.verifyRestored(cleanup, trustBefore, trustExisted, configBefore, configExisted) == nil {
					result.Rollback = "verified"
				}
			}
		}
		return result, err
	}
	// A successful reload is still unverified until independent readback.
	// Any later readback failure gets the same exact, checked recovery path;
	// leaving the changed trust in place would make this error unsafe to retry.
	restoreAfterReadbackFailure := func(cause error) (ApplyEvidence, error) {
		result.Rollback = "failed"
		recoveryErr := a.rollbackFiles(ctx, "readback", cause, true,
			fileBackup{path: a.cfg.TrustedUserCAKeysPath, data: trustBefore, existed: trustExisted},
			fileBackup{path: a.cfg.SSHDConfigPath, data: configBefore, existed: configExisted})
		var failure *ApplyFailure
		if errors.As(recoveryErr, &failure) && failure.Restored {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			if a.verifyRestored(cleanup, trustBefore, trustExisted, configBefore, configExisted) == nil {
				result.Rollback = "verified"
			}
		}
		return result, recoveryErr
	}
	result.Phase = "readback"
	trust, err := a.cfg.FS.ReadFile(a.cfg.TrustedUserCAKeysPath)
	if err != nil {
		return restoreAfterReadbackFailure(err)
	}
	config, err := a.cfg.FS.ReadFile(a.cfg.SSHDConfigPath)
	if err != nil {
		return restoreAfterReadbackFailure(err)
	}
	for _, key := range sshkeys.ParseAuthorizedKeys(trust) {
		if len(key.Options) == 0 && key.FingerprintSHA256 == info.FingerprintSHA256 {
			result.CAReadBack = true
		}
	}
	result.EffectiveConfigReadBack, err = a.sshdConfigReferencesTrustedKeys(a.cfg.SSHDConfigPath, string(config), a.cfg.TrustedUserCAKeysPath, map[string]bool{})
	if err != nil {
		return restoreAfterReadbackFailure(err)
	}
	if !result.CAReadBack || !result.EffectiveConfigReadBack {
		return restoreAfterReadbackFailure(errors.New("SSH trust readback did not confirm the requested CA and effective configuration"))
	}
	result.TrustFileSHA256 = "sha256:" + crypto.SHA256Hex(trust)
	result.ConfigFileSHA256 = "sha256:" + crypto.SHA256Hex(config)
	result.Phase = "complete"
	return result, nil
}

func (a *Applier) verifyRestored(ctx context.Context, trustBefore []byte, trustExisted bool, configBefore []byte, configExisted bool) error {
	for _, backup := range []fileBackup{{path: a.cfg.TrustedUserCAKeysPath, data: trustBefore, existed: trustExisted}, {path: a.cfg.SSHDConfigPath, data: configBefore, existed: configExisted}} {
		actual, existed, err := a.read(backup.path)
		if err != nil {
			return err
		}
		if existed != backup.existed || !bytes.Equal(actual, backup.data) {
			return errors.New("restored SSH files differ from the exact prior snapshot")
		}
	}
	if err := a.cfg.Reloader.Validate(ctx); err != nil {
		return err
	}
	if err := a.cfg.Reloader.Reload(ctx); err != nil {
		return err
	}
	return a.cfg.Reloader.HealthCheck(ctx)
}

type observedFileSystem struct {
	inner     FileSystem
	evidence  *ApplyEvidence
	trustPath string
}

func (f observedFileSystem) ReadFile(path string) ([]byte, error) { return f.inner.ReadFile(path) }
func (f observedFileSystem) Exists(path string) bool              { return f.inner.Exists(path) }
func (f observedFileSystem) Remove(path string) error             { return f.inner.Remove(path) }
func (f observedFileSystem) WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	f.evidence.Phase = "write_config"
	if path == f.trustPath {
		f.evidence.Phase = "write_trust"
	}
	return f.inner.WriteFileAtomic(path, data, mode)
}
func (f observedFileSystem) Glob(pattern string) ([]string, error) {
	if globber, ok := f.inner.(interface {
		Glob(string) ([]string, error)
	}); ok {
		return globber.Glob(pattern)
	}
	return nil, nil
}
