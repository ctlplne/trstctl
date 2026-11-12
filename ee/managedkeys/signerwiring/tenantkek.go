// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/tenantkek"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/signing"
)

// tenantKEKConfig is the signer-local tenant KEK custody file (A123): the
// PKCS#11 token whose AES keys wrap tenant domain KEKs, and the wrapper table
// mapping each wrapper ID the control plane names to the label of one of those
// keys. Like the managed-key file, credentials are file references only.
type tenantKEKConfig struct {
	PKCS11   pkcs11Config       `json:"pkcs11"`
	Wrappers []tenantKEKWrapper `json:"wrappers"`
	// KMSWrappers are wrapper keys kept wrapped by a cloud KMS key through
	// the signer's KMS wrap adapter (OD-10, A200-L4).
	KMSWrappers []tenantKEKKMSWrapper `json:"kms_wrappers"`
	// KMSCacheSeconds is how long an unwrapped KMS wrapper key may stay in
	// locked memory before it is wiped (OD-10). Zero, the default, keeps
	// nothing: every use unwraps it through the KMS.
	KMSCacheSeconds int64 `json:"kms_cache_seconds"`
	// KMSWrapCommand is the absolute path of the KMS wrap adapter
	// (trstctl-kms-wrap) the KMS wrappers use, and KMSTimeoutSeconds each
	// call's deadline (default 10). They are separate from the signer key
	// store's own --kms-* flags, which a --kek key store does not take.
	KMSWrapCommand    string `json:"kms_wrap_command"`
	KMSTimeoutSeconds int64  `json:"kms_timeout_seconds"`
}

type tenantKEKWrapper struct {
	ID       string `json:"id"`
	KeyLabel string `json:"key_label"`
}

// tenantKEKKMSWrapper is one wrapper key under a cloud KMS key: the adapter
// provider and key reference that wrap it, and the file holding its wrapped
// form (created on first start when absent; every signer replica mounts the
// same file).
type tenantKEKKMSWrapper struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	KeyRef         string `json:"key_ref"`
	WrappedKeyFile string `json:"wrapped_key_file"`
}

// kmsAdapter is the KMS wrap adapter command and its per-call deadline.
type kmsAdapter struct {
	Command string
	Timeout time.Duration
}

// maxKMSTimeout bounds one adapter call's deadline.
const maxKMSTimeout = 5 * time.Minute

// maxWrappedKMSKey bounds a wrapped wrapper key file.
const maxWrappedKMSKey = 16 << 10

// TenantKEKOption decodes the signer-local tenant KEK file, opens the PKCS#11
// session for HSM wrappers and the KMS wrapper keys through adapter, proves
// every wrapper seals and opens, and returns the custody for the signer to
// serve with the closer that wipes cached KMS wrapper keys and ends the HSM
// session at shutdown. The operator provisions the HSM keys and the KMS keys;
// a KMS wrapper key's wrapped file is created on first start.
func TenantKEKOption(path string) (signing.ServerOption, func() error, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the signer operator's explicit local configuration file, never remote input (CWE-22).
	if err != nil {
		return nil, nil, err
	}
	defer secret.Wipe(raw)
	if len(raw) > maxManagedKeyConfigBytes {
		return nil, nil, fmt.Errorf("tenant KEK config exceeds %d bytes", maxManagedKeyConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg tenantKEKConfig
	decodeErr := dec.Decode(&cfg)
	defer func() {
		secret.Wipe(cfg.PKCS11.UserPIN)
		cfg.PKCS11.UserPIN = nil
	}()
	if decodeErr != nil {
		return nil, nil, fmt.Errorf("decode tenant KEK config: %w", decodeErr)
	}
	if err := ensureConfigEOF(dec); err != nil {
		return nil, nil, err
	}
	if len(cfg.Wrappers) == 0 && len(cfg.KMSWrappers) == 0 {
		return nil, nil, fmt.Errorf("tenant KEK config names no wrappers")
	}
	if cfg.KMSCacheSeconds < 0 || time.Duration(cfg.KMSCacheSeconds)*time.Second > kmswrap.MaxWrapperKeyCache {
		return nil, nil, fmt.Errorf("tenant KEK config kms_cache_seconds is 0 (off) to %d", int64(kmswrap.MaxWrapperKeyCache/time.Second))
	}
	if cfg.KMSCacheSeconds > 0 && len(cfg.KMSWrappers) == 0 {
		return nil, nil, fmt.Errorf("tenant KEK config sets kms_cache_seconds but names no kms_wrappers")
	}
	table := make(map[string]string, len(cfg.Wrappers))
	for _, w := range cfg.Wrappers {
		if _, dup := table[w.ID]; dup {
			return nil, nil, fmt.Errorf("tenant KEK config names wrapper %q twice", w.ID)
		}
		table[w.ID] = w.KeyLabel
	}
	timeout := 10 * time.Second
	if cfg.KMSTimeoutSeconds != 0 {
		timeout = time.Duration(cfg.KMSTimeoutSeconds) * time.Second
	}
	if timeout <= 0 || timeout > maxKMSTimeout {
		return nil, nil, fmt.Errorf("tenant KEK config kms_timeout_seconds is 1 to %d", int64(maxKMSTimeout/time.Second))
	}
	if cfg.KMSWrapCommand != "" && len(cfg.KMSWrappers) == 0 {
		return nil, nil, fmt.Errorf("tenant KEK config sets kms_wrap_command but names no kms_wrappers")
	}
	adapter := kmsAdapter{Command: cfg.KMSWrapCommand, Timeout: timeout}
	kmsKeys, err := openKMSWrapperKeys(cfg.KMSWrappers, table, adapter, time.Duration(cfg.KMSCacheSeconds)*time.Second)
	if err != nil {
		return nil, nil, err
	}
	closeKMS := func() {
		for _, key := range kmsKeys {
			key.Close()
		}
	}
	var session pkcs11.Session
	if len(cfg.Wrappers) > 0 {
		if strings.TrimSpace(cfg.PKCS11.ModulePath) == "" || strings.TrimSpace(cfg.PKCS11.TokenLabel) == "" {
			closeKMS()
			return nil, nil, fmt.Errorf("tenant KEK config needs pkcs11.module_path and pkcs11.token_label")
		}
		pin, wipe, err := credential("tenant KEK pkcs11 user PIN", cfg.PKCS11.UserPIN, cfg.PKCS11.UserPINFile, true)
		if err != nil {
			closeKMS()
			return nil, nil, err
		}
		defer wipe()
		session, err = pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
			ModulePath: cfg.PKCS11.ModulePath, TokenLabel: cfg.PKCS11.TokenLabel,
			UserPIN: pin, KeyLabelPrefix: cfg.PKCS11.KeyLabelPrefix,
		})
		if err != nil {
			closeKMS()
			return nil, nil, err
		}
	}
	custody, err := tenantkek.NewWithKMS(session, table, kmsKeys)
	if err != nil {
		closeKMS()
		if session != nil {
			_ = session.Close()
		}
		return nil, nil, err
	}
	return signing.WithTenantKEKCustody(custody), custody.Close, nil
}

// openKMSWrapperKeys holds each KMS wrapper key in its wrapped form, creating
// it through the adapter when its file does not exist yet.
func openKMSWrapperKeys(wrappers []tenantKEKKMSWrapper, hsm map[string]string, adapter kmsAdapter, cache time.Duration) (map[string]*kmswrap.WrapperKey, error) {
	out := make(map[string]*kmswrap.WrapperKey, len(wrappers))
	fail := func(err error) (map[string]*kmswrap.WrapperKey, error) {
		for _, key := range out {
			key.Close()
		}
		return nil, err
	}
	if len(wrappers) > 0 && (strings.TrimSpace(adapter.Command) == "" || !filepath.IsAbs(strings.Fields(adapter.Command)[0])) {
		return nil, errors.New("tenant KEK kms_wrappers need kms_wrap_command, the absolute path of the KMS wrap adapter")
	}
	// Every entry is checked before any KMS call.
	adapters := make(map[string]*kmswrap.ExternalKMSWrapper, len(wrappers))
	for _, w := range wrappers {
		if _, dup := adapters[w.ID]; dup {
			return nil, fmt.Errorf("tenant KEK config names KMS wrapper %q twice", w.ID)
		}
		if _, dup := hsm[w.ID]; dup {
			return nil, fmt.Errorf("tenant KEK config names wrapper %q as both an HSM key and a KMS wrapper", w.ID)
		}
		if strings.TrimSpace(w.WrappedKeyFile) == "" || !filepath.IsAbs(w.WrappedKeyFile) {
			return nil, fmt.Errorf("tenant KEK KMS wrapper %q needs an absolute wrapped_key_file", w.ID)
		}
		kms, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
			Provider: w.Provider, KeyRef: w.KeyRef, WrapCommand: adapter.Command, Timeout: adapter.Timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("tenant KEK KMS wrapper %q: %w", w.ID, err)
		}
		adapters[w.ID] = kms
	}
	for _, w := range wrappers {
		kms := adapters[w.ID]
		wrapped, err := loadOrCreateWrappedKMSKey(w.WrappedKeyFile, kms)
		if err != nil {
			return fail(fmt.Errorf("tenant KEK KMS wrapper %q: %w", w.ID, err))
		}
		key, err := kmswrap.NewWrapperKey(kms, wrapped, cache)
		if err != nil {
			return fail(fmt.Errorf("tenant KEK KMS wrapper %q: %w", w.ID, err))
		}
		out[w.ID] = key
	}
	return out, nil
}

// loadOrCreateWrappedKMSKey reads a wrapped wrapper key, or creates one
// through the KMS and writes it (0600, replaced atomically) when the file
// does not exist. The file holds only the KMS-wrapped form.
func loadOrCreateWrappedKMSKey(path string, kms *kmswrap.ExternalKMSWrapper) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the signer operator's configured wrapped-key file, never remote input (CWE-22).
	if err == nil {
		defer func() { _ = f.Close() }()
		wrapped, err := io.ReadAll(io.LimitReader(f, maxWrappedKMSKey+1))
		if err != nil {
			return nil, err
		}
		if len(wrapped) == 0 || len(wrapped) > maxWrappedKMSKey {
			return nil, fmt.Errorf("%s is empty or larger than %d bytes", path, maxWrappedKMSKey)
		}
		return wrapped, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	wrapped, err := kmswrap.CreateWrapperKey(kms)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wrapped-kms-key-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(wrapped); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		// Another replica created it first: use theirs.
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateWrappedKMSKey(path, kms)
		}
		return nil, err
	}
	return wrapped, nil
}
