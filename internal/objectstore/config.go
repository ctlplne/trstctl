// SPDX-License-Identifier: BUSL-1.1

package objectstore

import (
	"bytes"
	"fmt"
	"os"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// FromConfig opens the store an operator configured. The credential files
// pass the secret-file custody checks (private mode, safe parents) before
// their bytes are read, and the read buffers are wiped once the credentials
// are in locked memory. It returns (nil, nil) when no object store is
// configured.
func FromConfig(cfg config.ObjectStore) (*S3, error) {
	if !cfg.Configured() {
		return nil, nil
	}
	secretRaw, err := secretfile.Load(cfg.SecretAccessKeyFile)
	if err != nil {
		return nil, fmt.Errorf("objectstore: read secret_access_key_file: %w", err)
	}
	defer secret.Wipe(secretRaw)
	var sessionRaw []byte
	if cfg.SessionTokenFile != "" {
		if sessionRaw, err = secretfile.Load(cfg.SessionTokenFile); err != nil {
			return nil, fmt.Errorf("objectstore: read session_token_file: %w", err)
		}
		defer secret.Wipe(sessionRaw)
	}
	var caPEM []byte
	if cfg.CAFile != "" {
		if caPEM, err = os.ReadFile(cfg.CAFile); err != nil { // #nosec G304 -- operator-configured CA bundle path (CWE-22)
			return nil, fmt.Errorf("objectstore: read ca_file: %w", err)
		}
	}
	timeout, err := cfg.TimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("objectstore: timeout: %w", err)
	}
	return Open(Options{
		Endpoint: cfg.Endpoint, Region: cfg.Region, Bucket: cfg.Bucket, Prefix: cfg.Prefix,
		PathStyle: cfg.PathStyle, AccessKeyID: cfg.AccessKeyID,
		SecretAccessKey: bytes.TrimSpace(secretRaw), SessionToken: bytes.TrimSpace(sessionRaw),
		CAPEM: caPEM, AllowInsecureLoopback: cfg.AllowInsecureLoopback,
		Timeout: timeout, MaxInFlight: cfg.MaxInFlight,
	})
}
