// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/config"
)

// prepareManagedKeySignerConfig creates the non-secret provider descriptor the
// supervised child signer reopens after a crash. Credential values themselves
// must already be operator-owned files; putting an inline secret into argv, env,
// or a restart-surviving generated file would violate AN-8.
func prepareManagedKeySignerConfig(cfg config.ManagedKeys) (string, func(), error) {
	if err := managedKeySignerSecretsAreFileBacked(cfg); err != nil {
		return "", func() {}, err
	}
	dir, err := os.MkdirTemp("", "trstctl-managed-key-signer-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	path := filepath.Join(dir, "provider.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func managedKeySignerSecretsAreFileBacked(cfg config.ManagedKeys) error {
	if len(cfg.AWS.SecretAccessKey) > 0 || len(cfg.AWS.SessionToken) > 0 ||
		len(cfg.Azure.BearerToken) > 0 || len(cfg.GCP.BearerToken) > 0 ||
		len(cfg.PKCS11.UserPIN) > 0 || len(cfg.TPM2.OwnerAuth) > 0 ||
		len(cfg.TPM2.KeyAuth) > 0 || len(cfg.YubiHSM2.UserPIN) > 0 {
		return fmt.Errorf("managed_keys child-signer config contains inline credential material; every provider secret must use its *_file field")
	}
	switch cfg.Provider {
	case "", config.ManagedKeyProviderAWS:
		if len(cfg.AWS.SecretAccessKey) > 0 || len(cfg.AWS.SessionToken) > 0 {
			return fmt.Errorf("managed_keys AWS credentials must use *_file fields in child-signer mode; inline values cannot be transferred safely across AN-4")
		}
	case config.ManagedKeyProviderAzureKeyVault:
		if len(cfg.Azure.BearerToken) > 0 {
			return fmt.Errorf("managed_keys Azure bearer token must use bearer_token_file in child-signer mode")
		}
	case config.ManagedKeyProviderGCPKMS:
		if len(cfg.GCP.BearerToken) > 0 {
			return fmt.Errorf("managed_keys GCP bearer token must use bearer_token_file in child-signer mode")
		}
	case config.ManagedKeyProviderPKCS11:
		if len(cfg.PKCS11.UserPIN) > 0 {
			return fmt.Errorf("managed_keys PKCS#11 PIN must use user_pin_file in child-signer mode")
		}
	case config.ManagedKeyProviderTPM2:
		if len(cfg.TPM2.OwnerAuth) > 0 || len(cfg.TPM2.KeyAuth) > 0 {
			return fmt.Errorf("managed_keys TPM auth values must use *_auth_file in child-signer mode")
		}
	case config.ManagedKeyProviderYubiHSM2:
		if len(cfg.YubiHSM2.UserPIN) > 0 {
			return fmt.Errorf("managed_keys YubiHSM2 PIN must use user_pin_file in child-signer mode")
		}
	}
	return nil
}
