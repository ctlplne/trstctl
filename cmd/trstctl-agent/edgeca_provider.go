// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"fmt"
	"os"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// openEdgeCAKeyProvider is a test seam around production device opening. The
// returned close function owns the device/session; callers close it only after
// CSR creation or issuance finishes. There is intentionally no software
// fallback here: failure to open the configured device is a hard refusal.
var openEdgeCAKeyProvider = openProductionEdgeCAKeyProvider

func openProductionEdgeCAKeyProvider(opts edgeCAOptions) (crypto.EdgeCAKeyProvider, func() error, error) {
	switch normalizedEdgeKeyProvider(opts.keyProvider) {
	case "tpm2":
		ownerAuth, err := readEdgeSecretFile(opts.tpmOwnerAuthFile, false)
		if err != nil {
			return nil, nil, fmt.Errorf("read TPM owner authorization: %w", err)
		}
		defer secret.Wipe(ownerAuth)
		keyAuth, err := readEdgeSecretFile(opts.tpmKeyAuthFile, false)
		if err != nil {
			return nil, nil, fmt.Errorf("read TPM key authorization: %w", err)
		}
		defer secret.Wipe(keyAuth)
		device, err := tpm.OpenDevice(tpm.DeviceConfig{
			Path: opts.tpmPath, OwnerAuth: ownerAuth, KeyAuth: keyAuth,
			PersistentHandleBase: opts.tpmPersistentHandleBase,
		})
		if err != nil {
			return nil, nil, err
		}
		backend := tpm.New(device)
		return backend, backend.Close, nil
	case "pkcs11":
		pin, err := readEdgeSecretFile(opts.pkcs11PINFile, true)
		if err != nil {
			return nil, nil, fmt.Errorf("read PKCS#11 user PIN: %w", err)
		}
		defer secret.Wipe(pin)
		session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
			ModulePath: opts.pkcs11Module, TokenLabel: opts.pkcs11Token,
			UserPIN: pin, KeyLabelPrefix: opts.pkcs11KeyLabelPrefix,
		})
		if err != nil {
			return nil, nil, err
		}
		return pkcs11.New(session), session.Close, nil
	default:
		return nil, nil, fmt.Errorf("provider %q is not a hardware edge CA provider", opts.keyProvider)
	}
}

func readEdgeSecretFile(path string, required bool) ([]byte, error) {
	if path == "" {
		if required {
			return nil, fmt.Errorf("secret file path is required")
		}
		return nil, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- explicit operator-owned device secret path (CWE-22)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	trimmed := bytes.TrimSpace(raw)
	if required && len(trimmed) == 0 {
		return nil, fmt.Errorf("secret file is empty")
	}
	return append([]byte(nil), trimmed...), nil
}
