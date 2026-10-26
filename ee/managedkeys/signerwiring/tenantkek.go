// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/ee/tenantkek"
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
}

type tenantKEKWrapper struct {
	ID       string `json:"id"`
	KeyLabel string `json:"key_label"`
}

// TenantKEKOption decodes the signer-local tenant KEK file, opens the PKCS#11
// session, proves every wrapper key seals and opens, and returns the custody
// for the signer to serve. The operator provisions the HSM keys; nothing here
// creates one.
func TenantKEKOption(path string) (signing.ServerOption, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the signer operator's explicit local configuration file, never remote input (CWE-22).
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	if len(raw) > maxManagedKeyConfigBytes {
		return nil, fmt.Errorf("tenant KEK config exceeds %d bytes", maxManagedKeyConfigBytes)
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
		return nil, fmt.Errorf("decode tenant KEK config: %w", decodeErr)
	}
	if err := ensureConfigEOF(dec); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.PKCS11.ModulePath) == "" || strings.TrimSpace(cfg.PKCS11.TokenLabel) == "" {
		return nil, fmt.Errorf("tenant KEK config needs pkcs11.module_path and pkcs11.token_label")
	}
	if len(cfg.Wrappers) == 0 {
		return nil, fmt.Errorf("tenant KEK config names no wrappers")
	}
	table := make(map[string]string, len(cfg.Wrappers))
	for _, w := range cfg.Wrappers {
		if _, dup := table[w.ID]; dup {
			return nil, fmt.Errorf("tenant KEK config names wrapper %q twice", w.ID)
		}
		table[w.ID] = w.KeyLabel
	}
	pin, wipe, err := credential("tenant KEK pkcs11 user PIN", cfg.PKCS11.UserPIN, cfg.PKCS11.UserPINFile, true)
	if err != nil {
		return nil, err
	}
	defer wipe()
	session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: cfg.PKCS11.ModulePath, TokenLabel: cfg.PKCS11.TokenLabel,
		UserPIN: pin, KeyLabelPrefix: cfg.PKCS11.KeyLabelPrefix,
	})
	if err != nil {
		return nil, err
	}
	custody, err := tenantkek.New(session, table)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return signing.WithTenantKEKCustody(custody), nil
}
