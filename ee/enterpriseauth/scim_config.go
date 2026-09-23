// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func buildSCIMConfig(cfg config.SCIM) (*api.SCIMConfig, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.ValidateEnabled(); err != nil {
		return nil, err
	}
	out := api.SCIMConfig{Enabled: true, NewHandler: NewSCIMHandler}
	seen := map[string]bool{}
	for i, tok := range cfg.Tokens {
		raw, err := secretfile.Load(tok.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("auth.scim.tokens[%d].token_file: %w", i, err)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			secret.Wipe(raw)
			return nil, fmt.Errorf("auth.scim.tokens[%d].token_file is empty", i)
		}
		hash := crypto.SHA256Hex(trimmed)
		secret.Wipe(raw)
		if seen[hash] {
			return nil, fmt.Errorf("auth.scim.tokens[%d] duplicates another SCIM token", i)
		}
		seen[hash] = true
		out.Tokens = append(out.Tokens, api.SCIMToken{Name: tok.Name, TenantID: tok.TenantID, TokenHash: hash, SubjectAttribute: tok.SubjectAttribute})
	}
	return &out, nil
}
