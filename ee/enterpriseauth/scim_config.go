// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

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
	writebacks := map[string]scimWritebackTarget{}
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
		token := api.SCIMToken{Name: tok.Name, TenantID: tok.TenantID, TokenHash: hash, SubjectAttribute: tok.SubjectAttribute, GroupRoles: tok.GroupRoles}
		if tok.WritebackConfigured() {
			// A73: the outbound bearer stays in locked memory for the life of
			// the process; the core seam sees only the endpoint.
			bearer, err := secretfile.Load(tok.WritebackTokenFile)
			if err != nil {
				return nil, fmt.Errorf("auth.scim.tokens[%d].writeback_token_file: %w", i, err)
			}
			buffer, err := secret.NewFrom(bytes.TrimSpace(bearer))
			secret.Wipe(bearer)
			if err != nil {
				return nil, err
			}
			if buffer.Len() == 0 {
				return nil, fmt.Errorf("auth.scim.tokens[%d].writeback_token_file is empty", i)
			}
			token.WritebackEndpoint = strings.TrimRight(strings.TrimSpace(tok.WritebackEndpoint), "/")
			writebacks[tok.TenantID] = scimWritebackTarget{
				TokenName: tok.Name, Endpoint: token.WritebackEndpoint, SubjectAttribute: strings.TrimSpace(tok.SubjectAttribute), bearer: buffer,
			}
		}
		out.Tokens = append(out.Tokens, token)
	}
	if len(writebacks) > 0 {
		out.NewWriteback = func(deps api.SCIMWritebackDeps) api.SCIMWritebackHandler {
			return newSCIMWriteback(deps, writebacks)
		}
	}
	// A207: the handler reads its tokens from a set that reloads the token
	// files when they change, so a rotated token works without a restart.
	set, err := newSCIMTokenSet(cfg.Tokens)
	if err != nil {
		return nil, err
	}
	out.NewHandler = func(_ api.SCIMConfig, d api.SCIMHandlerDeps) http.Handler {
		if set.empty() {
			return nil
		}
		return newSCIMHandler(set, d)
	}
	return &out, nil
}
