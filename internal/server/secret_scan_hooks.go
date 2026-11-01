// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// secretScanHooksAPIOption attaches the configured provider-native scan
// webhooks (P6). Each delivery resolves its hook's signing secret for that one
// check, as locked bytes the API destroys.
func secretScanHooksAPIOption(d Deps) api.Option {
	if len(d.SecretScanWebhooks) == 0 {
		return api.WithSecretScanHooks(nil)
	}
	hooks := make(map[string]config.SecretScanWebhook, len(d.SecretScanWebhooks))
	for _, hook := range d.SecretScanWebhooks {
		hooks[strings.TrimSpace(hook.ID)] = hook
	}
	resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
	return api.WithSecretScanHooks(func(ctx context.Context, hookID string) (string, string, *secret.Buffer, error) {
		hook, ok := hooks[hookID]
		if !ok {
			return "", "", nil, api.ErrUnknownSecretScanHook
		}
		key, err := resolver.resolve(ctx, hook.TenantID, hook.SecretRef)
		if err != nil {
			return "", "", nil, err
		}
		return strings.TrimSpace(hook.TenantID), hook.Provider, key, nil
	})
}
