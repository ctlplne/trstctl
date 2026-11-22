// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// secretScanHookCloneCredentialsAPIOption names each hook's private clone
// credential (OD-1): the reference, opened by the scan worker for the clone.
func secretScanHookCloneCredentialsAPIOption(d Deps) api.Option {
	refs := make(map[string][3]string, len(d.SecretScanWebhooks))
	for _, hook := range d.SecretScanWebhooks {
		if ref := strings.TrimSpace(hook.CloneCredentialRef); ref != "" {
			refs[strings.TrimSpace(hook.ID)] = [3]string{ref, strings.TrimSpace(hook.CloneCredentialUsername), hook.CloneOrigin}
		}
	}
	return api.WithSecretScanHookCloneCredentials(func(hookID string) (string, string, string) {
		clone := refs[hookID]
		return clone[0], clone[1], clone[2]
	})
}

// repositoryHookClones is read only after server construction. The worker uses
// this operator configuration, never the credential reference in a source row.
func repositoryHookClones(hooks []config.SecretScanWebhook) map[string]config.SecretScanWebhook {
	clones := make(map[string]config.SecretScanWebhook, len(hooks))
	for _, hook := range hooks {
		if strings.TrimSpace(hook.CloneCredentialRef) != "" {
			clones[strings.TrimSpace(hook.ID)] = hook
		}
	}
	return clones
}

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
