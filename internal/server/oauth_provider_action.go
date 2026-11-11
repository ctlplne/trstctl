// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/oauthrevoke"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The control-plane executor of an OAuth provider action (A170, A171): it
// reopens the source's admin connection for the grant's provider, resolves
// the token reference, asks the provider to revoke the grant or block the
// application, and records what the provider confirmed on the finding. A
// provider that is unreachable, throttles or fails on its side leaves the row
// to retry; any other refusal is recorded as failed with the provider's
// status, because it would fail the same way every time.
func (d *issuanceDispatcher) handleOAuthProviderAction(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.orch == nil {
		return errors.New("server: OAuth provider actions are not configured")
	}
	var in orchestrator.OAuthProviderActionIntent
	if err := json.Unmarshal(m.Payload, &in); err != nil || strings.TrimSpace(in.RequestID) == "" || strings.TrimSpace(in.SourceID) == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: OAuth provider action row is malformed"))
	}
	fail := func(detail string) error {
		if err := d.orch.RecordOAuthProviderAction(ctx, m.TenantID, in, orchestrator.OAuthActionFailed, detail); err != nil {
			return err
		}
		return orchestrator.DefiniteNoEffect(errors.New("server: OAuth provider action failed: " + detail))
	}
	source, err := d.store.GetDiscoverySource(ctx, m.TenantID, in.SourceID)
	if err != nil {
		return fail("the discovery source that found the grant is gone")
	}
	conn, found, err := oauthgrant.Connection(source.Config, in.Provider)
	if err != nil || !found {
		return fail("the discovery source no longer has an admin connection for " + in.Provider)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, conn.TokenRef)
	if err != nil {
		return fail("resolve the admin token reference: " + err.Error())
	}
	client, err := cloudHTTPClient(conn.BaseURL, conn.AllowPrivateEndpoint, conn.PrivateEgressCIDRs)
	if err != nil {
		return fail("the admin connection's endpoint is refused: " + err.Error())
	}
	provider, closeProvider, err := oauthrevoke.New(oauthrevoke.Connection{Provider: conn.Provider, BaseURL: conn.BaseURL, Token: []byte(token), Doer: client})
	if err != nil {
		return fail(err.Error())
	}
	defer closeProvider()
	var result oauthrevoke.Result
	switch in.Action {
	case orchestrator.OAuthActionRevokeGrant:
		result, err = provider.RevokeGrant(ctx, oauthrevoke.Grant{Principal: in.Principal, AppID: in.AppID, TenantWide: in.TenantWide})
	case orchestrator.OAuthActionBlockApp:
		result, err = provider.BlockApp(ctx, in.AppID)
	case orchestrator.OAuthActionUnblockApp:
		result, err = provider.UnblockApp(ctx, in.AppID)
	default:
		return fail("unknown action " + in.Action)
	}
	if err != nil {
		if oauthrevoke.Retryable(err) {
			return fmt.Errorf("server: OAuth provider action: %w", err)
		}
		return fail(err.Error())
	}
	status := orchestrator.OAuthActionConfirmed
	if result.Status == oauthrevoke.AlreadyAbsent {
		status = orchestrator.OAuthActionAlreadyAbsent
	}
	return d.orch.RecordOAuthProviderAction(ctx, m.TenantID, in, status, result.Detail)
}
