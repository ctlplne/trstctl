// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/scancollect"
	"trstctl.com/trstctl/internal/secretscan"
)

// collectThirdParty fetches a collected scan's content from the provider
// (N6) into a private temporary directory, in the layout of the provider's
// own export, and returns it as the scan target; the target's cleanup removes
// it. The connection's credentials are resolved here, for this call only.
func collectThirdParty(ctx context.Context, cfg secretscan.ThirdPartyScanConfig) (secretscan.ThirdPartyTarget, scancollect.Result, error) {
	c := cfg.Collect
	client, err := cloudHTTPClient(c.BaseURL, c.AllowPrivateEndpoint, c.PrivateEgressCIDRs)
	if err != nil {
		return secretscan.ThirdPartyTarget{}, scancollect.Result{}, fmt.Errorf("%w: the collection endpoint is refused: %v", scancollect.ErrRefused, err)
	}
	var token []byte
	if c.TokenRef != "" {
		if token, err = resolveDiscoveryCredentialBytesRef(ctx, c.TokenRef); err != nil {
			return secretscan.ThirdPartyTarget{}, scancollect.Result{}, fmt.Errorf("%w: resolve the collection token reference: %v", scancollect.ErrRefused, err)
		}
		defer secret.Wipe(token)
	}
	username, err := resolveOptionalDiscoveryCredentialRef(ctx, c.UsernameRef)
	if err != nil {
		return secretscan.ThirdPartyTarget{}, scancollect.Result{}, fmt.Errorf("%w: resolve the collection username reference: %v", scancollect.ErrRefused, err)
	}
	var since time.Time
	if lookback, err := c.SinceDuration(); err == nil && lookback > 0 {
		since = time.Now().Add(-lookback)
	}
	dir, err := os.MkdirTemp("", "trstctl-collect-*")
	if err != nil {
		return secretscan.ThirdPartyTarget{}, scancollect.Result{}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	result, err := scancollect.Collect(ctx, dir, scancollect.Request{
		Provider: secretscan.NormalizeThirdPartyProvider(cfg.Provider), BaseURL: c.BaseURL, Token: token, Username: username,
		Repository: c.Repository, Reference: c.Reference, Channels: c.Channels, Team: c.Team, JQL: c.JQL, CQL: c.CQL,
		System: c.System, Repo: c.Repo, Since: since,
		MaxItems: c.MaxItems, MaxBytes: c.MaxBytes, Doer: client,
	})
	if err != nil {
		cleanup()
		return secretscan.ThirdPartyTarget{}, result, err
	}
	return secretscan.ThirdPartyTarget{Path: dir, Cleanup: cleanup, Mode: "collected"}, result, nil
}
