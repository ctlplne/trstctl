// SPDX-License-Identifier: BUSL-1.1
package secretrender

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// prepareReplacement binds the first rendered lease to the reviewed publication.
// Once the ordinary lease loop replaces it, persisted state prevents re-bootstrap.
func (r *Renderer) prepareReplacement(ctx context.Context, t Template, st *templateState) error {
	if t.Replacement == nil {
		return nil
	}
	b := t.Replacement
	if st.ReplacementChangeID != "" {
		if st.ReplacementChangeID != b.ChangeID {
			return errors.New("replacement change differs from persisted renderer state")
		}
		return nil
	}
	reader, ok := r.fetch.(ReplacementReader)
	if !ok {
		return errors.New("replacement publication reader is unavailable")
	}
	p, err := reader.ReadReplacement(ctx, b.ChangeID)
	if err != nil {
		return err
	}
	if p.ID != b.ChangeID || p.Action != "replace_key" || p.Consumer != r.cfg.Consumer || p.Provider != b.Provider || p.Role != b.Role {
		return errors.New("replacement publication does not match this consumer and lease")
	}
	if p.State != "waiting_adoption" && p.State != "verified" {
		return errors.New("replacement is waiting for approved publication")
	}
	if p.LeaseID == "" || p.NativeRoleID == "" || p.Version != p.ExpectedVersion+1 || p.ExpectedVersion < 1 || !r.now().Before(p.ExpiresAt) {
		return errors.New("replacement publication lacks a live exact native session")
	}
	ref := b.Provider + "/" + b.Role
	if st.Leases[ref].ID != "" {
		return errors.New("replacement cannot overwrite an existing unrelated renderer lease")
	}
	if st.Leases == nil {
		st.Leases = map[string]leaseState{}
	}
	st.Leases[ref] = leaseState{ID: p.LeaseID, ExpiresAt: p.ExpiresAt, HardExpiresAt: p.ExpiresAt, BootstrapName: b.Role, BootstrapVersion: p.Version}
	st.ReplacementChangeID = b.ChangeID
	// A previous static template's successful probe cannot verify this new credential.
	st.Verified = false
	st.Removed = true
	return nil
}

func (r *Renderer) fetchReplacement(ctx context.Context, ls leaseState) (Lease, error) {
	raw, version, err := r.fetch.Fetch(ctx, ls.BootstrapName)
	if err != nil {
		return Lease{}, err
	}
	var expiry struct {
		Expiration time.Time `json:"expiration"`
	}
	if version != ls.BootstrapVersion || json.Unmarshal(raw, &expiry) != nil || !expiry.Expiration.Equal(ls.ExpiresAt) || !r.now().Before(expiry.Expiration) {
		secret.Wipe(raw)
		return Lease{}, errors.New("replacement secret version or native expiry differs from the approved publication")
	}
	return Lease{ID: ls.ID, Credential: raw, ExpiresAt: ls.ExpiresAt, HardExpiresAt: ls.HardExpiresAt}, nil
}

// ReadReplacement reads public metadata only; the credential is fetched through
// the existing name-scoped secret endpoint after these bindings are checked.
func (c *HTTPClient) ReadReplacement(ctx context.Context, id string) (ReplacementPublication, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+"/api/v1/cloud-entitlements/changes/"+url.PathEscape(id), nil)
	if err != nil {
		return ReplacementPublication{}, err
	}
	resp, err := c.do(req)
	if err != nil {
		return ReplacementPublication{}, errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ReplacementPublication{}, errors.New("replacement publication is not accessible")
	}
	return decodeReplacementPublication(resp.Body)
}

func decodeReplacementPublication(reader io.Reader) (ReplacementPublication, error) {
	var body struct {
		ID     string `json:"id"`
		State  string `json:"state"`
		Intent struct {
			Action          string `json:"action"`
			Consumer        string `json:"consumer"`
			Provider        string `json:"replacement_provider_id"`
			Role            string `json:"replacement_role"`
			ExpectedVersion int    `json:"replacement_expected_version"`
		} `json:"intent"`
		Result struct {
			LeaseID      string    `json:"replacement_lease_id"`
			NativeRoleID string    `json:"replacement_native_role_id"`
			Version      int       `json:"replacement_version"`
			ExpiresAt    time.Time `json:"replacement_expires_at"`
		} `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(reader, 1<<20)).Decode(&body) != nil {
		return ReplacementPublication{}, errors.New("replacement publication could not be read")
	}
	return ReplacementPublication{ID: body.ID, State: body.State, Action: body.Intent.Action, Consumer: body.Intent.Consumer, Provider: body.Intent.Provider, Role: body.Intent.Role, ExpectedVersion: body.Intent.ExpectedVersion, Version: body.Result.Version, LeaseID: body.Result.LeaseID, NativeRoleID: body.Result.NativeRoleID, ExpiresAt: body.Result.ExpiresAt}, nil
}
