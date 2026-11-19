// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"trstctl.com/trstctl/internal/agent/csitrust"
	"trstctl.com/trstctl/internal/kubetrust"
)

// TrustBundleSource is the cluster-local source for the CSI trust driver.
// Remote-origin bundles require explicit opt-in on the CSI process itself.
type TrustBundleSource struct {
	client      *Client
	allowRemote bool
}

func NewTrustBundleSource(c *Client, allowRemote bool) TrustBundleSource {
	return TrustBundleSource{client: c, allowRemote: allowRemote}
}

// TrustBundlePEM reads a locally authored bundle for CSI compatibility.
func (c *Client) TrustBundlePEM(ctx context.Context, name string) ([]byte, error) {
	return NewTrustBundleSource(c, false).TrustBundlePEM(ctx, name)
}

// TrustBundlePEM returns canonical public certificates from an admitted bundle.
func (s TrustBundleSource) TrustBundlePEM(ctx context.Context, name string) ([]byte, error) {
	if !kubetrust.ValidBundleName(name) {
		return nil, fmt.Errorf("k8s: invalid or reserved TrustBundle name %q", name)
	}
	st, body, err := s.client.request(ctx, http.MethodGet, trustBundleCollectionPath()+"/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return nil, csitrust.ErrBundleNotFound
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("k8s: read TrustBundle %s: status %d", name, st)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("k8s: decode TrustBundle %s: %w", name, err)
	}
	bundle, err := parseStoredTrustBundle(obj, s.allowRemote, false)
	if err != nil {
		return nil, fmt.Errorf("k8s: TrustBundle %s: %w", name, err)
	}
	if bundle.name != name {
		return nil, fmt.Errorf("k8s: unexpected TrustBundle identity returned for %s", name)
	}
	return []byte(bundle.pem), nil
}
