// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/agent/csitrust"
)

// TrustBundlePEM returns a TrustBundle's public CA certificates in the form the
// controller distributes them (A139): the CSI trust driver writes exactly these
// bytes into a pod's volume. A bundle that is not public certificates is an
// error, never written.
func (c *Client) TrustBundlePEM(ctx context.Context, name string) ([]byte, error) {
	st, body, err := c.request(ctx, http.MethodGet, trustBundleCollectionPath()+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return nil, csitrust.ErrBundleNotFound
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("k8s: read TrustBundle %s: status %d", name, st)
	}
	var obj struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("k8s: decode TrustBundle %s: %w", name, err)
	}
	bundle, _, err := trustBundlePEM(obj.Spec)
	if err != nil {
		return nil, fmt.Errorf("k8s: TrustBundle %s: %w", name, err)
	}
	return []byte(bundle), nil
}
