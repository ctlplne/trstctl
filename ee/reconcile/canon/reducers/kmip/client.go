// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/canon/reducers"
)

type Client struct {
	scope    string
	endpoint Endpoint
}

func NewClient(scope string, endpoint Endpoint) Client {
	return Client{scope: strings.TrimRight(strings.TrimSpace(scope), "/"), endpoint: endpoint}
}

func ReadOnlyKMIPObservationGrant(scope string) reducers.Grant {
	return reducers.ReadOnlyObservationGrant(scope)
}

func (c Client) Locate(ctx context.Context, sb *reducers.ObservationSandbox, tenantID string) ([]string, error) {
	if _, err := sb.List(ctx, c.resource("Locate", tenantID)); err != nil {
		return nil, err
	}
	if c.endpoint == nil {
		return nil, fmt.Errorf("xrec kmip: endpoint required")
	}
	return c.endpoint.Locate(ctx, tenantID)
}

func (c Client) GetAttributes(ctx context.Context, sb *reducers.ObservationSandbox, uniqueIdentifier string) (ManagedObject, error) {
	if _, err := sb.Describe(ctx, c.resource("GetAttributes", uniqueIdentifier)); err != nil {
		return ManagedObject{}, err
	}
	if c.endpoint == nil {
		return ManagedObject{}, fmt.Errorf("xrec kmip: endpoint required")
	}
	return c.endpoint.GetAttributes(ctx, uniqueIdentifier)
}

func (c Client) resource(op, id string) string {
	scope := c.scope
	if scope == "" {
		scope = "kmip"
	}
	return scope + "/" + strings.Trim(strings.TrimSpace(op), "/") + "/" + strings.Trim(strings.TrimSpace(id), "/")
}
