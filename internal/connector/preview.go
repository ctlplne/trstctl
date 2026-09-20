// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"context"
	"errors"
	"fmt"
)

// Preview is an effect-free answer from the exact connector that would later
// deploy. It contains only operator-readable routing and effect descriptions;
// credential values and certificate/private-key bytes never enter this shape.
type Preview struct {
	Endpoint    string
	WouldMutate []string
	Detail      string
}

// Previewer is the optional zero-write contract for a connector. Preview must
// authenticate to the receiver using a read-only provider operation and must
// never call Deploy or any mutation endpoint. A connector without this explicit
// contract fails closed instead of receiving a generic green check.
type Previewer interface {
	Connector
	Preview(ctx context.Context, sb Sandbox, target string) (Preview, error)
}

// ErrPreviewUnsupported means the connector has not implemented an auditable
// zero-write target test. Callers must not downgrade this to "ready".
var ErrPreviewUnsupported = errors.New("connector: this family has no effect-free preview contract")

// RunPreview executes only the connector's Preview method through its normal
// capability sandbox. Deploy is unreachable from this function by construction.
func RunPreview(ctx context.Context, c Connector, ops Ops, target string) (Preview, error) {
	previewer, ok := c.(Previewer)
	if !ok {
		return Preview{}, ErrPreviewUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	plan, err := previewer.Preview(ctx, sb, target)
	if err != nil {
		return Preview{}, err
	}
	if len(plan.WouldMutate) == 0 || plan.Detail == "" {
		return Preview{}, fmt.Errorf("connector: preview returned no operator-usable effect plan")
	}
	return plan, nil
}
