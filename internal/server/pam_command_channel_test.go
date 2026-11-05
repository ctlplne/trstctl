// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/transport"
)

func (c *sshCollectionServedChannel) ReviewGatewayAction(ctx context.Context, jobID int64, attempt int, key string, observation accessrules.Observation, cancel bool) (accessrules.Decision, error) {
	response, err := c.h.client.EvaluateGatewayAction(ctx, &transport.EvaluateGatewayActionRequest{JobID: jobID, Attempt: attempt, IdempotencyKey: key, Observation: observation, Cancel: cancel})
	if err != nil {
		return accessrules.Decision{}, err
	}
	return response.Decision, nil
}
