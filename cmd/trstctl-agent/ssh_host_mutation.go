// SPDX-License-Identifier: BUSL-1.1

package main

import "context"

// SSH trust and KRL installation share sshd validation/reload/health. Their
// independent workers must not reload while the other is midway through a
// checked change. Only this agent's mutations are serialized; administrator
// edits outside this process still require operator coordination.
var sshHostMutationSlot = make(chan struct{}, 1)

func acquireSSHHostMutation(ctx context.Context) (func(), error) {
	select {
	case sshHostMutationSlot <- struct{}{}:
		return func() { <-sshHostMutationSlot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
