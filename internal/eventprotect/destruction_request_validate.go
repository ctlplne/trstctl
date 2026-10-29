// SPDX-License-Identifier: BUSL-1.1

package eventprotect

// Validate checks closed public coordinates. It grants no destruction: retained
// source, the exact committed invocation, retention and holds remain required.
func (request DestructionRequest) Validate() error { return validateDestructionRequest(request) }
