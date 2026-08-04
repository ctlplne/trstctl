// SPDX-License-Identifier: MPL-2.0

package main

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// The agent binary's channel must satisfy the renewal signer (epic B2).
//
// A compile-time assertion rather than a runtime check, because the failure it
// prevents is invisible at runtime: the renewal executor type-asserts for this
// interface and refuses the work when it is absent, so a build missing the
// method would claim renewal jobs and fail every one with a message about the
// build. The job would look attempted and the endpoint would never renew.
var _ relay.CSRSigner = relayChannel{}

func TestTheAgentChannelCanRequestSigning(t *testing.T) {
	t.Parallel()
	var ch any = relayChannel{}
	if _, ok := ch.(relay.CSRSigner); !ok {
		t.Fatal("the agent's channel cannot request signing, so every host-generated renewal " +
			"this agent claims would be refused by its own executor")
	}
}
