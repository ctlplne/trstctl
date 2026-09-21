// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

// Agent-claimable work must WAIT for an agent, never dead-letter before one can
// claim it.
//
// The control-plane dispatcher is the sole handler for every outbox sweep, and
// its default branch returns a hard error for an unrecognized destination —
// correct for a genuinely unknown one, catastrophic for a kind an AGENT is
// supposed to execute. A hard error burns the row's attempt budget and lands it
// in status='failed', and ClaimAgentJobs only ever hands out rows in 'pending'.
// The work dies before any agent sees it, while the API has already told the
// operator it is queued.
//
// This was already known. connector.rollback and connector.test carry explicit
// deferral cases with a comment spelling out exactly this failure. What nobody
// did was apply it to the other five claimable kinds — endpoint.verify,
// endpoint.renew, revocation.probe, adcs.inventory and trust.distribute — each
// of which enqueued rows that dead-lettered on arrival. Registering the endpoint
// verification scheduler made that visible: it began producing endpoint.verify
// rows that died immediately.
//
// So the dispatcher now derives the answer from agentJobKindAllowlist, and this
// test walks that allowlist rather than a list of its own. A kind added there
// cannot be forgotten here, because there is nothing here to forget.

func TestNoAgentClaimableKindIsEverDeadLettered(t *testing.T) {
	t.Parallel()
	if len(agentJobKindAllowlist) == 0 {
		t.Fatal("the claimable allowlist is empty; this guard is walking nothing")
	}
	d := &issuanceDispatcher{}
	for destination := range agentJobKindAllowlist {
		t.Run(destination, func(t *testing.T) {
			err := d.Deliver(context.Background(), orchestrator.Message{
				TenantID: "11111111-1111-1111-1111-111111111111", Destination: destination,
			})
			// Whatever happens, it must not be the "unsupported destination"
			// refusal: that is the hard error that burns the attempt budget and
			// puts the row beyond ClaimAgentJobs' reach.
			if err != nil && strings.Contains(err.Error(), "unsupported first-party outbox destination") {
				t.Fatalf("%s dead-letters instead of waiting for an agent: %v\n\nA claimable kind "+
					"reaching the default branch burns its attempts and lands in status='failed', "+
					"where ClaimAgentJobs (which requires 'pending') can never see it. Give it a "+
					"control-plane handler or let it defer.", destination, err)
			}
		})
	}
}

// A genuinely unknown destination must STILL fail hard. The fix above must not
// have turned the dispatcher into a global silent ACK — there is no second
// worker to own an unrecognized row, so accepting one would lose it quietly,
// which is worse than dead-lettering it loudly.
func TestAnUnknownDestinationStillFailsClosed(t *testing.T) {
	t.Parallel()
	d := &issuanceDispatcher{}
	for _, destination := range []string{"ca.rotate", "future.vendor.command", "connector.unimplemented"} {
		err := d.Deliver(context.Background(), orchestrator.Message{Destination: destination})
		if err == nil {
			t.Fatalf("%s was silently acknowledged", destination)
		}
		if orchestrator.IsDeliveryDeferred(err) {
			t.Fatalf("%s was deferred; an unknown destination has nothing to wait for and would "+
				"re-pend forever", destination)
		}
		if !strings.Contains(err.Error(), "unsupported first-party outbox destination") {
			t.Fatalf("%s error = %v, want the fail-closed refusal", destination, err)
		}
	}
}
