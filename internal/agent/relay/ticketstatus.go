// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/ticketintake"
)

// KindTicketStatus is the relay-executed read of ServiceNow change-request
// approvals (P13): the approval and state of exactly the tickets the job
// names, with the intake schedule's token redeemed for this one attempt.
const KindTicketStatus = "ticket.status"

func runTicketStatus(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent ticketintake.StatusIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a ticket status intent")
		return false
	}
	endpoint, err := ticketintake.StatusEndpoint(intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket status endpoint is not usable")
		return false
	}
	if client == nil {
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for ticket status reads")
		return false
	}
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "credential redemption was not granted")
		return false
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "redeemed material could not be taken into locked memory")
		return false
	}
	defer destroy()
	token, ok := material[intent.TokenRef]
	if !ok || len(token) == 0 {
		report(ctx, ch, job, OutcomeFailed, "redemption did not include the ticket token reference")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket status request could not be built")
		return false
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket status read failed from this relay's vantage")
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("ticket status read failed with status %d", resp.StatusCode))
		return false
	}
	tickets, err := ticketintake.ParseStatusPage(io.LimitReader(resp.Body, maxCMDBResponseBytes), intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket status response could not be parsed")
		return false
	}
	detail, err := json.Marshal(ticketintake.StatusReport{Schedule: ticketintake.ScheduleName(intent.Schedule),
		StatusID: intent.StatusID, ObservedAt: time.Now().UTC(), Tickets: tickets})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket status report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
