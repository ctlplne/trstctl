// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/ticketintake"
)

const KindTicketSync = "ticket.sync"

func runTicketSync(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent ticketintake.SyncIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a ticket sync intent")
		return false
	}
	endpoint, err := ticketintake.Endpoint(intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket intake endpoint is not usable")
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
		report(ctx, ch, job, OutcomeFailed, "redemption did not include the ticket intake token reference")
		return false
	}
	if client == nil {
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for ticket intake reads")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket intake request could not be built")
		return false
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: ticket sync:", err)
		report(ctx, ch, job, OutcomeFailed, "ticket intake read failed from this relay's vantage")
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("ticket intake read failed with status %d", resp.StatusCode))
		return false
	}
	tickets, err := ticketintake.Parse(io.LimitReader(resp.Body, maxCMDBResponseBytes), intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket intake response could not be parsed")
		return false
	}
	detail, err := json.Marshal(ticketintake.SyncReport{ObservedAt: time.Now().UTC(), Tickets: tickets})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket intake report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
