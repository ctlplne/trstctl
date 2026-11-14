// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/ticketintake"
)

// KindTicketNote is the relay-executed work note on the ServiceNow ticket an
// intake-opened request came from (P13-L1): one decision trstctl recorded,
// written back once. The relay reads the ticket's work notes first and adds
// the note only when its marker is not there, so a replayed job adds nothing.
const KindTicketNote = ticketintake.NoteJobKind

func runTicketNote(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent ticketintake.NoteIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a ticket note intent")
		return false
	}
	readURL, writeURL, err := ticketintake.NoteEndpoints(intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket note endpoint is not usable")
		return false
	}
	body, err := ticketintake.NoteBody(intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket note body could not be built")
		return false
	}
	if client == nil {
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for ticket notes")
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
	call := func(method, target string, payload []byte) ([]byte, int, error) {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCMDBResponseBytes))
		return raw, resp.StatusCode, err
	}
	raw, status, err := call(http.MethodGet, readURL, nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket note read failed from this relay's vantage")
		return false
	}
	if status < 200 || status > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("ticket note read failed with status %d", status))
		return false
	}
	present, err := ticketintake.NoteAlreadyPresent(raw, intent.NoteID)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket note read could not be parsed")
		return false
	}
	outcome := ticketintake.NotePresent
	if !present {
		if _, status, err := call(http.MethodPatch, writeURL, body); err != nil {
			report(ctx, ch, job, OutcomeFailed, "ticket note write failed from this relay's vantage")
			return false
		} else if status < 200 || status > 299 {
			report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("ticket note write failed with status %d", status))
			return false
		}
		outcome = ticketintake.NoteAdded
	}
	detail, err := json.Marshal(ticketintake.NoteReport{Schedule: ticketintake.ScheduleName(intent.Schedule), NoteID: intent.NoteID,
		Outcome: outcome, ObservedAt: time.Now().UTC()})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "ticket note report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
