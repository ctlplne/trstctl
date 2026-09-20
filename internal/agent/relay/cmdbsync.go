// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ownership"
)

// Relay-executed CMDB read (epic I2).
//
// The relay READS AND PARSES; it decides nothing. The reconcile — including
// the rule that a source never overwrites a human's attestation — runs in the
// control plane on the reported records, so there is exactly one
// implementation of the decision whichever vantage performed the read.

// KindCMDBSync is the relay-executed CMDB read (I2).
const KindCMDBSync = "cmdb.sync"

// maxCMDBResponseBytes bounds one page read. The parse happens here, so an
// instance replying with a 50MB error page costs this relay a bounded read and
// a failed report, not an unbounded buffer and a 50MB report row (AN-7).
const maxCMDBResponseBytes = 8 << 20

// runCMDBSync executes one cmdb.sync job: redeem the token, GET the one
// permitted table, parse, report the records.
func runCMDBSync(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent ownership.CMDBSyncIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a cmdb sync intent")
		return false
	}
	limit := intent.PageLimit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	endpoint, err := ownership.CMDBPageEndpoint(intent.InstanceURL, intent.CIQuery, limit, intent.AfterSysID)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "cmdb instance URL is not usable")
		return false
	}

	// The token is redeemed per attempt, exactly like an appliance credential:
	// the value never rides the queue, and this attempt's single redemption is
	// spent on the read it authorizes.
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
		report(ctx, ch, job, OutcomeFailed, "redemption did not include the cmdb token reference")
		return false
	}

	if client == nil {
		// The loop always supplies its client; a nil one means a caller that
		// cannot fetch, and inventing an ambient client here would bypass the
		// egress posture the binary chose (SEC-005).
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for cmdb reads")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "cmdb request could not be built")
		return false
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// The transport error can embed the URL with whatever rode it; local
		// stderr keeps the detail, the report keeps the closed phrase.
		fmt.Fprintln(os.Stderr, "trstctl-agent: cmdb sync:", err)
		report(ctx, ch, job, OutcomeFailed, "cmdb read failed from this relay's vantage")
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("cmdb read failed with status %d", resp.StatusCode))
		return false
	}

	page, err := ownership.ParseCMDBPage(io.LimitReader(resp.Body, maxCMDBResponseBytes))
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "cmdb response could not be parsed")
		return false
	}
	expected := intent.ExpectedCount
	if remaining, parseErr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("X-Total-Count"))); parseErr == nil && remaining >= 0 {
		total := intent.ReadCount + remaining
		expected = &total
	}
	detail, err := json.Marshal(ownership.CMDBSyncReport{
		SweepID: intent.SweepID, AfterSysID: intent.AfterSysID, ObservedAt: time.Now().UTC(),
		SourceRefs: page.SourceRefs, Records: page.Records, Unattributed: page.Unattributed,
		ReadCount: intent.ReadCount + len(page.SourceRefs), ExpectedCount: expected,
		Complete: len(page.SourceRefs) < limit,
	})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "cmdb records could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
