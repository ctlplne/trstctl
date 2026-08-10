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

	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/secrettext"
)

// Relay-executed MDM read (epic I5). Same shape as the CMDB sync: the relay
// READS AND PARSES from its vantage — an on-prem Jamf behind a firewall is
// exactly the CMDB's reachability problem — and the correlation happens in the
// control plane on the reported devices, so the join rule cannot fork by
// vantage.

// KindMDMSync is the relay-executed MDM read (I5).
const KindMDMSync = "mdm.sync"

// runMDMSync executes one mdm.sync job: redeem the token, GET the fixed
// endpoint, parse, report devices.
func runMDMSync(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent mdm.SyncIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not an mdm sync intent")
		return false
	}
	var endpoint string
	var err error
	switch intent.MDM {
	case mdm.MDMIntune:
		endpoint, err = mdm.IntuneDevicesEndpoint(intent.BaseURL, intent.Filter)
	case mdm.MDMJamf:
		endpoint, err = mdm.JamfDevicesEndpoint(intent.BaseURL, intent.Filter)
	default:
		report(ctx, ch, job, OutcomeFailed, "mdm sync intent names an unknown mdm")
		return false
	}
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "mdm base URL is not usable")
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
		report(ctx, ch, job, OutcomeFailed, "redemption did not include the mdm token reference")
		return false
	}

	if client == nil {
		// The loop always supplies its client; inventing an ambient one here
		// would bypass the egress posture the binary chose (SEC-005).
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for mdm reads")
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "mdm request could not be built")
		return false
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: mdm sync:", err)
		report(ctx, ch, job, OutcomeFailed, "mdm read failed from this relay's vantage")
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("mdm read failed with status %d", resp.StatusCode))
		return false
	}

	var devices []mdm.Device
	switch intent.MDM {
	case mdm.MDMIntune:
		devices, err = mdm.ParseIntuneDevices(io.LimitReader(resp.Body, maxCMDBResponseBytes))
	default:
		devices, err = mdm.ParseJamfDevices(io.LimitReader(resp.Body, maxCMDBResponseBytes))
	}
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "mdm response could not be parsed")
		return false
	}
	if intent.MDM == mdm.MDMIntune && len(intent.SCEPProfileIDs) > 0 {
		evidence, reportErr := mdm.ReadIntuneCertificateEvidence(ctx, client, intent.BaseURL, token, intent.SCEPProfileIDs)
		if reportErr != nil {
			report(ctx, ch, job, OutcomeFailed, "Intune certificate evidence report could not be read")
			return false
		}
		mdm.AttachIntuneCertificateEvidence(devices, evidence)
	}
	detail, err := json.Marshal(struct {
		ObservedAt time.Time    `json:"observed_at"`
		MDM        string       `json:"mdm"`
		Devices    []mdm.Device `json:"devices"`
	}{ObservedAt: time.Now().UTC(), MDM: intent.MDM, Devices: devices})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "mdm devices could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
