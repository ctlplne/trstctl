// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
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

// clientCredentialsFailure names a refused token exchange without its details.
func clientCredentialsFailure(err error) string {
	switch {
	case errors.Is(err, mdm.ErrClientCredentialsRefused):
		return "the identity platform refused the client ID or client secret"
	case errors.Is(err, mdm.ErrClientNotAuthorized):
		return "the app registration is not authorized for Microsoft Graph application access"
	default:
		return "the client-credentials token exchange failed from this relay's vantage"
	}
}

// jamfClientFailure is the operator-facing reason a Jamf Pro API client's
// exchange failed (A156-L1).
func jamfClientFailure(err error) string {
	if errors.Is(err, mdm.ErrJamfClientRefused) {
		return "Jamf Pro refused the API client ID or client secret"
	}
	return "the Jamf Pro API client token exchange failed from this relay's vantage"
}

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
	// A156 / A156-L1: the redeemed material is the app registration's or the
	// Jamf Pro API client's secret, exchanged for an access token. A156-L2:
	// the relay keeps that token across jobs and exchanges again only when
	// it nears expiry, the secret changed, or the MDM refused it.
	bearer, refusal := newMDMBearer(ctx, client, intent.MDM, intent.BaseURL, intent.ClientCredentials, intent.JamfAPIClient, token)
	if refusal != "" {
		report(ctx, ch, job, OutcomeFailed, refusal)
		return false
	}
	defer bearer.close()
	readAt := func(endpoint string) (*http.Response, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, "mdm request could not be built")
			return nil, false
		}
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", bearer.token))
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: mdm sync:", err)
			report(ctx, ch, job, OutcomeFailed, "mdm read failed from this relay's vantage")
			return nil, false
		}
		return resp, true
	}
	read := func() (*http.Response, bool) { return readAt(endpoint) }
	resp, ok := read()
	if !ok {
		return false
	}
	if resp.StatusCode == http.StatusUnauthorized {
		again, refusal := bearer.refused()
		if refusal != "" {
			_ = resp.Body.Close()
			report(ctx, ch, job, OutcomeFailed, refusal)
			return false
		}
		if again {
			_ = resp.Body.Close()
			if resp, ok = read(); !ok {
				return false
			}
		}
	}
	token = bearer.token
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
	if intent.MDM == mdm.MDMJamf && intent.JamfMobileDevices {
		// N9-L1: the mobile device inventory, with the same token. The
		// schedule asked for it, so a refusal fails the read rather than
		// leaving the mobile devices silently out.
		mobile, refusal := readJamfMobileDevices(intent.BaseURL, readAt)
		if refusal != "" {
			report(ctx, ch, job, OutcomeFailed, refusal)
			return false
		}
		devices = append(devices, mobile...)
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

// readJamfMobileDevices reads the first page of Jamf Pro's mobile device
// inventory (N9-L1) and says why when it cannot.
func readJamfMobileDevices(base string, readAt func(string) (*http.Response, bool)) ([]mdm.Device, string) {
	endpoint, err := mdm.JamfMobileDevicesEndpoint(base)
	if err != nil {
		return nil, "mdm base URL is not usable"
	}
	resp, ok := readAt(endpoint)
	if !ok {
		return nil, "the Jamf mobile device inventory read failed from this relay's vantage"
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Sprintf("Jamf refused the mobile device inventory read with status %d: the API role needs Read Mobile Devices", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Sprintf("the Jamf mobile device inventory read failed with status %d", resp.StatusCode)
	}
	devices, err := mdm.ParseJamfMobileDevices(io.LimitReader(resp.Body, maxCMDBResponseBytes))
	if err != nil {
		return nil, "the Jamf mobile device inventory could not be parsed"
	}
	return devices, ""
}
