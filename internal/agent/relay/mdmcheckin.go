// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/secrettext"
)

// N9: a device check-in asked of the MDM, after trstctl's own approval —
// Intune's syncDevice action on one managed device, or a Jamf Pro blank push
// to one computer — so the device fetches its profiles (a new SCEP profile, a
// renewed certificate) now instead of at its next scheduled check-in. The
// relay runs it from its vantage with the MDM credentials it redeems for this
// job, as it runs mdm.sync. It is the only write trstctl makes to an MDM, and
// it carries no body: the MDM decides what the device then fetches.

// KindMDMCheckIn is the relay-executed MDM device check-in.
const KindMDMCheckIn = "mdm.device.check_in"

// Device identifiers a check-in may name: an Intune managed device ID, or a
// Jamf Pro computer ID (the inventory mdm.sync reads). Each travels as one
// escaped path segment of a fixed endpoint.
var (
	intuneDeviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	jamfDeviceID   = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// MDMCheckInIntent is the job payload: one device at one MDM.
type MDMCheckInIntent struct {
	ID                string                 `json:"id"`
	MDM               string                 `json:"mdm"`
	BaseURL           string                 `json:"base_url"`
	TokenRef          string                 `json:"token_ref"`
	ClientCredentials *mdm.ClientCredentials `json:"client_credentials,omitempty"`
	DeviceID          string                 `json:"device_id"`
	RequiredAgentID   string                 `json:"required_agent_id"`
}

// MDMCheckInReport is what returns: the MDM's answer to the check-in.
type MDMCheckInReport struct {
	MDM            string `json:"mdm"`
	DeviceID       string `json:"device_id"`
	ProviderStatus int    `json:"provider_status"`
}

// ValidMDMCheckInDevice says a device ID can travel in a check-in at that MDM.
func ValidMDMCheckInDevice(provider, deviceID string) bool {
	switch provider {
	case mdm.MDMIntune:
		return intuneDeviceID.MatchString(deviceID)
	case mdm.MDMJamf:
		return jamfDeviceID.MatchString(deviceID)
	}
	return false
}

// ValidateMDMCheckInIntent checks a queued check-in.
func ValidateMDMCheckInIntent(intent MDMCheckInIntent) error {
	switch {
	case intent.ID == "" || intent.TokenRef == "" || intent.RequiredAgentID == "":
		return errors.New("relay: an MDM check-in needs its id, the token reference and one exact relay")
	case intent.MDM != mdm.MDMIntune && intent.MDM != mdm.MDMJamf:
		return errors.New("relay: an MDM check-in names intune or jamf")
	case !ValidMDMCheckInDevice(intent.MDM, intent.DeviceID):
		return errors.New("relay: an MDM check-in names one Intune managed device or one Jamf computer")
	case intent.ClientCredentials != nil && intent.MDM != mdm.MDMIntune:
		return errors.New("relay: client credentials are only valid for Intune")
	}
	u, err := url.Parse(intent.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("relay: an MDM check-in needs an https base URL")
	}
	return nil
}

// ValidateMDMCheckInReport checks a relay's answer against the queued check-in.
func ValidateMDMCheckInReport(intent MDMCheckInIntent, r MDMCheckInReport) error {
	if r.MDM != intent.MDM || r.DeviceID != intent.DeviceID || r.ProviderStatus < 200 || r.ProviderStatus > 299 {
		return errors.New("relay: MDM check-in report names another device or no accepted check-in")
	}
	return nil
}

// MDMCheckInEndpoint is the one call a check-in makes: Graph's syncDevice
// action on one managed device, or a Jamf Pro blank push to one computer. No
// other MDM write exists in trstctl.
func MDMCheckInEndpoint(intent MDMCheckInIntent) string {
	base := strings.TrimRight(intent.BaseURL, "/")
	if intent.MDM == mdm.MDMIntune {
		return base + "/v1.0/deviceManagement/managedDevices/" + url.PathEscape(intent.DeviceID) + "/syncDevice"
	}
	return base + "/JSSResource/computercommands/command/BlankPush/id/" + url.PathEscape(intent.DeviceID)
}

func runMDMCheckIn(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent MDMCheckInIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || ValidateMDMCheckInIntent(intent) != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a check-in of one MDM device")
		return false
	}
	if client == nil {
		report(ctx, ch, job, OutcomeFailed, "this agent has no http client for MDM calls")
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
	if intent.ClientCredentials != nil {
		access, err := mdm.ExchangeClientCredentials(ctx, client, *intent.ClientCredentials, token)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, clientCredentialsFailure(err))
			return false
		}
		defer secret.Wipe(access)
		token = access
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, MDMCheckInEndpoint(intent), nil)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the check-in request could not be built")
		return false
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the MDM could not be reached from this relay's vantage")
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		report(ctx, ch, job, OutcomeFailed, fmt.Sprintf("the MDM refused the check-in with status %d", resp.StatusCode))
		return false
	}
	detail, err := json.Marshal(MDMCheckInReport{MDM: intent.MDM, DeviceID: intent.DeviceID, ProviderStatus: resp.StatusCode})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the check-in report could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
