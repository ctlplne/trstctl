// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Read-only device correlation against Intune and Jamf (epic I5).
//
// The acceptance says "read-only proven (no MDM writes)". That is held here the
// way I2 holds it for the CMDB: this file contains no request builder that can
// emit anything but a GET, and the two endpoint helpers below are the ONLY
// places a URL is constructed, each against a fixed path. A configuration flag
// would be one careless default away from writing to a customer's device
// management system, where a bad write does not corrupt a record — it pushes a
// profile to real laptops.

// MDM names a supported device management system. Intune and Jamf are kept
// distinct rather than normalised: an estate can run both, and a device present
// in one is not evidence about the other.
const (
	MDMIntune = "intune"
	MDMJamf   = "jamf"
)

// responseLimit bounds one page. An MDM answering with an unbounded body would
// otherwise exhaust this process through an integration operators think of as
// read-only.
const responseLimit = 8 << 20

// Device is one MDM device record, reduced to what correlation needs.
//
// Deliberately NOT the MDM's full record. Copying device inventory would create
// a second, staler source of truth about devices that somebody would eventually
// trust over the MDM itself.
type Device struct {
	MDM          string
	MDMDeviceID  string
	Name         string
	SerialNumber string
	// InstallState is the MDM's word about the certificate profile, in our
	// vocabulary. Unknown is NOT failed.
	InstallState  Outcome
	InstallDetail string
	ObservedAt    time.Time
}

// IntuneDevicesEndpoint builds the Microsoft Graph managed-devices read URL.
//
// GET only, fixed path. A caller cannot steer this at another resource: the
// filter travels as an encoded $filter parameter, never as a path segment.
func IntuneDevicesEndpoint(base, filter string) (string, error) {
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1.0/deviceManagement/managedDevices"
	q := url.Values{}
	if f := strings.TrimSpace(filter); f != "" {
		q.Set("$filter", f)
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

// JamfDevicesEndpoint builds the Jamf Pro computer-inventory read URL.
func JamfDevicesEndpoint(base, section string) (string, error) {
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/computers-inventory"
	q := url.Values{}
	// Only the sections correlation needs. Asking for everything would pull
	// user and location data this feature has no use for, and data you did not
	// need is data you should not have fetched.
	s := strings.TrimSpace(section)
	if s == "" {
		s = "GENERAL,HARDWARE"
	}
	q.Set("section", s)
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func parseAbsolute(base string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return nil, fmt.Errorf("mdm: parse base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("mdm: base URL must be absolute")
	}
	return u, nil
}

// ParseIntuneDevices maps a Graph managedDevices response.
func ParseIntuneDevices(r io.Reader) ([]Device, error) {
	var resp struct {
		Value []struct {
			ID           string `json:"id"`
			DeviceName   string `json:"deviceName"`
			SerialNumber string `json:"serialNumber"`
			// Graph's own vocabulary for the compliance/profile state.
			State  string `json:"deviceRegistrationState"`
			Detail string `json:"managementAgent"`
			// lastSyncDateTime is the DEVICE's last check-in, and it is what
			// ObservedAt must carry: the renewal check asks when the MDM last
			// heard from the device, and stamping the POLL time instead would
			// make every device look fresh on every poll — defeating the one
			// question the offline-renewal check exists to ask.
			LastSync string `json:"lastSyncDateTime"`
		} `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r, responseLimit)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("mdm: parse Intune managedDevices: %w", err)
	}
	out := make([]Device, 0, len(resp.Value))
	for _, d := range resp.Value {
		if strings.TrimSpace(d.ID) == "" {
			// A device record with no id cannot be correlated to anything, and
			// keeping it would put a row in the join that joins to nothing.
			continue
		}
		out = append(out, Device{
			MDM: MDMIntune, MDMDeviceID: d.ID, Name: d.DeviceName,
			SerialNumber: d.SerialNumber, InstallState: intuneState(d.State),
			InstallDetail: strings.TrimSpace(d.Detail),
			// The device's OWN last check-in, never the poll time. A record
			// with no lastSyncDateTime carries a ZERO ObservedAt — "the MDM
			// did not say" — which the renewal check treats as never observed
			// rather than as fresh.
			ObservedAt: parseMDMTime(d.LastSync),
		})
	}
	return out, nil
}

// parseMDMTime reads an MDM timestamp, zero when absent or unparseable: "the
// MDM did not say when" must never be recorded as "just now".
func parseMDMTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// intuneState maps Graph's registration states onto our three-value vocabulary.
//
// Anything unrecognised becomes UNKNOWN rather than failed. Microsoft adds
// states; a mapping that treated a new one as a failure would raise alerts on
// healthy devices the first time Graph shipped a value we had not seen.
func intuneState(s string) Outcome {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "registered":
		return OutcomeOK
	case "revoked", "keyconflict", "approvalpending", "certificatereset", "notregisteredpendingenrollment":
		return OutcomeFailed
	default:
		return OutcomeUnknown
	}
}

// ParseJamfDevices maps a Jamf Pro computers-inventory response.
func ParseJamfDevices(r io.Reader) ([]Device, error) {
	var resp struct {
		Results []struct {
			ID      string `json:"id"`
			General struct {
				Name string
				// The device's last check-in, for the same reason Intune's
				// lastSyncDateTime is read: the renewal check asks when the
				// MDM last HEARD from the device.
				LastContactTime string `json:"lastContactTime"`
			} `json:"general"`
			Hardware struct {
				SerialNumber string `json:"serialNumber"`
			} `json:"hardware"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(r, responseLimit)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("mdm: parse Jamf computers-inventory: %w", err)
	}
	out := make([]Device, 0, len(resp.Results))
	for _, d := range resp.Results {
		if strings.TrimSpace(d.ID) == "" {
			continue
		}
		out = append(out, Device{
			MDM: MDMJamf, MDMDeviceID: d.ID, Name: d.General.Name,
			SerialNumber: d.Hardware.SerialNumber,
			// Jamf's inventory endpoint does not report per-profile install
			// state. UNKNOWN is the honest answer: claiming "ok" because the
			// device is enrolled would assert something we did not observe.
			InstallState: OutcomeUnknown,
			InstallDetail: "Jamf computers-inventory does not report per-profile install state; " +
				"the certificate's presence on this device has not been observed.",
			ObservedAt: parseMDMTime(d.General.LastContactTime),
		})
	}
	return out, nil
}

// CorrelateBySerial joins MDM devices to our SCEP transactions by serial number.
//
// Serial is the join key because it is the one identifier both sides genuinely
// hold: the MDM records it from the hardware, and a SCEP subject that carries it
// is the convention every MDM SCEP profile template uses. Matching on device
// NAME would silently join two laptops an admin happened to name the same.
//
// Unmatched rows on both sides are returned rather than dropped: an MDM device
// with no certificate and a certificate with no MDM device are both findings,
// and a correlation that reported only its successes would make an estate look
// fully covered because the gaps were invisible.
func CorrelateBySerial(devices []Device, bySerial map[string]string) (matched []Device, unmatchedDevices []Device, unmatchedSerials []string) {
	seen := map[string]bool{}
	for _, d := range devices {
		serial := strings.ToUpper(strings.TrimSpace(d.SerialNumber))
		if serial == "" {
			unmatchedDevices = append(unmatchedDevices, d)
			continue
		}
		if _, ok := bySerial[serial]; !ok {
			unmatchedDevices = append(unmatchedDevices, d)
			continue
		}
		seen[serial] = true
		matched = append(matched, d)
	}
	for serial := range bySerial {
		if !seen[serial] {
			unmatchedSerials = append(unmatchedSerials, serial)
		}
	}
	return matched, unmatchedDevices, unmatchedSerials
}

// SyncIntent is the payload of one relay-executed mdm.sync job (I5). Shared
// shape for the same reason the CMDB's is: the control plane enqueues it and
// the relay decodes it, and a drift fails every sync while both halves pass
// their own tests. TokenRef is a secret:// REFERENCE the relay redeems per
// attempt.
type SyncIntent struct {
	MDM      string `json:"mdm"`
	BaseURL  string `json:"base_url"`
	Filter   string `json:"filter,omitempty"`
	TokenRef string `json:"token_ref"`
}
