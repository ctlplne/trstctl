// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Read-only device correlation against Intune and Jamf (epic I5).
//
// The acceptance says "read-only proven (no MDM writes)". Inventory URLs are
// fixed GET resources. Intune's certificate evidence requires creating a
// fixed CertificatesByRAPolicy export artifact; that report-only POST is
// isolated in intune_report.go and cannot name a policy/device mutation path.
// A configuration flag would be one careless default away from writing to a
// customer's device management system, where a bad write pushes a profile to
// real laptops.

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
	// InstallState is populated only after the control plane compares an exact
	// issued-certificate serial with the certificate observations below.
	// Device enrollment or registration is never certificate evidence.
	InstallState  Outcome
	InstallDetail string
	// InstallObserved says the provider returned its certificate-specific
	// inventory/report for this device. An observed empty list is different
	// from a provider response that did not contain certificate evidence.
	InstallObserved bool
	Certificates    []CertificateObservation
	ObservedAt      time.Time
}

// CertificateObservation is one provider-attributable statement about one
// exact certificate. It is evidence, not a conclusion: the control plane must
// still compare SerialNumber with the immutable issuance event for the device.
type CertificateObservation struct {
	MDMDeviceID  string    `json:"mdm_device_id,omitempty"`
	PolicyID     string    `json:"policy_id,omitempty"`
	SerialNumber string    `json:"serial_number"`
	Status       string    `json:"status,omitempty"`
	CommonName   string    `json:"common_name,omitempty"`
	ValidTo      time.Time `json:"valid_to,omitempty"`
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
func JamfDevicesEndpoint(base, _ string) (string, error) {
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/computers-inventory"
	q := url.Values{}
	// These are the complete and fixed read sections correlation needs. The
	// caller cannot remove CERTIFICATES (which would erase install evidence) or
	// add privacy-heavy sections this feature has no use for.
	q.Add("section", "GENERAL")
	q.Add("section", "HARDWARE")
	q.Add("section", "CERTIFICATES")
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
			SerialNumber: d.SerialNumber, InstallState: OutcomeUnknown,
			InstallDetail: "Intune managedDevices reports device enrollment, not SCEP certificate installation; " +
				"certificate evidence requires a CertificatesByRAPolicy report for the configured profile.",
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
			Certificates json.RawMessage `json:"certificates"`
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
		device := Device{
			MDM: MDMJamf, MDMDeviceID: d.ID, Name: d.General.Name,
			SerialNumber: d.Hardware.SerialNumber,
			InstallState: OutcomeUnknown,
			InstallDetail: "Jamf certificate inventory was not present in this device response; " +
				"the issued certificate's presence has not been observed.",
			ObservedAt: parseMDMTime(d.General.LastContactTime),
		}
		raw := bytes.TrimSpace(d.Certificates)
		if len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
			var certificates []struct {
				SerialNumber      string `json:"serialNumber"`
				CertificateStatus string `json:"certificateStatus"`
				LifecycleStatus   string `json:"lifecycleStatus"`
				Status            string `json:"status"`
				CommonName        string `json:"commonName"`
				ExpirationDate    string `json:"expirationDate"`
			}
			if err := json.Unmarshal(raw, &certificates); err != nil {
				return nil, fmt.Errorf("mdm: parse Jamf certificate inventory for device %q: %w", d.ID, err)
			}
			device.InstallObserved = true
			device.InstallDetail = "Jamf returned the certificate inventory for this device; " +
				"the control plane must compare it with the exact issued serial."
			for _, certificate := range certificates {
				status := firstNonempty(certificate.CertificateStatus, certificate.LifecycleStatus, certificate.Status)
				device.Certificates = append(device.Certificates, CertificateObservation{
					MDMDeviceID:  d.ID,
					SerialNumber: strings.TrimSpace(certificate.SerialNumber),
					Status:       status,
					CommonName:   strings.TrimSpace(certificate.CommonName),
					ValidTo:      parseMDMTime(certificate.ExpirationDate),
				})
			}
		}
		out = append(out, device)
	}
	return out, nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
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
	MDM            string   `json:"mdm"`
	BaseURL        string   `json:"base_url"`
	Filter         string   `json:"filter,omitempty"`
	TokenRef       string   `json:"token_ref"`
	SCEPProfileIDs []string `json:"scep_profile_ids,omitempty"`
}
