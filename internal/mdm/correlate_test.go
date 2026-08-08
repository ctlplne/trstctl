// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"net/url"
	"strings"
	"testing"
)

// Read-only must be structural: nothing here may construct a URL that is not a
// fixed read path, and a caller-supplied filter must never reach the path.
func TestAFilterCannotEscapeIntoTheMDMPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, base, arg, wantPath string
		build                     func(string, string) (string, error)
	}{
		{"intune", "https://graph.microsoft.com", "../../users?x=1",
			"/v1.0/deviceManagement/managedDevices", IntuneDevicesEndpoint},
		{"jamf", "https://example.jamfcloud.com", "../../v1/scripts",
			"/api/v1/computers-inventory", JamfDevicesEndpoint},
	} {
		got, err := tc.build(tc.base, tc.arg)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatal(err)
		}
		if u.Path != tc.wantPath {
			t.Fatalf("%s path = %q, want %q. A caller who can choose the path can read — or "+
				"write — a resource this feature has no business touching", tc.name, u.Path, tc.wantPath)
		}
	}
}

// An unrecognised MDM state must be UNKNOWN, never failed.
//
// Microsoft adds registration states. A mapping that treated a new one as a
// failure would raise alerts on healthy devices the first time Graph shipped a
// value we had not seen.
func TestAnUnrecognisedIntuneStateIsUnknownNotFailed(t *testing.T) {
	t.Parallel()
	if got := intuneState("someFutureStateMicrosoftAdds"); got != OutcomeUnknown {
		t.Fatalf("unknown state mapped to %q. Treating a state we do not recognise as a failure "+
			"raises alerts on healthy devices the first time the vendor ships a new value", got)
	}
	if got := intuneState("registered"); got != OutcomeOK {
		t.Fatalf("registered = %q, want ok", got)
	}
	if got := intuneState("revoked"); got != OutcomeFailed {
		t.Fatalf("revoked = %q, want failed", got)
	}
}

// Jamf's inventory endpoint does not report per-profile install state, so
// claiming "ok" would assert something we never observed.
func TestJamfDoesNotClaimAnInstallItDidNotObserve(t *testing.T) {
	t.Parallel()
	got, err := ParseJamfDevices(strings.NewReader(
		`{"results":[{"id":"7","general":{"name":"mac-1"},"hardware":{"serialNumber":"C02XYZ"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("parsed %d devices", len(got))
	}
	if got[0].InstallState != OutcomeUnknown {
		t.Fatalf("install state = %q. Jamf's inventory endpoint does not report per-profile state, "+
			"so anything but unknown asserts something this system never observed", got[0].InstallState)
	}
	if got[0].SerialNumber != "C02XYZ" {
		t.Fatalf("serial = %q, want the hardware serial — it is the join key", got[0].SerialNumber)
	}
}

// A device record with no id joins to nothing and must not become a row.
func TestDevicesWithNoIDAreNotCorrelated(t *testing.T) {
	t.Parallel()
	got, err := ParseIntuneDevices(strings.NewReader(
		`{"value":[{"id":"","deviceName":"ghost"},{"id":"d1","deviceName":"real","serialNumber":"S1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MDMDeviceID != "d1" {
		t.Fatalf("parsed = %+v, want only the correlatable device; a row that joins to nothing "+
			"is a row in the join that means nothing", got)
	}
}

// Both sides' gaps are findings, not noise to drop.
func TestUnmatchedDevicesAndCertificatesAreBothReported(t *testing.T) {
	t.Parallel()
	devices := []Device{
		{MDM: MDMIntune, MDMDeviceID: "d1", SerialNumber: "S1"},
		{MDM: MDMIntune, MDMDeviceID: "d2", SerialNumber: "S-NOCERT"},
		{MDM: MDMIntune, MDMDeviceID: "d3", SerialNumber: ""},
	}
	matched, unmatchedDevices, unmatchedSerials := CorrelateBySerial(devices,
		map[string]string{"S1": "identity-1", "S-NODEVICE": "identity-2"})

	if len(matched) != 1 || matched[0].MDMDeviceID != "d1" {
		t.Fatalf("matched = %+v", matched)
	}
	if len(unmatchedDevices) != 2 {
		t.Fatalf("unmatched devices = %+v, want the no-cert and the no-serial ones. A device with "+
			"no certificate is a finding, and dropping it makes the estate look covered", unmatchedDevices)
	}
	if len(unmatchedSerials) != 1 || unmatchedSerials[0] != "S-NODEVICE" {
		t.Fatalf("unmatched serials = %v, want the certificate with no device. A certificate "+
			"nobody can tie to a device is exactly what this epic exists to surface", unmatchedSerials)
	}
}

// Serial matching must not depend on the case an MDM happens to report.
func TestSerialMatchingIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	matched, _, _ := CorrelateBySerial(
		[]Device{{MDM: MDMJamf, MDMDeviceID: "j1", SerialNumber: "c02xyz"}},
		map[string]string{"C02XYZ": "identity-1"})
	if len(matched) != 1 {
		t.Fatal("a serial differing only in case failed to match; the same laptop would appear as " +
			"both an uncorrelated device and an uncorrelated certificate")
	}
}

// An MDM answering with an unbounded body must not exhaust this process.
func TestAnOversizedMDMResponseIsBounded(t *testing.T) {
	t.Parallel()
	huge := `{"value":[{"id":"d1","deviceName":"` + strings.Repeat("a", responseLimit) + `"}]}`
	if _, err := ParseIntuneDevices(strings.NewReader(huge)); err == nil {
		t.Fatal("a response larger than the limit parsed successfully; an integration operators " +
			"think of as read-only can still be a denial of service")
	}
}
