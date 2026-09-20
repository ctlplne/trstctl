// SPDX-License-Identifier: BUSL-1.1

package mdm

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
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

// deviceRegistrationState says whether the DEVICE is registered. It does not
// say whether the SCEP profile or the exact certificate installed. Treating
// "registered" as installed was AUD-50's remaining false positive.
func TestIntuneDeviceRegistrationStateNeverClaimsCertificateInstallation(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"registered", "revoked", "someFutureStateMicrosoftAdds"} {
		got, err := ParseIntuneDevices(strings.NewReader(`{"value":[{"id":"d1","deviceName":"laptop","serialNumber":"SER1","deviceRegistrationState":"` + state + `"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].InstallState != OutcomeUnknown || got[0].InstallObserved {
			t.Fatalf("registration state %q produced %+v; only certificate/profile readback may claim installation", state, got)
		}
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

func TestJamfCertificateInventoryCarriesExactInstallEvidence(t *testing.T) {
	t.Parallel()
	endpoint, err := JamfDevicesEndpoint("https://example.jamfcloud.com", "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Join(u.Query()["section"], ",")
	for _, required := range []string{"GENERAL", "HARDWARE", "CERTIFICATES"} {
		if !strings.Contains(sections, required) {
			t.Fatalf("Jamf read sections = %q; %s is required for exact certificate installation evidence", sections, required)
		}
	}
	got, err := ParseJamfDevices(strings.NewReader(`{"results":[{"id":"7","general":{"name":"mac-1"},"hardware":{"serialNumber":"C02XYZ"},"certificates":[{"serialNumber":"00A7","certificateStatus":"ACTIVE","commonName":"C02XYZ"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].InstallObserved || len(got[0].Certificates) != 1 || got[0].Certificates[0].SerialNumber != "00A7" {
		t.Fatalf("Jamf certificate evidence = %+v; want an explicit, attributable inventory observation", got)
	}
}

func TestIntuneCertificateReportUsesOnlyExactDeviceAndCertificateEvidence(t *testing.T) {
	t.Parallel()
	zipBytes := newIntuneReportZIP(t, "DeviceId,PolicyId,SerialNumber,CertificateStatus,ValidTo\n"+
		"device-7,profile-9,00A7,Active,2030-01-01T00:00:00Z\n")
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body string
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/beta/deviceManagement/reports/exportJobs"):
			body = `{"id":"job-7","status":"notStarted"}`
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "exportJobs"):
			body = `{"id":"job-7","status":"completed","url":"https://download.example.test/report.zip"}`
		case req.Method == http.MethodGet && req.URL.Host == "download.example.test":
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(zipBytes)), Request: req}, nil
		default:
			t.Fatalf("unexpected Intune report request: %s %s", req.Method, req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	got, err := ReadIntuneCertificateEvidence(context.Background(), client, "https://graph.microsoft.com", []byte("token"), []string{"profile-9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MDMDeviceID != "device-7" || got[0].SerialNumber != "00A7" || got[0].Status != "Active" {
		t.Fatalf("Intune certificate evidence = %+v; want exact device/profile/certificate observation", got)
	}
}

func TestCertificateInstallationRequiresTheExactIssuedSerialAndProviderStatus(t *testing.T) {
	t.Parallel()
	device := Device{
		MDM: MDMIntune, MDMDeviceID: "device-7", InstallObserved: true,
		Certificates: []CertificateObservation{
			{MDMDeviceID: "device-7", PolicyID: "profile-9", SerialNumber: "00:A7", Status: "Active"},
		},
	}
	if outcome, detail := EvaluateCertificateInstallation(device, "a7"); outcome != OutcomeOK || !strings.Contains(detail, "exact issued serial") {
		t.Fatalf("matching evidence = %q %q, want attributable ok", outcome, detail)
	}
	if outcome, detail := EvaluateCertificateInstallation(device, "b8"); outcome != OutcomeFailed || !strings.Contains(detail, "did not contain") {
		t.Fatalf("different certificate = %q %q, want explicit failed readback", outcome, detail)
	}
	device.InstallObserved = false
	if outcome, _ := EvaluateCertificateInstallation(device, "a7"); outcome != OutcomeUnknown {
		t.Fatalf("unobserved provider evidence = %q, want unknown", outcome)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func newIntuneReportZIP(t *testing.T, contents string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("CertificatesByRAPolicy.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, contents); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
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
