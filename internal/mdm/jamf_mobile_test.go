// SPDX-License-Identifier: BUSL-1.1

package mdm

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// N9-L1: Jamf's mobile device inventory (Jamf Pro API v2 mobile device
// detail) is read on its own fixed URL, and each device is reported under a
// prefixed ID — Jamf numbers computers and mobile devices apart — with its
// last contact and no install evidence: Jamf names a mobile device's
// certificates without serial numbers.
func TestParseJamfMobileDevicesN9L1(t *testing.T) {
	endpoint, err := JamfMobileDevicesEndpoint("https://jamf.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(endpoint)
	if u.Path != "/api/v2/mobile-devices/detail" || strings.Join(u.Query()["section"], ",") != "GENERAL,HARDWARE" ||
		u.Query().Get("page") != "0" || u.Query().Get("page-size") != "100" {
		t.Fatalf("endpoint = %s", endpoint)
	}
	if _, err := JamfMobileDevicesEndpoint("jamf.example.test"); err == nil {
		t.Fatal("a relative base URL built an endpoint")
	}
	devices, err := ParseJamfMobileDevices(strings.NewReader(`{"totalCount":3,"results":[
		{"mobileDeviceId":"12","deviceType":"iOS","general":{"displayName":"ipad-12","lastContactDate":"2026-11-13T09:30:00.123Z","lastInventoryUpdateDate":"2026-11-12T00:00:00Z"},
		 "hardware":{"serialNumber":"IPAD-N9L1"},"certificates":[{"commonName":"IPAD-N9L1","identity":true,"expirationDate":"2027-11-13T00:00:00Z"}]},
		{"mobileDeviceId":"13","deviceType":"tvOS","general":{"displayName":"lobby-tv","lastInventoryUpdateDate":"2026-11-10T00:00:00Z"},"hardware":{"serialNumber":"TV-N9L1"}},
		{"mobileDeviceId":"","general":{"displayName":"no id"}}]}`))
	if err != nil || len(devices) != 2 {
		t.Fatalf("devices = %+v %v; want the two with an ID", devices, err)
	}
	ipad, tv := devices[0], devices[1]
	if ipad.MDM != MDMJamf || ipad.MDMDeviceID != "mobile-12" || !IsJamfMobileDeviceID(ipad.MDMDeviceID) || ipad.Name != "ipad-12" ||
		ipad.SerialNumber != "IPAD-N9L1" || !ipad.ObservedAt.Equal(time.Date(2026, 11, 13, 9, 30, 0, 123e6, time.UTC)) {
		t.Fatalf("ipad = %+v", ipad)
	}
	if ipad.InstallState != OutcomeUnknown || ipad.InstallObserved || len(ipad.Certificates) != 0 || !strings.Contains(ipad.InstallDetail, "without their serial numbers") {
		t.Fatalf("ipad install evidence = %+v", ipad)
	}
	if tv.MDMDeviceID != "mobile-13" || !tv.ObservedAt.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) || !strings.Contains(tv.InstallDetail, "tvOS") {
		t.Fatalf("tv = %+v; want the last inventory update when Jamf names no contact", tv)
	}
	if IsJamfMobileDeviceID("12") {
		t.Fatal("a computer ID reads as a mobile device")
	}
	if _, err := ParseJamfMobileDevices(strings.NewReader(`{"results":[`)); err == nil {
		t.Fatal("a truncated page parsed")
	}
}
