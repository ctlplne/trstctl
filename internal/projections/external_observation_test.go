// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// A180: an observer's configuration and an observation are checked before
// they are recorded.
func TestExternalObservationPayloadValidation(t *testing.T) {
	good := projections.ObserverRegistered{ID: "o1", Name: "probectl-eu", EventsURL: "https://probectl.example.test/events", CredentialRef: "secret://observers/eu", Enabled: true}
	if err := projections.ValidateObserverRegistered(good); err != nil {
		t.Fatalf("a valid observer was refused: %v", err)
	}
	for name, mutate := range map[string]func(*projections.ObserverRegistered){
		"no name":            func(o *projections.ObserverRegistered) { o.Name = "" },
		"odd name":           func(o *projections.ObserverRegistered) { o.Name = "probe/ctl" },
		"plain http":         func(o *projections.ObserverRegistered) { o.EventsURL = "http://probectl.example.test/events" },
		"credentials in url": func(o *projections.ObserverRegistered) { o.EventsURL = "https://user:pw@probectl.example.test/events" },
		"inline credential":  func(o *projections.ObserverRegistered) { o.CredentialRef = "hunter2" },
	} {
		o := good
		mutate(&o)
		if err := projections.ValidateObserverRegistered(o); err == nil {
			t.Errorf("%s: accepted %+v", name, o)
		}
	}
	fp := strings.Repeat("ab", 32)
	observation := projections.ObservationRecorded{ID: "x1", ObserverID: "o1", Endpoint: "checkout.example.test:443",
		ObservedAt: time.Now().UTC(), Reachable: true, Health: "healthy", ServedFingerprint: fp, ExpectedFingerprint: fp, Verdict: "match"}
	if err := projections.ValidateObservationRecorded(observation); err != nil {
		t.Fatalf("a valid observation was refused: %v", err)
	}
	for name, mutate := range map[string]func(*projections.ObservationRecorded){
		"no port":                func(o *projections.ObservationRecorded) { o.Endpoint = "checkout.example.test" },
		"unknown health":         func(o *projections.ObservationRecorded) { o.Health = "fine" },
		"unknown verdict":        func(o *projections.ObservationRecorded) { o.Verdict = "ok" },
		"uppercase fingerprint":  func(o *projections.ObservationRecorded) { o.ServedFingerprint = strings.ToUpper(fp) },
		"unreachable but served": func(o *projections.ObservationRecorded) { o.Reachable = false; o.Verdict = "unreachable" },
		"unreachable verdict":    func(o *projections.ObservationRecorded) { o.Reachable, o.ServedFingerprint = false, "" },
		"long detail":            func(o *projections.ObservationRecorded) { o.Detail = strings.Repeat("x", 2000) },
	} {
		o := observation
		mutate(&o)
		if err := projections.ValidateObservationRecorded(o); err == nil {
			t.Errorf("%s: accepted %+v", name, o)
		}
	}
}
