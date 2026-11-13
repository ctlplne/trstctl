// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/listenersessions"
	"trstctl.com/trstctl/internal/agent/transport"
)

// A245-L2 (relay): a verified host deploy's report carries the host's count
// of its listener's sessions against the deploy's start, and the evidence the
// receipt signs covers the count with the transcript; a count changed after
// signing no longer matches. A host that cannot count leaves the report and
// its evidence as they were.
func TestHostDeployReportCarriesListenerSessionsA245L2(t *testing.T) {
	tr := transport.ProbeTranscript{Address: "127.0.0.1:8443", Vantage: transport.VantageLocal, Reached: true,
		ExpectedFingerprint: "ab", ObservedFingerprint: "ab", ObservedAtUnix: 1_800_000_000}
	raw, err := json.Marshal(EndpointVerifyReport{Results: []EndpointVerifyResult{{EndpointID: "target-1", Transcript: tr}}})
	if err != nil {
		t.Fatal(err)
	}
	detail, evidence := string(raw), tr.Digest()
	started := time.Unix(1_800_000_000, 0)
	var askedPort int
	var askedSince time.Time
	defer func(prev func(int, time.Time) (listenersessions.Observation, error)) { observeListenerSessions = prev }(observeListenerSessions)
	observeListenerSessions = func(port int, since time.Time) (listenersessions.Observation, error) {
		askedPort, askedSince = port, since
		return listenersessions.Observation{Port: port, Established: 3, HeldByOlder: 1, SinceUnix: since.Unix(), CheckedAtUnix: since.Unix() + 2}, nil
	}
	intent := DeployIntent{TargetID: "target-1", VerifyAddress: "127.0.0.1:8443"}
	gotDetail, gotEvidence := withListenerSessions(intent, detail, evidence, started)
	if askedPort != 8443 || !askedSince.Equal(started) {
		t.Fatalf("counted port %d since %v", askedPort, askedSince)
	}
	var report EndpointVerifyReport
	if err := json.Unmarshal([]byte(gotDetail), &report); err != nil || len(report.Results) != 1 || report.Results[0].Sessions == nil {
		t.Fatalf("report = %s, %v", gotDetail, err)
	}
	s := report.Results[0].Sessions
	if s.Port != 8443 || s.Established != 3 || s.HeldByOlder != 1 || s.SinceUnix != started.Unix() {
		t.Fatalf("sessions = %+v", s)
	}
	if gotEvidence == evidence || gotEvidence != DeploymentEvidenceDigest(report.Results[0]) {
		t.Fatalf("evidence %s does not cover the count (transcript %s)", gotEvidence, evidence)
	}
	tampered := report.Results[0]
	changed := *tampered.Sessions
	changed.HeldByOlder = 0
	tampered.Sessions = &changed
	if DeploymentEvidenceDigest(tampered) == gotEvidence {
		t.Fatal("a changed count still matches the signed evidence")
	}
	if bare := (EndpointVerifyResult{Transcript: tr}); DeploymentEvidenceDigest(bare) != tr.Digest() {
		t.Fatal("a report without a count no longer signs the bare transcript digest")
	}

	observeListenerSessions = func(int, time.Time) (listenersessions.Observation, error) {
		return listenersessions.Observation{}, listenersessions.ErrUnsupported
	}
	if d, e := withListenerSessions(intent, detail, evidence, started); d != detail || e != evidence {
		t.Fatal("a host that cannot count changed the report")
	}
	observeListenerSessions = func(int, time.Time) (listenersessions.Observation, error) {
		return listenersessions.Observation{}, errors.New("unreadable")
	}
	if d, e := withListenerSessions(DeployIntent{VerifyAddress: "no-port"}, detail, evidence, started); d != detail || e != evidence {
		t.Fatal("an address without a port changed the report")
	}
}
