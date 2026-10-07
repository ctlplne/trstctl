// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
)

func TestContainmentIsClaimedAndAdvertisedWithItsHostProfile(t *testing.T) {
	if !slices.Contains(ClaimableKinds(), KindEndpointContain) {
		t.Fatal("the host agent never asks for endpoint.contain")
	}
	for _, shipped := range ShippedJobKinds() {
		if shipped.Kind != KindEndpointContain {
			continue
		}
		if len(shipped.Connectors) != 0 ||
			!slices.Contains(shipped.Flags, "--relay-claim") ||
			!slices.Contains(shipped.Flags, "--host-exec-profile") {
			t.Fatalf("containment must advertise the host profile and claim flags without connector work: %+v", shipped)
		}
		return
	}
	t.Fatal("the agent claims and executes endpoint.contain but its advertised shipped capabilities omit it")
}

func TestContainmentNeverStopsAnUnobservedOrReplacedLeaf(t *testing.T) {
	const compromised = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	intent := ContainmentIntent{TargetID: "target-1", TargetRevision: "revision-1", IdentityID: "identity-1",
		RequiredAgentID: "agent-1", ExpectedFingerprint: compromised}
	binding := connector.LocalContainment{TargetID: intent.TargetID, Address: "127.0.0.1:8443", Action: "stop-target-1"}
	for _, tc := range []struct {
		name, observed, want string
		reached              bool
	}{
		{"unreachable", "", ContainmentUnverified, false},
		{"different leaf", strings.Repeat("b", 64), ContainmentDifferentLeaf, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stops := 0
			got, err := executeContainment(t.Context(), intent, binding,
				func() (transport.ProbeTranscript, error) {
					return transport.ProbeTranscript{Address: binding.Address, Vantage: transport.VantageLocal,
						Reached: tc.reached, ObservedFingerprint: tc.observed,
						ExpectedFingerprint: compromised, ObservedAtUnix: 100}, nil
				}, func() error { stops++; return nil })
			if err != nil || got.State != tc.want || stops != 0 || len(got.After) != 0 {
				t.Fatalf("report=%+v stops=%d err=%v", got, stops, err)
			}
			if err := ValidateContainmentReport(intent, got, got.Digest()); err != nil {
				t.Fatalf("receiver rejected refusal report: %v", err)
			}
		})
	}
}

func TestContainmentRequiresRepeatedPostStopAbsence(t *testing.T) {
	const compromised = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	intent := ContainmentIntent{TargetID: "target-1", TargetRevision: "revision-1", IdentityID: "identity-1",
		RequiredAgentID: "agent-1", ExpectedFingerprint: compromised}
	binding := connector.LocalContainment{TargetID: intent.TargetID, Address: "127.0.0.1:8443", Action: "stop-target-1"}
	for _, tc := range []struct {
		name       string
		after      []string
		stopErr    error
		want       string
		wantProbes int
	}{
		{"stopped", []string{"", ""}, nil, ContainmentStopped, 2},
		{"transient refusal", []string{"", compromised}, nil, ContainmentFailed, 4},
		{"action failed", []string{"", ""}, errors.New("stop failed"), ContainmentFailed, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, stops := 0, 0
			got, err := executeContainmentWithPolicy(context.Background(), intent, binding,
				func() (transport.ProbeTranscript, error) {
					fp := compromised
					if calls > 0 {
						index := min(calls-1, len(tc.after)-1)
						fp = tc.after[index]
					}
					calls++
					return transport.ProbeTranscript{Address: binding.Address, Vantage: transport.VantageLocal,
						Reached: fp != "", ObservedFingerprint: fp,
						ExpectedFingerprint: compromised, ObservedAtUnix: int64(100 + calls)}, nil
				}, func() error { stops++; return tc.stopErr }, 4, 0)
			if err != nil || got.State != tc.want || stops != 1 || calls != tc.wantProbes+1 || len(got.After) != tc.wantProbes {
				t.Fatalf("report=%+v stops=%d calls=%d err=%v", got, stops, calls, err)
			}
			if got.Digest() == "" {
				t.Fatal("signed report digest is empty")
			}
			if err := ValidateContainmentReport(intent, got, got.Digest()); err != nil {
				t.Fatalf("receiver rejected truthful report: %v", err)
			}
			tampered := got
			tampered.State = ContainmentStopped
			if tc.want != ContainmentStopped && ValidateContainmentReport(intent, tampered, got.Digest()) == nil {
				t.Fatal("receiver accepted a tampered contained state")
			}
		})
	}
}

func TestContainmentWaitsForGracefulStopWithoutDiscardingSignedObservations(t *testing.T) {
	const compromised = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	intent := ContainmentIntent{TargetID: "target-1", TargetRevision: "revision-1", IdentityID: "identity-1",
		RequiredAgentID: "agent-1", ExpectedFingerprint: compromised}
	binding := connector.LocalContainment{TargetID: intent.TargetID, Address: "127.0.0.1:8443", Action: "stop-target-1"}
	observed := []string{compromised, compromised, "", ""}
	calls := 0
	got, err := executeContainmentWithPolicy(t.Context(), intent, binding,
		func() (transport.ProbeTranscript, error) {
			fp := observed[calls]
			calls++
			return transport.ProbeTranscript{Address: binding.Address, Vantage: transport.VantageLocal,
				Reached: fp != "", ObservedFingerprint: fp,
				ExpectedFingerprint: compromised, ObservedAtUnix: int64(100 + calls)}, nil
		}, func() error { return nil }, 4, 0)
	if err != nil || got.State != ContainmentStopped || calls != len(observed) || len(got.After) != 3 {
		t.Fatalf("graceful stop report=%+v probes=%d err=%v", got, calls, err)
	}
	if got.After[0].ObservedFingerprint != compromised || got.After[1].Reached || got.After[2].Reached {
		t.Fatalf("signed evidence omitted the still-serving interval: %+v", got.After)
	}
	if err := ValidateContainmentReport(intent, got, got.Digest()); err != nil {
		t.Fatalf("receiver rejected bounded convergence evidence: %v", err)
	}
	tampered := got
	tampered.After = append([]transport.ProbeTranscript(nil), got.After...)
	tampered.After[len(tampered.After)-1].Reached = true
	if ValidateContainmentReport(intent, tampered, tampered.Digest()) == nil {
		t.Fatal("receiver accepted a stopped report whose final probe still reached the leaf")
	}
}

func TestContainmentIntentRequiresExactFingerprint(t *testing.T) {
	good := ContainmentIntent{TargetID: "target", TargetRevision: "revision", IdentityID: "identity",
		RequiredAgentID: "agent", ExpectedFingerprint: strings.Repeat("a", 64)}
	if !validContainmentIntent(good) {
		t.Fatal("exact intent refused")
	}
	good.ExpectedFingerprint = "not-a-sha256"
	if validContainmentIntent(good) {
		t.Fatal("malformed fingerprint authorized a host action")
	}
}
