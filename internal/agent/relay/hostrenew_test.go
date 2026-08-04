// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
)

// Host-generated renewal: what goes up, and what never does (epic B2).
//
// The claim this epic makes to an operator is narrow and checkable: for a target
// marked agent-executed, the private key is generated on the host and the
// control plane never sees it. These tests hold that line at the one place it
// could be broken silently — the bytes the agent puts on the wire.

// renewChannel is a fakeChannel that can also sign, and records the CSR it was
// asked to sign so a test can inspect exactly what left the host.
type renewChannel struct {
	fakeChannel
	signed    [][]byte
	signErr   error
	certPEM   []byte
	chainPEM  []byte
	fpr       string
	signCalls int
}

func (r *renewChannel) SignJobCSR(_ context.Context, _ int64, _ int, csrDER []byte) ([]byte, []byte, string, error) {
	r.signCalls++
	r.signed = append(r.signed, append([]byte(nil), csrDER...))
	if r.signErr != nil {
		return nil, nil, "", r.signErr
	}
	return r.certPEM, r.chainPEM, r.fpr, nil
}

func renewJob(t *testing.T, intent relay.DeployIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 77, Kind: relay.KindEndpointRenew, Attempt: 1, Payload: payload}
}

// The request that leaves the host carries a public key and names, and nothing
// else. This is the whole epic, tested at the wire.
func TestTheRenewalRequestThatLeavesTheHostCarriesNoPrivateKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ch := &renewChannel{
		signErr: errors.New("refused"), // stop after the CSR; the wire bytes are the subject
	}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector:         "nginx",
		Target:            "web01",
		SubjectCommonName: "api.example.test",
		SubjectDNSNames:   []string{"api.example.test"},
		TargetConfig:      json.RawMessage(`{"cert_path":"` + filepath.Join(dir, "c.pem") + `","key_path":"` + filepath.Join(dir, "k.pem") + `"}`),
	})}

	if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 4, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}

	if ch.signCalls != 1 {
		t.Fatalf("the agent made %d signing requests, want exactly 1", ch.signCalls)
	}
	if ch.redeemed != 0 {
		t.Errorf("the agent redeemed %d credentials for a renewal; a host-generated renewal has "+
			"nothing to redeem, and redeeming would burn the attempt's one redemption on material "+
			"the control plane deliberately does not hold", ch.redeemed)
	}
	for _, csr := range ch.signed {
		for _, marker := range [][]byte{
			[]byte("PRIVATE KEY"),
			[]byte("-----BEGIN EC PRIVATE KEY-----"),
			[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		} {
			if bytes.Contains(csr, marker) {
				t.Errorf("the request sent up contains %q; the only thing that may leave this host "+
					"is a public request", marker)
			}
		}
		if len(csr) == 0 {
			t.Error("an empty request was sent up")
		}
	}
}

// A signing refusal is reported as a failure, and nothing is installed.
//
// The distinction matters: an agent that wrote a half-finished file after a
// refused signature would leave the endpoint serving a certificate and a key
// that do not match, which is worse than not renewing at all.
func TestARefusedSignatureInstallsNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	ch := &renewChannel{signErr: errors.New("refused")}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector:         "nginx",
		Target:            "web01",
		SubjectCommonName: "api.example.test",
		TargetConfig:      json.RawMessage(`{"cert_path":"` + certPath + `","key_path":"` + keyPath + `"}`),
	})}

	executed, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 4, 60)
	if err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if executed != 0 {
		t.Errorf("executed = %d, want 0: a renewal whose signature was refused executed nothing", executed)
	}
	for _, path := range []string{certPath, keyPath} {
		if _, statErr := os.Stat(path); statErr == nil {
			t.Errorf("%s was written despite the signature being refused; a key on disk with no "+
				"matching certificate is worse than an unrenewed endpoint", path)
		}
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failed report", ch.reports)
	}
}

// A channel that cannot sign refuses BEFORE generating a key.
//
// A key generated for a certificate that can never be requested is pure
// liability: material in memory with no consumer and no purpose.
func TestAChannelThatCannotSignRefusesTheWork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A plain fakeChannel implements Channel but not CSRSigner.
	ch := &fakeChannel{jobs: []relay.Job{renewJob(t, relay.DeployIntent{
		Connector:         "nginx",
		Target:            "web01",
		SubjectCommonName: "api.example.test",
	})}}
	executed, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 4, 60)
	if err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if executed != 0 {
		t.Errorf("executed = %d, want 0", executed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failed report", ch.reports)
	}
	if ch.redeemed != 0 {
		t.Errorf("the agent redeemed %d credentials for work it cannot perform", ch.redeemed)
	}
}

// A renewal intent naming no subject is refused rather than certified as
// something the control plane picked.
func TestARenewalNamingNoSubjectIsRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ch := &renewChannel{}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{Connector: "nginx", Target: "web01"})}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 4, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if ch.signCalls != 0 {
		t.Errorf("a subject-less renewal reached the signing call %d times", ch.signCalls)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failed report", ch.reports)
	}
}

// A NETWORK-vantage connector cannot take renewal work.
//
// Not a policy preference. A relay generating a key for an appliance it merely
// reaches would rebuild the exact custody hop this epic removes, with one more
// machine in the chain rather than one fewer.
func TestARelayVantageConnectorCannotTakeRenewalWork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ch := &renewChannel{}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector:         "f5",
		Target:            "vip01",
		SubjectCommonName: "api.example.test",
	})}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 4, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if ch.signCalls != 0 {
		t.Errorf("an appliance connector reached the signing call %d times; host-generated "+
			"renewal is host-only by construction", ch.signCalls)
	}
}

// The renewal kind is claimed and censused as shipped.
func TestRenewalIsClaimedAndCensusedAsShipped(t *testing.T) {
	t.Parallel()
	found := false
	for _, kind := range relay.ClaimableKinds() {
		if kind == relay.KindEndpointRenew {
			found = true
		}
	}
	if !found {
		t.Error("the renewal kind is not claimed, so no agent would ever be handed one")
	}
	shipped := false
	for _, k := range relay.ShippedJobKinds() {
		if k.Kind == relay.KindEndpointRenew {
			shipped = true
			if len(k.Connectors) == 0 {
				t.Error("the renewal kind advertises no connectors, so it executes nothing")
			}
		}
	}
	if !shipped {
		t.Error("the renewal kind is claimed but absent from the shipped census; C1a's rule is " +
			"that a claimed kind must be one this build can execute end to end")
	}
}
