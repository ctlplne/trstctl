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
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// The relay's rollback path (epic D4).
//
// What matters here is the ORDER of refusals. A relay that redeems a credential
// and then discovers it cannot perform the work has moved material outside the
// seal for nothing and burned the attempt's one redemption, so no other agent
// can take the job either. Every reason a rollback cannot run is therefore
// checked before anything is redeemed.

func rollbackJob(t *testing.T, jobID int64, intent relay.RollbackIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: relay.KindConnectorRollback, Attempt: 1, Payload: payload}
}

// A connector that cannot re-bind is refused before redeeming.
func TestRelayRefusesRollbackForANonRebindableConnectorBeforeRedeeming(t *testing.T) {
	ch := &fakeChannel{
		jobs: []relay.Job{rollbackJob(t, 1, relay.RollbackIntent{
			// paloalto is relay-reachable but its API cannot address an
			// installed object separately from importing one.
			Connector: "paloalto", Target: "vsys1", PredecessorFingerprint: "abcd1234",
		})},
		material: map[string][]byte{"secret://appliance-admin": []byte(appliancePassword)},
	}
	executed, err := relay.RunOnce(context.Background(), ch, http.DefaultClient, 4, 60)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if executed != 0 {
		t.Fatalf("executed %d jobs, want 0", executed)
	}
	if ch.redeemed != 0 {
		t.Errorf("relay redeemed %d credentials for a rollback it cannot perform, want 0", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failure", ch.reports)
	}
}

// A rollback naming no predecessor is refused before redeeming.
//
// This is the first-deployment case. There is nothing to roll back to, and no
// amount of retrying or redeeming will produce one.
func TestRelayRefusesRollbackWithNoPredecessorBeforeRedeeming(t *testing.T) {
	ch := &fakeChannel{
		jobs: []relay.Job{rollbackJob(t, 2, relay.RollbackIntent{
			Connector: "f5", Target: "clientssl_app",
		})},
		material: map[string][]byte{"secret://appliance-admin": []byte(appliancePassword)},
	}
	if _, err := relay.RunOnce(context.Background(), ch, http.DefaultClient, 4, 60); err != nil {
		t.Fatalf("run: %v", err)
	}
	if ch.redeemed != 0 {
		t.Errorf("relay redeemed %d credentials for a rollback with no predecessor, want 0", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want one failure", ch.reports)
	}
}

// The rollback census is the intersection of what a relay can reach and what
// can re-bind. Either half missing means the same thing to an operator.
func TestRollbackCapableKindsAreReachableAndRebindable(t *testing.T) {
	capable := relay.RollbackCapableKinds()
	if len(capable) == 0 {
		t.Fatal("no relay connector can roll back; connector.rollback must not be advertised at all")
	}
	for _, kind := range capable {
		if !relay.Executes(kind) {
			t.Errorf("census names %q, which this relay cannot reach", kind)
		}
		if !connector.CanRollback(kind) {
			t.Errorf("census names %q, which cannot re-bind", kind)
		}
	}
	// And nothing reachable-and-rebindable is left out, or an operator would
	// see a capability the binary has but does not offer.
	for _, kind := range relay.RelayConnectorKinds() {
		if !connector.CanRollback(kind) {
			continue
		}
		found := false
		for _, c := range capable {
			if c == kind {
				found = true
			}
		}
		if !found {
			t.Errorf("%q can re-bind and is relay-reachable but is missing from the census", kind)
		}
	}
}

// A rollback intent carries no key material, and that is structural rather than
// a convention: the type has nowhere to put one.
func TestRollbackIntentCannotCarryKeyMaterial(t *testing.T) {
	encoded, err := json.Marshal(relay.RollbackIntent{
		Connector: "f5", Target: "clientssl_app", PredecessorFingerprint: "abcd1234",
		Reason: "wrong SAN",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The whole reason a rollback is executable at all is that the control
	// plane holds no subject key. A payload that carried one would mean the
	// property had quietly been given up somewhere upstream.
	for _, forbidden := range []string{"PRIVATE KEY", "key_pem", "cert_pem"} {
		if json.Valid(encoded) && containsFold(string(encoded), forbidden) {
			t.Errorf("rollback intent encodes %q: %s", forbidden, encoded)
		}
	}
}

// G1's real host path: two ordinary deploy attempts retain the predecessor on
// the enrolled agent. A later rollback redeems nothing, restores the old bytes,
// runs the connector's reload path, and proves the listener serves the old
// certificate before signing a verified result.
func TestHostRollbackRestoresReloadsAndReverifiesWithoutRedemption(t *testing.T) {
	predecessor, err := tlsprobe.NewServingTestServer("rollback.example.test")
	if err != nil {
		t.Fatalf("start predecessor listener: %v", err)
	}
	defer predecessor.Close()
	successor, err := tlsprobe.NewServingTestServer("successor.example.test")
	if err != nil {
		t.Fatalf("mint successor: %v", err)
	}
	defer successor.Close()

	root := t.TempDir()
	state, err := relay.NewHostRollbackStore(filepath.Join(root, "rollback-state"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	profile := hostProfileForNginx(t, root)
	config := mustJSON(t, map[string]string{
		"cert_path": filepath.Join(root, "server.crt"),
		"key_path":  filepath.Join(root, "server.key"),
	})
	firstIssuer := []byte("-----BEGIN CERTIFICATE-----\npredecessor-issuer-evidence\n-----END CERTIFICATE-----\n")
	deploy := func(jobID int64, fingerprint string, certPEM, chainPEM []byte) {
		t.Helper()
		ch := &fakeChannel{
			jobs: []relay.Job{intentJob(t, jobID, relay.DeployIntent{
				Connector: "nginx", Target: "edge", TargetID: "target-a",
				TargetConfig: config, Fingerprint: fingerprint,
			})},
			material: map[string][]byte{
				"credential.cert_pem":  certPEM,
				"credential.chain_pem": chainPEM,
				"credential.key_pem":   []byte(testKeyPEM + fingerprint),
			},
		}
		if _, runErr := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), ch,
			http.DefaultClient, profile, nil, nil, state, 1, 30); runErr != nil {
			t.Fatalf("deploy %s: %v", fingerprint, runErr)
		}
		if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
			t.Fatalf("deploy %s reports = %+v", fingerprint, ch.reports)
		}
	}
	deploy(10, "first", predecessor.LeafPEM, firstIssuer)
	deploy(11, "second", successor.LeafPEM, []byte("successor-issuer-evidence"))

	rollback := &fakeChannel{jobs: []relay.Job{rollbackJob(t, 12, relay.RollbackIntent{
		Connector: "nginx", Target: "edge", TargetID: "target-a", TargetConfig: config,
		PredecessorFingerprint: "first", VerifyAddress: predecessor.Addr,
	})}}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), rollback,
		http.DefaultClient, profile, nil, nil, state, 1, 30); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rollback.redeemed != 0 {
		t.Fatalf("host rollback redeemed %d control-plane credentials, want zero", rollback.redeemed)
	}
	if len(rollback.confirmations) != 1 || rollback.confirmations[0].jobID != 12 || rollback.confirmations[0].attempt != 1 {
		t.Fatalf("host restore did not confirm its exact current attempt: %+v", rollback.confirmations)
	}
	if len(rollback.reports) != 1 || rollback.reports[0].outcome != transport.OutcomeVerified || rollback.reports[0].evidence == "" {
		t.Fatalf("rollback reports = %+v, want signed-evidence-ready verified result", rollback.reports)
	}
	got, err := os.ReadFile(filepath.Join(root, "server.crt")) // #nosec G304 -- test-owned temporary path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), predecessor.LeafPEM...), firstIssuer...)
	if !bytes.Equal(got, want) {
		t.Fatal("host certificate file was not restored to the complete predecessor serving chain")
	}
}

func TestRollbackNeedsFreshAuthorizationBeforeLocalStateOrCredentials(t *testing.T) {
	for _, kind := range []string{"nginx", "f5"} {
		for _, unavailable := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/denied", true: "/unavailable"}[unavailable], func(t *testing.T) {
				root := t.TempDir()
				state, err := relay.NewHostRollbackStore(filepath.Join(root, "state"), "tenant-a")
				if err != nil {
					t.Fatal(err)
				}
				// Missing predecessor state makes ordering visible: opening it
				// first would report a different failure and bypass authorization.
				ch := &fakeChannel{confirmationDenied: !unavailable, jobs: []relay.Job{rollbackJob(t, 77, relay.RollbackIntent{
					Connector: kind, Target: "owned-target", TargetID: "target-a", PredecessorFingerprint: "first",
				})}}
				want := transport.RollbackRefusedAuthorization
				if unavailable {
					ch.confirmationErr = errors.New("control plane unavailable")
					want = transport.RollbackRefusedAuthorizationUnavailable
				}
				contacted := false
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					contacted = true
					return nil, errors.New("unexpected target contact")
				})}
				executed, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), ch, client, hostProfileForNginx(t, root), nil, nil, state, 1, 30)
				if err != nil || executed != 0 || contacted || ch.redeemed != 0 {
					t.Fatalf("authorization failure reached execution: executed=%d contacted=%t redeemed=%d error=%v", executed, contacted, ch.redeemed, err)
				}
				if len(ch.confirmations) != 1 || len(ch.reports) != 1 || ch.reports[0].detail != want {
					t.Fatalf("wrong refusal: confirmations=%+v reports=%+v", ch.confirmations, ch.reports)
				}
				if transport.RollbackReasonContactedTarget(want) || transport.RollbackReasonIsPermanent(want) == unavailable {
					t.Fatal("authorization refusal misclassified contact or retryability")
				}
			})
		}
	}
}

// A corrupt or unreadable encrypted ledger is a LOCAL refusal. No restore
// callback ran, so recording it as "failed at target" would invent target
// contact and send the operator to the wrong machine.
func TestHostRollbackUnreadableStateRefusesBeforeTargetContact(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "rollback-state")
	state, err := relay.NewHostRollbackStore(stateRoot, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RecordDeploy("nginx", "target-a", "first", []byte(testCertPEM), []byte(testKeyPEM)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".state" {
			if err := os.WriteFile(filepath.Join(stateRoot, entry.Name()), []byte("not encrypted state"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	ch := &fakeChannel{jobs: []relay.Job{rollbackJob(t, 13, relay.RollbackIntent{
		Connector: "nginx", Target: "edge", TargetID: "target-a", PredecessorFingerprint: "first",
	})}}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), ch,
		http.DefaultClient, hostProfileForNginx(t, root), nil, nil, state, 1, 30); err != nil {
		t.Fatal(err)
	}
	if ch.redeemed != 0 {
		t.Fatalf("unreadable local state redeemed %d control-plane credentials", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].detail != transport.RollbackRefusedHostStateUnavailable {
		t.Fatalf("unreadable local state reports = %+v", ch.reports)
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexFold(haystack, needle) >= 0
}

func indexFold(haystack, needle string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if lower(haystack[i+j]) != lower(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// Every kind this build declares SHIPPED must be a kind it actually asks for.
//
// This guard exists because its absence already cost a whole epic. D4 added
// connector.rollback to ShippedJobKinds, to the served capability census, to the
// docs and to a rollback_queued status an operator would read — and did not add
// it to ClaimableKinds, the one list the agent passes to ClaimJobs. Every layer
// said rollback was served; no relay ever requested the kind, so the executor
// was unreachable and the whole feature was a claim about code that never ran.
//
// Nothing failed. The per-kind tests all passed, because they drive RunOnce
// against a fake channel that hands back whatever jobs the test seeded
// regardless of what was asked for. Two lists that must agree, with nothing
// checking, is the shape of that failure — so this checks.
func TestEveryShippedKindIsActuallyClaimed(t *testing.T) {
	claimed := map[string]bool{}
	for _, kind := range relay.ClaimableKinds() {
		claimed[kind] = true
	}
	// agent.upgrade is asked for CONDITIONALLY — RunOnceWithSelfUpgrade appends
	// it only when the machine operator passed -self-upgrade, because the ask
	// itself is the consent to binary replacement (A5). The kind is still
	// claimed by the binary; it is just not in the unconditional list, and the
	// loop test TestUpgradeKindIsClaimedOnlyWithTheOptIn pins both directions
	// of that conditionality.
	claimed[relay.KindAgentUpgrade] = true
	for _, shipped := range relay.ShippedJobKinds() {
		if !claimed[shipped.Kind] {
			t.Errorf("%q is declared shipped but is not in ClaimableKinds, so no relay ever "+
				"asks for it and its executor is unreachable — every surface that advertises "+
				"it is describing work the binary does not perform", shipped.Kind)
		}
	}
	// And the reverse: asking for work this build cannot execute takes a claim,
	// burns the attempt's one credential redemption, and hands it back.
	shipped := map[string]bool{}
	for _, s := range relay.ShippedJobKinds() {
		shipped[s.Kind] = true
	}
	for _, kind := range relay.ClaimableKinds() {
		if !shipped[kind] {
			t.Errorf("relay claims %q but does not declare it shipped; it will take work it "+
				"cannot perform", kind)
		}
	}
	// Nothing may be in both censuses at once.
	for kind := range relay.UnshippedJobKinds() {
		if claimed[kind] {
			t.Errorf("%q is named unshipped yet is claimed", kind)
		}
	}
}
