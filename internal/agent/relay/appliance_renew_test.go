// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
)

// applianceChannel signs whatever CSR it is sent with a test CA, as the
// control plane would, and records what each signed report carried.
type applianceChannel struct {
	fakeChannel
	ca           *crypto.LockedSigner
	caDER        []byte
	signErr      error
	signed       [][]byte
	custody      []custody.Record
	fingerprints []string
}

func newApplianceChannel(t *testing.T) *applianceChannel {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Relay Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &applianceChannel{ca: ca, caDER: caDER}
}

func (a *applianceChannel) SignJobCSR(_ context.Context, _ int64, _ int, csrDER []byte) ([]byte, []byte, string, error) {
	a.signed = append(a.signed, append([]byte(nil), csrDER...))
	if a.signErr != nil {
		return nil, nil, "", a.signErr
	}
	leafDER, err := crypto.SignLeafFromCSR(a.caDER, a.ca, csrDER, time.Hour)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	return certPEM, nil, connector.CertificateFingerprint(certPEM), nil
}

func (a *applianceChannel) ReportJobResultWithCustody(ctx context.Context, jobID int64, attempt int,
	outcome, detail, evidence, fingerprint string, record custody.Record) (bool, error) {
	a.custody = append(a.custody, record)
	a.fingerprints = append(a.fingerprints, fingerprint)
	return a.ReportJobResult(ctx, jobID, attempt, outcome, detail, evidence)
}

func applianceRenewJob(t *testing.T, srv *netscalertest.Server, jobID int64, attempt int, declare bool) relay.Job {
	t.Helper()
	cfg := map[string]string{"endpoint": srv.URL(), "username": "nsroot", "password_ref": "secret://connectors/ns"}
	if declare {
		cfg["key_generation"] = "appliance"
	}
	targetConfig, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(relay.DeployIntent{
		Connector: "netscaler", Target: "web-prod", TargetID: "target-ns", IdentityID: "identity-vip",
		SubjectCommonName: "vip.example.test", SubjectDNSNames: []string{"vip.example.test"},
		TargetConfig: targetConfig, CredentialRefs: []string{"secret://connectors/ns"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: relay.KindEndpointRenew, Attempt: attempt, Payload: payload}
}

// A122: a network relay renews an appliance whose key stays on the appliance.
// It redeems only the appliance login, sends up the CSR the appliance made and
// nothing else, installs the certificate against the appliance's key, and
// reports appliance custody.
func TestARelayRenewsAnApplianceWhoseKeyStaysOnTheAppliance(t *testing.T) {
	srv := netscalertest.New("nsroot", "s3cret")
	defer srv.Close()
	ch := newApplianceChannel(t)
	ch.material = map[string][]byte{"secret://connectors/ns": []byte("s3cret")}
	ch.jobs = []relay.Job{applianceRenewJob(t, srv, 41, 1, true)}

	executed, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60)
	if err != nil || executed != 1 {
		t.Fatalf("RunOnceWithHost = %d, %v; reports %+v", executed, err, ch.reports)
	}
	if len(ch.signed) != 1 || bytes.Contains(ch.signed[0], []byte("PRIVATE KEY")) {
		t.Fatalf("signing requests = %d, want one public CSR", len(ch.signed))
	}
	if ch.redeemed != 1 {
		t.Fatalf("redemptions = %d, want the appliance login once", ch.redeemed)
	}
	object := connector.ApplianceKeyObjectName("web-prod", 41)
	if !srv.DeviceKey(object + ".key") {
		t.Fatalf("the appliance holds no key %s.key", object)
	}
	binding, ok := srv.Binding("web-prod")
	if !ok || binding.Key != object+".key" || len(ch.fingerprints) != 1 ||
		binding.Cert != connector.DeployedObjectName("web-prod", ch.fingerprints[0])+".crt" {
		t.Fatalf("certkey binding = %+v %v (reported fingerprints %v)", binding, ok, ch.fingerprints)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one executed report", ch.reports)
	}
	if want := relay.ApplianceRenewCustody(""); len(ch.custody) != 1 || ch.custody[0] != want {
		t.Fatalf("custody = %+v, want %+v", ch.custody, want)
	}
	if srv.DeviceKeyReads() != 0 {
		t.Fatalf("the relay read the appliance key %d times", srv.DeviceKeyReads())
	}
}

// A reclaimed job asks the appliance again and gets the same CSR, so a crash
// between generating and signing never leaves two keys for one renewal.
func TestAReclaimedApplianceRenewalSendsTheSameCSR(t *testing.T) {
	srv := netscalertest.New("nsroot", "s3cret")
	defer srv.Close()
	ch := newApplianceChannel(t)
	ch.material = map[string][]byte{"secret://connectors/ns": []byte("s3cret")}
	ch.signErr = errors.New("lease lost")
	ch.jobs = []relay.Job{applianceRenewJob(t, srv, 42, 1, true)}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil {
		t.Fatal(err)
	}
	ch.signErr = nil
	ch.jobs = []relay.Job{applianceRenewJob(t, srv, 42, 2, true)}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.signed) != 2 || !bytes.Equal(ch.signed[0], ch.signed[1]) {
		t.Fatalf("signing requests across the reclaim = %d, want the same CSR twice", len(ch.signed))
	}
	if len(ch.reports) != 2 || ch.reports[0].outcome != relay.OutcomeFailed || ch.reports[1].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want the refused attempt failed and the reclaim executed", ch.reports)
	}
}

// An appliance target that did not declare key_generation=appliance is not
// renewed this way: without the declaration the relay generates nothing and
// asks the appliance for nothing.
func TestAnUndeclaredApplianceRenewalIsRefused(t *testing.T) {
	srv := netscalertest.New("nsroot", "s3cret")
	defer srv.Close()
	ch := newApplianceChannel(t)
	ch.material = map[string][]byte{"secret://connectors/ns": []byte("s3cret")}
	ch.jobs = []relay.Job{applianceRenewJob(t, srv, 43, 1, false)}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.signed) != 0 || ch.redeemed != 0 || srv.Logins() != 0 {
		t.Fatalf("an undeclared appliance renewal signed %d, redeemed %d, logged in %d times", len(ch.signed), ch.redeemed, srv.Logins())
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("reports = %+v, want the renewal refused", ch.reports)
	}
}
