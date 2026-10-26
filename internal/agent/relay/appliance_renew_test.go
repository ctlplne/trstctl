// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/connector/paloalto/paloaltotest"
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

// applianceTargetID is the destination these renewals belong to.
const applianceTargetID = "0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d"

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
		Connector: "netscaler", Target: "web-prod", TargetID: applianceTargetID, IdentityID: "identity-vip",
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
	object := connector.ApplianceKeyObjectName(applianceTargetID, 41)
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

// A rollback to a predecessor whose key the appliance generated re-binds the
// certkey to that certificate and to the appliance key named for its job,
// without reading the key; a predecessor key object that is gone is refused.
func TestARelayRollsAnApplianceBackToItsGeneratedKey(t *testing.T) {
	srv := netscalertest.New("nsroot", "s3cret")
	defer srv.Close()
	ch := newApplianceChannel(t)
	ch.material = map[string][]byte{"secret://connectors/ns": []byte("s3cret")}
	for _, jobID := range []int64{41, 42} {
		ch.jobs = []relay.Job{applianceRenewJob(t, srv, jobID, 1, true)}
		if executed, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil || executed != 1 {
			t.Fatalf("renewal job %d = %d, %v; reports %+v", jobID, executed, err, ch.reports)
		}
	}
	predecessor, successor := ch.fingerprints[0], ch.fingerprints[1]
	if binding, _ := srv.Binding("web-prod"); binding.Cert != connector.DeployedObjectName("web-prod", successor)+".crt" {
		t.Fatalf("certkey before the rollback = %+v, want the successor", binding)
	}
	intent := func(object string) relay.RollbackIntent {
		cfg, err := json.Marshal(map[string]string{"endpoint": srv.URL(), "username": "nsroot",
			"password_ref": "secret://connectors/ns", "key_generation": "appliance"})
		if err != nil {
			t.Fatal(err)
		}
		return relay.RollbackIntent{
			Connector: "netscaler", Target: "web-prod", TargetID: applianceTargetID, TargetConfig: cfg,
			CredentialRefs: []string{"secret://connectors/ns"}, PredecessorFingerprint: predecessor,
			PredecessorKeyObject: object,
		}
	}
	material := func() relay.Material {
		return relay.Material{"secret://connectors/ns": []byte("s3cret")}
	}
	object := connector.ApplianceKeyObjectName(applianceTargetID, 41)
	if _, _, err := relay.RollbackWithResult(context.Background(), srv.Client(), intent(object), material()); err != nil {
		t.Fatalf("roll back to the appliance-generated predecessor: %v", err)
	}
	binding, _ := srv.Binding("web-prod")
	if binding.Cert != connector.DeployedObjectName("web-prod", predecessor)+".crt" || binding.Key != object+".key" {
		t.Fatalf("certkey after the rollback = %+v, want the predecessor and %s.key", binding, object)
	}
	if srv.DeviceKeyReads() != 0 {
		t.Fatalf("the rollback read an appliance key %d times", srv.DeviceKeyReads())
	}
	srv.RemoveFile(object + ".csr")
	if _, _, err := relay.RollbackWithResult(context.Background(), srv.Client(), intent(object), material()); !errors.Is(err, connector.ErrNoPredecessorInstalled) {
		t.Fatalf("rollback to an appliance key whose object is gone = %v, want ErrNoPredecessorInstalled", err)
	}
}

func panApplianceRenewJob(t *testing.T, srv *paloaltotest.Server, jobID int64, attempt int) relay.Job {
	t.Helper()
	targetConfig, err := json.Marshal(map[string]string{
		"endpoint": srv.URL(), "api_key_ref": "secret://connectors/pan", "ssl_tls_profile": "web-profile",
		"commit_admin": "trstctl", "key_generation": "appliance",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(relay.DeployIntent{
		Connector: "paloalto", Target: "web-prod", TargetID: applianceTargetID, IdentityID: "identity-vip",
		SubjectCommonName: "vip.example.test", SubjectDNSNames: []string{"vip.example.test"},
		TargetConfig: targetConfig, CredentialRefs: []string{"secret://connectors/pan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: relay.KindEndpointRenew, Attempt: attempt, Payload: payload}
}

// A122 on PAN-OS: a relay renews a firewall whose key stays on the firewall,
// binding the SSL/TLS service profile to the object named for the job. PAN-OS
// keeps no CSR once its certificate is imported, so a reclaim after the
// install asks for no second signature and says why it stopped.
func TestARelayRenewsAFirewallWhoseKeyStaysOnTheFirewall(t *testing.T) {
	srv := paloaltotest.New([]byte("pan-api-key"))
	defer srv.Close()
	ch := newApplianceChannel(t)
	ch.material = map[string][]byte{"secret://connectors/pan": []byte("pan-api-key")}
	ch.jobs = []relay.Job{panApplianceRenewJob(t, srv, 51, 1)}
	executed, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60)
	if err != nil || executed != 1 {
		t.Fatalf("RunOnceWithHost = %d, %v; reports %+v", executed, err, ch.reports)
	}
	object := connector.ApplianceKeyObjectName(applianceTargetID, 51)
	if !srv.DeviceKey(object) || srv.ProfileCertificate("web-profile") != object {
		t.Fatalf("firewall key %s generated %v, profile bound to %q", object, srv.DeviceKey(object), srv.ProfileCertificate("web-profile"))
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one executed report", ch.reports)
	}
	if want := relay.ApplianceRenewCustody(""); len(ch.custody) != 1 || ch.custody[0] != want {
		t.Fatalf("custody = %+v, want %+v", ch.custody, want)
	}

	ch.jobs = []relay.Job{panApplianceRenewJob(t, srv, 51, 2)}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.signed) != 1 {
		t.Fatalf("signing requests = %d, want none after the install", len(ch.signed))
	}
	if len(ch.reports) != 2 || ch.reports[1].outcome != relay.OutcomeFailed || !strings.Contains(ch.reports[1].detail, "earlier attempt") {
		t.Fatalf("reclaim reports = %+v, want a failure naming the earlier attempt", ch.reports)
	}
	if srv.KeyExports() != 0 {
		t.Fatalf("the relay asked to export a firewall key %d times", srv.KeyExports())
	}
}

// recordingApplianceChannel keeps the appliance references a relay records.
type recordingApplianceChannel struct {
	*applianceChannel
	references []string
}

func (r *recordingApplianceChannel) RecordJobApplianceReference(_ context.Context, _ int64, _ int, reference string) error {
	r.references = append(r.references, reference)
	return nil
}

func iseApplianceRenewJob(t *testing.T, srv *ciscotest.Server, jobID int64, attempt int, reference string) relay.Job {
	t.Helper()
	targetConfig, err := json.Marshal(map[string]any{
		"endpoint": srv.URL(), "username": "ers-admin", "password_ref": "secret://connectors/ise",
		"node_hostname": srv.Node(), "certificate_roles": []string{"eap"}, "key_generation": "appliance",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(relay.DeployIntent{
		Connector: "cisco", Target: "radius-vip", TargetID: applianceTargetID, IdentityID: "identity-radius",
		SubjectCommonName: "radius.example.test", SubjectDNSNames: []string{"radius.example.test"},
		TargetConfig: targetConfig, CredentialRefs: []string{"secret://connectors/ise"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: relay.KindEndpointRenew, Attempt: attempt, Payload: payload, ApplianceReference: reference}
}

// A122 (owner decision 2026-10-26): a relay renews a Cisco ISE node whose key
// ISE generates. It records ISE's request ID for the job before asking for a
// signature; an attempt that loses its signature is retried with the recorded
// ID and sends the same CSR without ISE generating another; the bind installs
// the certificate with the target's roles and appliance custody.
func TestARelayRenewsAnISENodeAndReusesItsRequest(t *testing.T) {
	srv := ciscotest.New("ers-admin", []byte("ise-pass"))
	defer srv.Close()
	ch := &recordingApplianceChannel{applianceChannel: newApplianceChannel(t)}
	ch.material = map[string][]byte{"secret://connectors/ise": []byte("ise-pass")}
	ch.signErr = errors.New("lease lost")
	ch.jobs = []relay.Job{iseApplianceRenewJob(t, srv, 91, 1, "")}
	if _, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.references) != 1 || ch.references[0] == "" || srv.CSRsGenerated() != 1 {
		t.Fatalf("first attempt recorded %v with %d requests on ISE; want one recorded request", ch.references, srv.CSRsGenerated())
	}
	ch.signErr = nil
	ch.jobs = []relay.Job{iseApplianceRenewJob(t, srv, 91, 2, ch.references[0])}
	executed, err := relay.RunOnceWithHost(context.Background(), ch, srv.Client(), connector.LocalOpsConfig{}, 4, 60)
	if err != nil || executed != 1 {
		t.Fatalf("retried attempt = %d, %v; reports %+v", executed, err, ch.reports)
	}
	if srv.CSRsGenerated() != 1 || len(ch.references) != 1 || len(ch.signed) != 2 || !bytes.Equal(ch.signed[0], ch.signed[1]) {
		t.Fatalf("retry made %d requests, recorded %v, signed %d; want the recorded request reused", srv.CSRsGenerated(), ch.references, len(ch.signed))
	}
	if len(ch.fingerprints) != 1 || srv.RoleHolder("eap") != connector.DeployedObjectName("radius-vip", ch.fingerprints[0]) {
		t.Fatalf("EAP role is on %q after the renewal (fingerprints %v)", srv.RoleHolder("eap"), ch.fingerprints)
	}
	if want := relay.ApplianceRenewCustody(""); len(ch.custody) != 1 || ch.custody[0] != want {
		t.Fatalf("custody = %+v, want %+v", ch.custody, want)
	}
}
