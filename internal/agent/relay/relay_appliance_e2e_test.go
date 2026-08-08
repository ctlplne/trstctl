// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
	"trstctl.com/trstctl/internal/connector/fortigate/fortigatetest"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/connector/paloalto/paloaltotest"
)

// Does a deploy driven THROUGH THE RELAY actually reach the appliance? (epic E1)
//
// Until this file, nothing answered that. Each family had a device proof —
// its connector driven against a faithful double of its management API — and
// the relay had its own tests for refusals, capability denial and dry-run. What
// sat between them was untested: relay.Execute decodes a target config, pulls
// credentials out of redeemed material by reference name, and builds the
// connector. Every one of those is a place a deploy can be lost, and all of
// them are relay-only code that the device proofs never run.
//
// That gap is not academic. E1's whole purpose is to move these families off
// the control plane, and the control-plane path is the one with an end-to-end
// proof: the DoD suite drives a10, cisco, kemp and netscaler through the served
// API against these same emulators. Refusing the control-plane path — E1's
// acceptance criterion — without this file would have retired a proven path in
// favour of an unproven one. So the refusal waits on this, not the other way
// round.
//
// What each case asserts is deliberately not "no error": a connector that
// posted to the wrong path and got a 200 from a permissive double returns no
// error too. Each case reads the certificate back OUT of the emulator and
// compares bytes.

func TestARelayDeployReachesEveryApplianceItAdvertises(t *testing.T) {
	certPEM := []byte(testCertPEM)
	keyPEM := []byte(testKeyPEM)

	const (
		user  = "svc-trstctl"
		pass  = "appliance-secret"
		token = "appliance-token"
	)

	cases := []struct {
		connector string
		target    string
		// start returns the emulator's URL, the material the relay must have
		// redeemed for this family, the target config, and a close func.
		start func(t *testing.T) (url string, client *http.Client, material relay.Material, cfg relay.TargetConfig, verify func(t *testing.T, target, fingerprint string))
	}{
		{
			connector: "f5", target: "app",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := f5test.New(user, pass)
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.f5_password": []byte(pass)},
					relay.TargetConfig{Username: user, PasswordRef: "credential.f5_password", ClientSSLProfile: "clientssl-app"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, _, fingerprint string) {
						// F5 names the uploaded object after the client-SSL
						// PROFILE, not the deployment target — the profile is
						// what a virtual server binds to.
						base := connector.DeployedObjectName("clientssl-app", fingerprint)
						got, ok := srv.Uploaded(base + ".crt")
						if !ok {
							t.Fatalf("f5 holds no certificate at %s.crt after a relay deploy", base)
						}
						if !bytes.Equal(got, certPEM) {
							t.Fatal("f5 stored different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "netscaler", target: "certkey-app",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := netscalertest.New(user, pass)
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.ns_password": []byte(pass)},
					relay.TargetConfig{Username: user, PasswordRef: "credential.ns_password"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, fingerprint string) {
						base := connector.DeployedObjectName(target, fingerprint)
						got, ok := srv.File(base + ".crt")
						if !ok {
							t.Fatalf("netscaler holds no file at %s.crt after a relay deploy", base)
						}
						if !bytes.Equal(got, certPEM) {
							t.Fatal("netscaler stored different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "a10", target: "payments-client-ssl",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := a10test.New(user, pass)
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.a10_password": []byte(pass)},
					relay.TargetConfig{Username: user, PasswordRef: "credential.a10_password"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, _ string) {
						b, ok := srv.Binding(target)
						if !ok {
							t.Fatalf("a10 template %q is unbound after a relay deploy", target)
						}
						if !bytes.Equal(b.Certificate, certPEM) {
							t.Fatal("a10 bound different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "kemp", target: "vs-payments-443",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := kemptest.New(token)
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.kemp_token": []byte(token)},
					relay.TargetConfig{TokenRef: "credential.kemp_token"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, _ string) {
						b, ok := srv.Binding(target)
						if !ok {
							t.Fatalf("kemp virtual service %q is unbound after a relay deploy", target)
						}
						if !bytes.Equal(b.Certificate, certPEM) {
							t.Fatal("kemp bound different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "cisco", target: "trstctl-app",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := ciscotest.New(user, []byte(pass))
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.cisco_password": []byte(pass)},
					relay.TargetConfig{Username: user, PasswordRef: "credential.cisco_password"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, _ string) {
						got, ok := srv.Imported(target)
						if !ok {
							t.Fatalf("cisco imported nothing under %q after a relay deploy; device has %v",
								target, srv.ImportedNames())
						}
						if !bytes.Equal(got.Certificate, certPEM) {
							t.Fatal("cisco imported different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "fortigate", target: "trstctl-app",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := fortigatetest.New([]byte(token))
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.fgt_token": []byte(token)},
					relay.TargetConfig{TokenRef: "credential.fgt_token"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, _ string) {
						got, ok := srv.Stored(target)
						if !ok {
							t.Fatalf("fortigate stored nothing under %q after a relay deploy", target)
						}
						if !bytes.Equal(got.Certificate, certPEM) {
							t.Fatal("fortigate stored different certificate bytes than the relay deployed")
						}
					}
			},
		},
		{
			connector: "paloalto", target: "trstctl-app",
			start: func(t *testing.T) (string, *http.Client, relay.Material, relay.TargetConfig, func(*testing.T, string, string)) {
				srv := paloaltotest.New([]byte(token))
				t.Cleanup(srv.Close)
				return srv.URL(), srv.Client(),
					relay.Material{"credential.pan_api_key": []byte(token)},
					relay.TargetConfig{APIKeyRef: "credential.pan_api_key"}, // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
					func(t *testing.T, target, _ string) {
						obj, ok := srv.Object(target)
						if !ok {
							t.Fatalf("palo alto holds no object %q after a relay deploy", target)
						}
						if !bytes.Equal(obj.CertPEM, certPEM) {
							t.Fatal("palo alto stored different certificate bytes than the relay deployed")
						}
					}
			},
		},
	}

	// Every family the relay ADVERTISES must appear here. A family added to
	// RelayConnectorKinds without a case would otherwise ship an execution path
	// nothing has ever driven — which is the exact condition this file exists
	// to end.
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.connector] = true
	}
	for _, kind := range relay.RelayConnectorKinds() {
		if !covered[kind] {
			t.Errorf("the relay advertises %q and no test drives a deploy through it to a device",
				kind)
		}
	}

	// The fingerprint the control plane would put on the intent. Computed from
	// the certificate rather than invented, because the appliance connectors
	// name the object they upload after it — a made-up value would still pass
	// while proving nothing about the naming a rollback later depends on.
	fingerprint := connector.CertificateFingerprint(certPEM)
	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			url, client, material, cfg, verify := tc.start(t)
			cfg.Endpoint = url
			material["credential.cert_pem"] = certPEM
			material["credential.key_pem"] = keyPEM

			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.Execute(context.Background(), client, relay.DeployIntent{
				Connector:    tc.connector,
				Target:       tc.target,
				Fingerprint:  fingerprint,
				TargetConfig: raw,
			}, material); err != nil {
				t.Fatalf("relay deploy to %s: %v", tc.connector, err)
			}
			verify(t, tc.target, fingerprint)
		})
	}
}

// A relay deploy must refuse before touching the device when the credential it
// needs was not redeemed for this attempt.
//
// The device proofs cannot cover this: they construct the connector with the
// password in hand. Reference resolution is relay-only code, and a relay that
// silently deployed with an empty password would either fail confusingly or —
// against an appliance that does not enforce auth — succeed, which is worse.
func TestARelayDeployWithoutItsRedeemedCredentialNeverReachesTheDevice(t *testing.T) {
	srv := kemptest.New("appliance-token")
	t.Cleanup(srv.Close)

	cfg, err := json.Marshal(relay.TargetConfig{Endpoint: srv.URL(), TokenRef: "credential.kemp_token"}) // #nosec G101 -- a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798)
	if err != nil {
		t.Fatal(err)
	}
	// Cert and key present, the appliance token missing — the shape a partial
	// redemption produces.
	_, err = relay.Execute(context.Background(), srv.Client(), relay.DeployIntent{
		Connector: "kemp", Target: "vs-payments-443", Fingerprint: connector.CertificateFingerprint([]byte(testCertPEM)), TargetConfig: cfg,
	}, relay.Material{
		"credential.cert_pem": []byte(testCertPEM),
		"credential.key_pem":  []byte(testKeyPEM),
	})
	if err == nil {
		t.Fatal("the relay deployed with an unredeemed appliance token")
	}
	if certificates, bindings := srv.ObjectCounts(); certificates != 0 || bindings != 0 {
		t.Fatalf("the appliance was touched despite the refusal: certificates=%d bindings=%d",
			certificates, bindings)
	}
}

// F5 HA-peer sync through the relay (epic E1): a deploy with a peer endpoint
// configured must reach BOTH BIG-IPs. An F5 pair keeps certificate objects in
// separate stores, so a relay that updated only the active node would report
// success while the standby served the old certificate until a failover. This
// drives relay.Execute against two device doubles and confirms both hold the
// deployed certificate.
func TestARelayF5DeployReachesBothHAPeers(t *testing.T) {
	certPEM := []byte(testCertPEM)
	const (
		user = "svc-trstctl"
		pass = "appliance-secret"
	)
	active := f5test.New(user, pass)
	t.Cleanup(active.Close)
	standby := f5test.New(user, pass)
	t.Cleanup(standby.Close)

	cfg, err := json.Marshal(relay.TargetConfig{ // #nosec G101 -- credential REFERENCE NAMES, not credentials: the relay looks values up in redeemed material by these keys (CWE-798)
		Endpoint:         active.URL(),
		PeerEndpoint:     standby.URL(),
		Username:         user,
		PasswordRef:      "credential.f5_password",
		ClientSSLProfile: "clientssl-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := connector.CertificateFingerprint(certPEM)
	if _, err := relay.Execute(context.Background(), active.Client(), relay.DeployIntent{
		Connector:    "f5",
		Target:       "app",
		Fingerprint:  fingerprint,
		TargetConfig: cfg,
	}, relay.Material{
		"credential.f5_password": []byte(pass),
		"credential.cert_pem":    certPEM,
		"credential.key_pem":     []byte(testKeyPEM),
	}); err != nil {
		t.Fatalf("relay HA deploy: %v", err)
	}

	base := connector.DeployedObjectName("clientssl-app", fingerprint)
	for name, srv := range map[string]*f5test.Server{"active": active, "standby": standby} {
		got, ok := srv.Uploaded(base + ".crt")
		if !ok || !bytes.Equal(got, certPEM) {
			t.Fatalf("%s BIG-IP does not hold the deployed certificate at %s.crt (ok=%v); a relay HA "+
				"deploy that skips a peer is the defect this gate closes", name, base, ok)
		}
	}
}
