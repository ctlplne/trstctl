// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// B2 (design-limit review lead): the relay reports a closed phrase for a
// failed deploy, because the appliance's error can echo the credential, and
// the docs say the detail stays on the relay. Nothing kept it: the error was
// discarded, so nobody anywhere could read why a deploy failed. The relay now
// logs it on its own host, with every redeemed value (and every line of a
// multi-line one) redacted; the report to the control plane is unchanged.
func TestRelayLogsWhyADeployFailedWithTheCredentialsRedacted(t *testing.T) {
	var logged bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })

	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("auth failed for password " + appliancePassword + " key " + testKeyPEM))
	}))
	defer hostile.Close()
	targetConfig, err := json.Marshal(map[string]string{ // #nosec G101 -- "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798)
		"endpoint": hostile.URL, "username": "admin", "password_ref": "secret://appliance-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs: []relay.Job{intentJob(t, 9, relay.DeployIntent{Connector: "f5", Target: "edge-f5", TargetConfig: targetConfig, Fingerprint: "ff00"})},
		material: map[string][]byte{
			"credential.cert_pem":      []byte(testCertPEM),
			"credential.key_pem":       []byte(testKeyPEM),
			"secret://appliance-admin": []byte(appliancePassword),
		},
	}
	if _, err := relay.RunOnce(context.Background(), ch, hostile.Client(), 4, 60); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed || ch.reports[0].detail != "connector deploy failed against the target" {
		t.Fatalf("report = %+v, want the closed failure phrase", ch.reports)
	}
	text := logged.String()
	if !strings.Contains(text, "job 9") || !strings.Contains(text, "f5 deploy to edge-f5 failed") || !strings.Contains(text, "401") {
		t.Fatalf("the relay's own log does not say why the deploy failed:\n%s", text)
	}
	for _, canary := range []string{appliancePassword, "MIIEvQIBADANBgkq", "BEGIN PRIVATE KEY"} {
		if strings.Contains(text, canary) {
			t.Fatalf("the relay's log leaked %q:\n%s", canary, text)
		}
	}
}
