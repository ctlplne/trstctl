// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// A192: a failed deploy leaves an entry in the relay's own failure log that
// names the step and holds no secret — not the redeemed password, not the
// private key, not a bearer token or a credential-shaped field the appliance
// echoed — while the control plane still receives only the closed phrase. The
// log keeps the newest entries up to its bound and is private to the host.
func TestRelayKeepsAScrubbedBoundedFailureLogNamingTheStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "deploy-failures.jsonl")
	failures, err := relay.OpenDeployFailureLog(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	relay.SetDeployFailureLog(failures)
	t.Cleanup(func() { relay.SetDeployFailureLog(nil) })

	const bearer = "eyJhbGciOiJFUzI1NiJ9.c2Vzc2lvbg.c2lnbmF0dXJl" // #nosec G101 -- a canary the log must not keep, not a credential (CWE-798)
	const sessionToken = "s3ss10n-t0ken-9f8e7d"
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("auth failed for password " + appliancePassword + " key " + testKeyPEM +
			"\nretry with Authorization: Bearer " + bearer + " or token=" + sessionToken))
	}))
	defer hostile.Close()
	targetConfig, err := json.Marshal(map[string]string{ // #nosec G101 -- "password_ref" is a reference NAME, not a credential (CWE-798)
		"endpoint": hostile.URL, "username": "admin", "password_ref": "secret://appliance-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	material := map[string][]byte{
		"credential.cert_pem":      []byte(testCertPEM),
		"credential.key_pem":       []byte(testKeyPEM),
		"secret://appliance-admin": []byte(appliancePassword),
	}
	deploy := func(id int64) relay.Job {
		return intentJob(t, id, relay.DeployIntent{Connector: "f5", Target: "edge-f5", TargetConfig: targetConfig, Fingerprint: "ff00"})
	}
	ch := &fakeChannel{jobs: []relay.Job{deploy(9)}, material: material}
	if _, err := relay.RunOnce(context.Background(), ch, hostile.Client(), 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed || ch.reports[0].detail != "connector deploy failed against the target" {
		t.Fatalf("report = %+v, want only the closed phrase", ch.reports)
	}
	entries, err := relay.ReadDeployFailures(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("failure log = %+v, %v", entries, err)
	}
	got := entries[0]
	if got.JobID != 9 || got.Connector != "f5" || got.Target != "edge-f5" || got.Step != relay.DeployStepConnector ||
		!strings.Contains(got.Reason, "401") || got.At.IsZero() {
		t.Fatalf("entry = %+v, want the connector step and why", got)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{appliancePassword, "MIIEvQIBADANBgkq", "BEGIN PRIVATE KEY", bearer, sessionToken} {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("the failure log kept %q:\n%s", canary, raw)
		}
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("failure log mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}

	refused := &fakeChannel{jobs: []relay.Job{deploy(10)}, redeemErr: errors.New("rpc error: code = PermissionDenied desc = attempt superseded")}
	if _, err := relay.RunOnce(context.Background(), refused, hostile.Client(), 4, 60); err != nil {
		t.Fatal(err)
	}
	if len(refused.reports) != 1 || refused.reports[0].detail != "credential redemption was not granted" {
		t.Fatalf("refused redemption report = %+v", refused.reports)
	}
	for id := int64(11); id <= 13; id++ {
		more := &fakeChannel{jobs: []relay.Job{deploy(id)}, material: material}
		if _, err := relay.RunOnce(context.Background(), more, hostile.Client(), 4, 60); err != nil {
			t.Fatal(err)
		}
	}
	entries, err = relay.ReadDeployFailures(path)
	if err != nil || len(entries) != 3 || entries[0].JobID != 11 || entries[2].JobID != 13 {
		t.Fatalf("bounded log = %+v, %v; want the newest three", entries, err)
	}
	all := append([]relay.DeployFailure(nil), entries...)
	refusedLog := filepath.Join(t.TempDir(), "refused.jsonl")
	only, err := relay.OpenDeployFailureLog(refusedLog, 0)
	if err != nil {
		t.Fatal(err)
	}
	relay.SetDeployFailureLog(only)
	if _, err := relay.RunOnce(context.Background(), &fakeChannel{jobs: []relay.Job{deploy(14)}, redeemErr: errors.New("superseded")}, hostile.Client(), 4, 60); err != nil {
		t.Fatal(err)
	}
	if entries, err := relay.ReadDeployFailures(refusedLog); err != nil || len(entries) != 1 || entries[0].Step != relay.DeployStepRedeem ||
		!strings.Contains(entries[0].Reason, "superseded") {
		t.Fatalf("refused redemption entry = %+v, %v (earlier %+v)", entries, err, all)
	}
}
