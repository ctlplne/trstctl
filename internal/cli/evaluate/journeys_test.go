// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

// labServer is a control plane's secret store and SSH CA, as far as the two
// journeys use them.
type labServer struct {
	mu      sync.Mutex
	secrets map[string]labSecret
	ca      *crypto.LockedSigner
	serial  uint64
	krl     *sshca.KRL
	version uint64
	// lagKRL leaves this many KRL reads without the latest revocation.
	lagKRL int
}

type labSecret struct {
	value   string
	version int
}

func newLabServer(t *testing.T) (*labServer, *httptest.Server) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	lab := &labServer{secrets: map[string]labSecret{}, ca: ca, krl: sshca.NewKRL(), version: 1}
	srv := httptest.NewServer(http.HandlerFunc(lab.serve))
	t.Cleanup(srv.Close)
	return lab, srv
}

func (l *labServer) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	const store = "/api/v1/secrets/store"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == store:
		name, value := body["name"].(string), body["value"].(string)
		l.secrets[name] = labSecret{value: value, version: 1}
		reply(http.StatusCreated, map[string]any{"name": name, "version": 1})
	case strings.HasPrefix(r.URL.Path, store+"/"):
		name := strings.TrimPrefix(r.URL.Path, store+"/")
		current, ok := l.secrets[name]
		switch r.Method {
		case http.MethodGet:
			if !ok {
				reply(http.StatusNotFound, map[string]any{"detail": "secret not found"})
				return
			}
			reply(http.StatusOK, map[string]any{"name": name, "value": current.value, "version": current.version})
		case http.MethodPut:
			l.secrets[name] = labSecret{value: body["value"].(string), version: current.version + 1}
			reply(http.StatusOK, map[string]any{"name": name, "version": current.version + 1})
		case http.MethodDelete:
			delete(l.secrets, name)
			w.WriteHeader(http.StatusNoContent)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/ssh/certificates":
		l.serial++
		var principals []string
		for _, p := range body["principals"].([]any) {
			principals = append(principals, p.(string))
		}
		cert, err := crypto.SignSSHCertificate(l.ca, crypto.SSHCertParams{
			SubjectPublicKey: []byte(body["public_key"].(string)), KeyID: body["key_id"].(string), Principals: principals,
			CertType: crypto.SSHUserCert, ValidAfter: time.Now().Add(-time.Minute), ValidBefore: time.Now().Add(10 * time.Minute), Serial: l.serial,
		})
		if err != nil {
			reply(http.StatusBadRequest, map[string]any{"detail": err.Error()})
			return
		}
		reply(http.StatusCreated, map[string]any{"certificate": strings.TrimSpace(string(cert)), "serial": l.serial})
	case r.Method == http.MethodGet && r.URL.Path == "/ssh/ca":
		key, err := crypto.SSHPublicKeyFromSigner(l.ca)
		if err != nil {
			reply(http.StatusInternalServerError, map[string]any{"detail": err.Error()})
			return
		}
		_, _ = w.Write(key)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/ssh/certificates/revoke":
		l.krl.RevokeSerial(uint64(body["serial"].(float64)))
		l.version++
		reply(http.StatusOK, map[string]any{"revoked": true})
	case r.Method == http.MethodGet && r.URL.Path == "/ssh/krl":
		if l.lagKRL > 0 {
			l.lagKRL--
			_, _ = w.Write(sshca.NewKRL().DistributeKRL(l.version - 1))
			return
		}
		_, _ = w.Write(l.krl.DistributeKRL(l.version))
	default:
		reply(http.StatusNotFound, map[string]any{"detail": "no route " + r.Method + " " + r.URL.Path})
	}
}

func labOptions(srv *httptest.Server, lab *labServer, journeys ...string) Options {
	return Options{
		Server: srv.URL, Token: "lab-token", HTTPClient: srv.Client(), Journeys: journeys,
		Timeout: 5 * time.Second, PollInterval: 10 * time.Millisecond,
		// trstctl run, as the lab sees it: the child gets the stored value and
		// compares it with the one expected.
		RunCLI: func(_ context.Context, name, want string) error {
			lab.mu.Lock()
			defer lab.mu.Unlock()
			if lab.secrets[name].value != want {
				return errors.New("the child exited 1: it was given another value")
			}
			return nil
		},
	}
}

func stepStatuses(steps []Step) string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Name+"="+string(s.Status))
	}
	return strings.Join(out, " ")
}

// A249: the secrets and SSH journeys pass against a control plane that does
// what they ask, in a v2 pack that keeps the secret's value out of it.
func TestSecretsAndSSHJourneysPassA249(t *testing.T) {
	lab, srv := newLabServer(t)
	lab.lagKRL = 2 // the KRL catches up after two reads
	pack, err := Evaluate(t.Context(), labOptions(srv, lab, JourneySecrets, JourneySSH))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Format != PackFormatV2 || pack.Verdict != StatusPass || len(pack.Steps) != 0 || len(pack.Journeys) != 2 {
		t.Fatalf("pack = %s verdict %s, %d steps, %d journeys", pack.Format, pack.Verdict, len(pack.Steps), len(pack.Journeys))
	}
	want := map[string]string{
		JourneySecrets: "secret_create=pass secret_read=pass secret_rotate=pass secret_run=pass secret_delete=pass",
		JourneySSH:     "ssh_issue=pass ssh_verify=pass ssh_revoke=pass ssh_krl=pass",
	}
	for _, journey := range pack.Journeys {
		if got := stepStatuses(journey.Steps); got != want[journey.Name] || journey.Verdict != StatusPass {
			t.Fatalf("%s journey: %s (%s)", journey.Name, got, journey.Verdict)
		}
	}
	if pack.Summary.Passed != 9 || pack.Summary.Failed != 0 || pack.Summary.Skipped != 0 {
		t.Fatalf("summary = %+v", pack.Summary)
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(lab.secrets) != 0 {
		t.Fatalf("the journey left %d secrets behind", len(lab.secrets))
	}
	if !strings.Contains(string(raw), `"value_sha256"`) || strings.Contains(string(raw), `"value":`) {
		t.Fatalf("the pack must carry the secret's digest, never its value: %s", raw)
	}
}

// A249: a forced failure in each journey is reported as a failure — the step
// that expected what did not happen fails, its journey's later steps are
// skipped, the other journey is unaffected, and the pack's verdict fails.
func TestForcedFailureIsReportedAsFailureA249(t *testing.T) {
	for _, tc := range []struct {
		journey, failed, other string
		steps                  string
	}{
		{JourneySecrets, StepSecretRead, JourneySSH, "secret_create=pass secret_read=fail secret_rotate=skipped secret_run=skipped secret_delete=skipped"},
		{JourneySSH, StepSSHKRL, JourneySecrets, "ssh_issue=pass ssh_verify=pass ssh_revoke=pass ssh_krl=fail"},
	} {
		lab, srv := newLabServer(t)
		opts := labOptions(srv, lab, JourneySecrets, JourneySSH)
		opts.ForceFailure = tc.journey
		pack, err := Evaluate(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if pack.Verdict != StatusFail {
			t.Fatalf("forced %s: the pack passed", tc.journey)
		}
		for _, journey := range pack.Journeys {
			switch journey.Name {
			case tc.journey:
				if got := stepStatuses(journey.Steps); got != tc.steps || journey.Verdict != StatusFail || !journey.ForcedFailure {
					t.Fatalf("forced %s: %s (verdict %s, forced %v)", tc.journey, got, journey.Verdict, journey.ForcedFailure)
				}
				if !strings.Contains(strings.Join(journey.Limits, " "), "forced failure") {
					t.Fatalf("forced %s: the limits do not say a failure was forced: %q", tc.journey, journey.Limits)
				}
			case tc.other:
				if journey.Verdict != StatusPass || journey.ForcedFailure {
					t.Fatalf("forcing %s changed the %s journey: %s", tc.journey, tc.other, stepStatuses(journey.Steps))
				}
			}
		}
	}
	lab, srv := newLabServer(t)
	opts := labOptions(srv, lab, JourneySecrets)
	opts.ForceFailure = JourneySSH
	if _, err := Evaluate(t.Context(), opts); err == nil {
		t.Fatal("a forced failure for a journey that is not run was accepted")
	}
}

// A249: the journey list is checked, the certificate journey alone is the
// default, and only the certificate journey needs a deployment target.
func TestJourneyListA249(t *testing.T) {
	if got, err := Journeys(""); err != nil || len(got) != 1 || got[0] != JourneyCertificate {
		t.Fatalf("default journeys = %v, %v", got, err)
	}
	if got, err := Journeys("ssh, secrets,ssh"); err != nil || strings.Join(got, ",") != "ssh,secrets" {
		t.Fatalf("journeys = %v, %v", got, err)
	}
	if _, err := Journeys("certificate,dns"); err == nil {
		t.Fatal("an unknown journey was accepted")
	}
	if _, err := Evaluate(t.Context(), Options{Server: "https://cp.example.test", Token: "t"}); err == nil ||
		!strings.Contains(err.Error(), "deployment target") {
		t.Fatalf("the certificate journey without a target = %v", err)
	}
}
