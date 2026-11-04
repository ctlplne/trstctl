// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli/evaluate"
	"trstctl.com/trstctl/internal/config"
)

// restartableFront serves one address, as a deployment's listener does. A
// restart closes it, builds a new server from the same store, event log and
// signer, and serves the same address again.
type restartableFront struct {
	t         *testing.T
	h         *servedHarness
	protocols config.Protocols
	addr      string

	mu        sync.Mutex
	current   *http.Server
	requests  atomic.Int64
	restartAt atomic.Int64 // the request that starts the restart; 0 is none
	restarts  sync.WaitGroup
}

func (f *restartableFront) serve(handler http.Handler, l net.Listener) {
	s := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.requests.Add(1) == f.restartAt.Load() {
			f.restarts.Add(1)
			go f.restart()
		}
		handler.ServeHTTP(w, r)
	})}
	f.mu.Lock()
	f.current = s
	f.mu.Unlock()
	go func() {
		if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			f.t.Errorf("serve %s: %v", f.addr, err)
		}
	}()
}

func (f *restartableFront) restart() {
	defer f.restarts.Done()
	f.mu.Lock()
	old := f.current
	f.mu.Unlock()
	_ = old.Close()
	time.Sleep(500 * time.Millisecond) // down long enough for the evaluator to notice
	rebuilt, err := Build(context.Background(), Deps{
		Store: f.h.store, Log: f.h.log, Signer: f.h.signer, SignAuthorizer: f.h.authz,
		CACertFile: f.h.caFile, Protocols: f.protocols, KEK: f.h.kek, EnableSecretsAPI: true,
	})
	if err != nil {
		f.t.Errorf("restart: build: %v", err)
		return
	}
	cleanupServedServer(f.t, rebuilt)
	var l net.Listener
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if l, err = net.Listen("tcp", f.addr); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		f.t.Errorf("restart: listen on %s again: %v", f.addr, err)
		return
	}
	f.serve(rebuilt.Handler(), l)
}

// A249: `trstctl evaluate --cycles 3` runs the secrets and SSH journeys three
// times unattended against a served control plane that is restarted in the
// middle of the second cycle. The cut cycle is interrupted, the evaluator
// waits for /readyz, and the third cycle passes against the restarted
// control plane, so the run passes.
func TestServedEvaluateCyclesRecoverFromARestartA249(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the secrets journey's run step's child is a POSIX shell")
	}
	protocols := config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SSHUserPrincipals: []string{config.DefaultEvalSSHUserPrincipal}}
	h := newServedHarness(t, protocols, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A249 cycles tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "certs:issue", "certs:write", "certs:read")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &restartableFront{t: t, h: h, protocols: protocols, addr: listener.Addr().String()}
	front.serve(h.srv.Handler(), listener)
	t.Cleanup(func() {
		front.restarts.Wait()
		front.mu.Lock()
		defer front.mu.Unlock()
		_ = front.current.Close()
	})

	pack, err := evaluate.Evaluate(t.Context(), evaluate.Options{
		Server: "http://" + front.addr, Token: token, Journeys: []string{evaluate.JourneySecrets, evaluate.JourneySSH},
		Cycles: 3, RecoveryTimeout: time.Minute, Timeout: time.Minute, PollInterval: 100 * time.Millisecond,
		// The restart begins at cycle 2's third request, after some of its
		// steps have run.
		CycleStarted: func(cycle int) {
			if cycle == 2 {
				front.restartAt.Store(front.requests.Load() + 3)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	verdicts := make([]string, 0, len(pack.Cycles))
	for _, c := range pack.Cycles {
		verdicts = append(verdicts, string(c.Verdict))
	}
	details := func(c evaluate.CycleResult) string {
		var out []string
		for _, journey := range c.Journeys {
			for _, s := range journey.Steps {
				out = append(out, s.Name+"="+string(s.Status)+" ("+s.Detail+")")
			}
		}
		return strings.Join(out, "\n")
	}
	if pack.Format != evaluate.PackFormatV3 || pack.Verdict != evaluate.StatusPass || strings.Join(verdicts, " ") != "pass interrupted pass" {
		for _, c := range pack.Cycles {
			t.Logf("cycle %d %s outage %+v\n%s", c.Cycle, c.Verdict, c.Outage, details(c))
		}
		t.Fatalf("pack %s %s, cycles %v", pack.Format, pack.Verdict, verdicts)
	}
	outage := pack.Cycles[1].Outage
	if outage == nil || outage.RecoveredAt.IsZero() || !outage.RecoveredAt.After(outage.FirstSeen) {
		t.Fatalf("cycle 2 outage = %+v", outage)
	}
	// Cycle 2 got some way before the restart cut it short.
	passed := 0
	for _, journey := range pack.Cycles[1].Journeys {
		passed += journey.Summary.Passed
	}
	if passed == 0 {
		t.Fatalf("the restart was not mid-cycle: cycle 2 passed no step\n%s", details(pack.Cycles[1]))
	}
}

// A249: the certificate journey repeats on one target: each cycle issues,
// deploys, verifies, renews and revokes again through the same endpoint.
func TestServedEvaluateCertificateJourneyCyclesA249(t *testing.T) {
	opts := newIncidentLab(t, "cycles.lab.test")
	opts.Journeys, opts.Cycles = []string{evaluate.JourneyCertificate}, 2
	pack, err := evaluate.Evaluate(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range pack.Cycles {
		if c.Verdict != evaluate.StatusPass {
			for _, s := range c.Steps {
				t.Logf("cycle %d %s=%s (%s)", c.Cycle, s.Name, s.Status, s.Detail)
			}
		}
	}
	if pack.Verdict != evaluate.StatusPass || len(pack.Cycles) != 2 || pack.Summary.Passed != 16 {
		t.Fatalf("pack %s, %d cycles, summary %+v", pack.Verdict, len(pack.Cycles), pack.Summary)
	}
	first, second := pack.Cycles[0].Steps, pack.Cycles[1].Steps
	if first[2].Evidence["fingerprint"] == second[2].Evidence["fingerprint"] || first[5].Evidence["fingerprint"] == second[5].Evidence["fingerprint"] {
		t.Fatalf("the second cycle did not issue and renew anew: %v / %v", first[2].Evidence, second[2].Evidence)
	}
}
