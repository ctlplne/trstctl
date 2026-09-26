// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// This is an ACME protocol double with real certificate signing. It does not
// qualify a real CA, its account authentication, or signer process isolation.
// The transport makes the before/after-finalization boundary deterministic.
type acmeRecoveryFaultTransport struct {
	base           http.RoundTripper
	beforeFinalize bool
	failPath       string
	failAfter      bool
	timeout        bool
	outage         atomic.Bool
	finalizations  atomic.Int32
	requests       atomic.Int32
}

func (f *acmeRecoveryFaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.requests.Add(1)
	if f.outage.Load() {
		if (f.beforeFinalize && !f.failAfter && req.URL.Path == f.failPath) || (!f.beforeFinalize && f.finalizations.Load() > 0) {
			if f.timeout {
				<-req.Context().Done()
				return nil, req.Context().Err()
			}
			return nil, errors.New("owned ACME availability fault")
		}
	}
	resp, err := f.base.RoundTrip(req)
	if err == nil && f.beforeFinalize && f.failAfter && f.outage.Load() && req.URL.Path == f.failPath {
		_, copyErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if copyErr != nil || closeErr != nil {
			return nil, errors.Join(copyErr, closeErr)
		}
		return nil, errors.New("owned loss of successful ACME preparation response")
	}
	if err == nil && strings.HasSuffix(req.URL.Path, "/finalize") && resp.StatusCode == http.StatusOK {
		f.finalizations.Add(1)
		if f.outage.Load() {
			// The receiver has minted the certificate. Discard its response and
			// block order reconciliation until the test restores connectivity.
			_, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if copyErr != nil || closeErr != nil {
				return nil, errors.Join(copyErr, closeErr)
			}
			return nil, errors.New("owned loss of finalized ACME response")
		}
	}
	return resp, err
}

func TestServedExternalACMERecoveryRequiresUnsubmittedFinalization(t *testing.T) {
	for _, phase := range []struct {
		name, path                string
		after, timeout, finalized bool
	}{
		{name: "directory-unavailable", path: "/directory"},
		{name: "account-unavailable", path: "/new-account"},
		{name: "order-unavailable", path: "/new-order"},
		{name: "account-response-lost", path: "/new-account", after: true},
		{name: "order-response-lost", path: "/new-order", after: true},
		{name: "directory-deadline", path: "/directory", timeout: true},
		{name: "order-deadline", path: "/new-order", timeout: true},
		{name: "finalized-response-lost", finalized: true},
	} {
		name, before := phase.name, !phase.finalized
		t.Run(name, func(t *testing.T) {
			upstream, err := acmefake.NewServer()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(upstream.Close)
			account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(account.Destroy)
			fault := &acmeRecoveryFaultTransport{base: http.DefaultTransport, beforeFinalize: before, failPath: phase.path, failAfter: phase.after, timeout: phase.timeout}
			fault.outage.Store(true)
			plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner("recovery-boundary", upstream.DirectoryURL(), &http.Client{Transport: fault, Timeout: 3 * time.Second}, account)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(plugin.Destroy)
			h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
				d.ExternalCAs = []ExternalCA{{ID: "recovery-boundary", Type: "letsencrypt", CA: plugin}}
			})
			startServedExternalCADispatcher(t, h)
			body := externalCAIssueRequestBody(t, "recovery-boundary.served.test")
			const key = "acme-recovery-boundary"
			const intentKey = key + ":external-ca:recovery-boundary"
			const path = "/api/v1/external-cas/recovery-boundary/issue"
			code, raw := doExternalCARequest(t, h, http.MethodPost, path, key, body)
			if code != http.StatusBadGateway {
				t.Fatalf("outage response=%d %s", code, raw)
			}
			wantFinalizations := int32(1)
			if before {
				wantFinalizations = 0
			}
			if got := fault.finalizations.Load(); got != wantFinalizations {
				t.Fatalf("fault reached wrong phase: finalizations=%d want=%d", got, wantFinalizations)
			}
			id := externalCAIntentOutboxID(t, h, intentKey)
			row, err := h.srv.outbox.Get(t.Context(), h.tenant, id)
			if err != nil || row.Attempts < 1 || row.Status != "pending" {
				t.Fatalf("missing original failed-attempt intent: status=%s attempts=%d err=%v", row.Status, row.Attempts, err)
			}
			t.Logf("original attempt: stage=%s finalizations=%d request_attempts=%d", row.LastError, fault.finalizations.Load(), fault.requests.Load())
			fault.outage.Store(false)
			forceExternalCAOutboxDue(t, h, intentKey)
			code, recovered := doExternalCARequest(t, h, http.MethodPost, path, key, body)
			if !before {
				if code != http.StatusBadGateway || fault.finalizations.Load() != 1 {
					t.Fatalf("ambiguous completed issuance was replayed: status=%d finalizations=%d", code, fault.finalizations.Load())
				}
				return
			}
			if code != http.StatusCreated {
				t.Fatalf("CA restored before any finalization, but original request cannot recover: status=%d finalizations=%d request_attempts=%d body=%s", code, fault.finalizations.Load(), fault.requests.Load(), recovered)
			}
			var cert externalCAIssueResponse
			if err := json.Unmarshal(recovered, &cert); err != nil {
				t.Fatal(err)
			}
			if cert.Serial == "" || cert.CertificatePEM == "" || fault.finalizations.Load() != 1 {
				t.Fatalf("recovery did not produce exactly one certificate: finalizations=%d", fault.finalizations.Load())
			}
			waitForOutboxStatus(t, h.srv.outbox, h.tenant, id, "delivered")
			code, replay := doExternalCARequest(t, h, http.MethodPost, path, key, body)
			if code != http.StatusCreated || !bytes.Equal(recovered, replay) || fault.finalizations.Load() != 1 {
				t.Fatal("completed replay changed the certificate or finalized a second order")
			}
		})
	}
}
