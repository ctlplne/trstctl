// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/store"
)

type heldTenantSVIDIssuer struct {
	spiffe.Issuer
	hold func(context.Context) error
}

func (i heldTenantSVIDIssuer) SignX509SVID(ctx context.Context, _ string, _ []byte, _ time.Duration) ([]byte, error) {
	return nil, i.hold(ctx)
}
func (i heldTenantSVIDIssuer) SignJWTSVID(ctx context.Context, _ string, _ []string, _ time.Duration) (string, error) {
	return "", i.hold(ctx)
}

type heldEnrollmentIssuer struct {
	enroll.CAIssuer
	hold func() error
}

func (i heldEnrollmentIssuer) SignClientCSRWithTenant([]byte, string, []string, time.Duration, ...string) ([]byte, error) {
	return nil, i.hold()
}

// The boundary probe deliberately stops inside the issuer/handler. It proves
// lifecycle exclusion through that call, not validity of a generated certificate.
func TestTenantServiceProtocolWorkExcludesLifecycleChanges(t *testing.T) {
	for _, lane := range []string{"protocol", "spiffe-x509", "spiffe-jwt", "tsa", "agent-bootstrap", "agent-renewal"} {
		t.Run(lane, func(t *testing.T) {
			st := newServerTestStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			const tenantID = "e1d5b3cb-e79f-4c9f-a011-a202bbec2e32"
			if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "Service work test"}); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			stopped := errors.New("controlled stop inside admitted work")
			hold := func(ctx context.Context) error {
				close(entered)
				select {
				case <-release:
					return stopped
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			var run func() error
			switch lane {
			case "protocol":
				log := openServerFederationSeamTestLog(t)
				issuer := &protocolIssuer{store: st, log: log, idem: orchestrator.NewIdempotency(st), issue: func(ctx context.Context, _ []byte, _ time.Duration, _ crypto.LeafProfile) ([]byte, error) {
					return nil, hold(ctx)
				}}
				csr := agentCSRWithDNS(t, "work.example.test", []string{"work.example.test"})
				run = func() error {
					_, err := issuer.IssueProtocolLeaf(ctx, tenantID, "est", "service-work", csr, time.Minute)
					return err
				}
			case "spiffe-x509", "spiffe-jwt":
				issuer := tenantSPIFFEIssuer{Issuer: heldTenantSVIDIssuer{hold: hold}, tenantID: tenantID, work: st.BeginTenantService}
				run = func() error {
					if lane == "spiffe-x509" {
						_, err := issuer.SignX509SVID(ctx, "spiffe://qa/workload", nil, time.Minute)
						return err
					}
					_, err := issuer.SignJWTSVID(ctx, "spiffe://qa/workload", []string{"qa"}, time.Minute)
					return err
				}
			case "tsa":
				handler := tenantProtocolAdmission(st.BeginTenantService, nil, tenantID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = hold(r.Context())
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				run = func() error {
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/tsa", nil).WithContext(ctx))
					if w.Code != http.StatusServiceUnavailable {
						return errors.New("unexpected timestamp probe result")
					}
					return stopped
				}
			case "agent-bootstrap", "agent-renewal":
				ca, err := mtls.NewCA("service work fixture")
				if err != nil {
					t.Fatal(err)
				}
				authority, err := enroll.NewAuthorityWithIssuer(heldEnrollmentIssuer{CAIssuer: ca, hold: func() error { return hold(ctx) }}, enroll.NewMemoryTokenStore(), enroll.WithTenantServiceWork(st.BeginTenantService))
				if err != nil {
					t.Fatal(err)
				}
				csr := agentCSRWithDNS(t, "agent-work", nil)
				if lane == "agent-bootstrap" {
					token, err := authority.IssueBootstrapToken(ctx, tenantID, "")
					if err != nil {
						t.Fatal(err)
					}
					defer secret.Wipe(token)
					run = func() error { _, err := authority.EnrollBootstrap(ctx, token, csr); return err }
				} else {
					chain, err := ca.SignClientCSRWithTenant(csr, tenantID, nil, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					leaf, err := mtls.FirstCertDER(chain)
					if err != nil {
						t.Fatal(err)
					}
					run = func() error { _, err := authority.EnrollRenewal(ctx, [][]byte{leaf}, csr); return err }
				}
			}
			finished := make(chan error, 1)
			go func() { finished <- run() }()
			joined := false
			defer func() {
				unblock()
				if !joined {
					<-finished
				}
			}()
			select {
			case <-entered:
			case err := <-finished:
				joined = true
				t.Fatalf("did not reach admitted work: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			called := false
			barrierErr := st.WithTenantServiceBarrier(ctx, tenantID, func(context.Context) error { called = true; return nil })
			unblock()
			result := <-finished
			joined = true
			if !errors.Is(result, stopped) {
				t.Fatalf("work did not reach controlled result: %v", result)
			}
			if called || !errors.Is(barrierErr, store.ErrTenantServiceBusy) {
				t.Fatalf("lifecycle crossed active %s: called=%v err=%v", lane, called, barrierErr)
			}
			if err := st.WithTenantServiceBarrier(ctx, tenantID, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("completed work retained lifecycle lock: %v", err)
			}
		})
	}
}
