// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/store"
)

// Pause after a real signature, at the real event-log adapter. The lifecycle
// fence must cover the remaining audit and graph writes as well as signing.
func TestTenantServiceSPIFFEOperationIncludesAuditAndResult(t *testing.T) {
	for _, lane := range []string{"x509-local", "jwt-local", "x509-node", "jwt-node"} {
		t.Run(lane, func(t *testing.T) {
			st := newServerTestStore(t)
			log := openServerFederationSeamTestLog(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			const tenant = "2be51f06-e302-4ac6-9990-6874418f9956"
			const id = "spiffe://operation.test/workload"
			if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "SPIFFE operation"}); err != nil {
				t.Fatal(err)
			}
			key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			caDER, err := crypto.SelfSignedCACert(key, "operation test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			defer workload.Destroy()
			ca := &spiffe.CAIssuer{CACertDER: caDER, CASigner: key, JWTSigner: key, JWTKeyID: "qa"}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			sink := audit.NewAuditor(log)
			var auditErr error
			held := auditsink.AuditorFunc(func(ctx context.Context, kind, tenantID string, data []byte) error {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				auditErr = sink.Audit(ctx, kind, tenantID, data)
				return auditErr
			})
			parent := ""
			if lane == "x509-node" || lane == "jwt-node" {
				parent = "spiffe://operation.test/agent/node"
			}
			g := graph.New()
			wl, err := spiffe.New(spiffe.Config{
				TenantID: tenant, TenantServiceWork: st.BeginTenantService,
				Issuer: tenantSPIFFEIssuer{Issuer: ca, tenantID: tenant, work: st.BeginTenantService},
				Audit:  held, Graph: g, Entries: []spiffe.RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}, ParentID: parent}},
			})
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if lane == "x509-local" || lane == "x509-node" {
					var values []spiffe.X509SVID
					var err error
					if parent == "" {
						values, err = wl.FetchX509SVIDs(ctx, workload.Public().DER, []string{"unix"})
					} else {
						values, err = wl.FetchX509SVIDsForNode(ctx, parent, workload.Public().DER, []string{"unix"})
					}
					if err == nil && len(values) != 1 {
						err = errors.New("expected one X509 identity")
					}
					if err == nil {
						err = crypto.VerifyLeafSignedByCA(values[0].CertChain[0], caDER)
					}
					if err == nil {
						var got string
						got, err = crypto.SPIFFEIDFromCert(values[0].CertChain[0])
						if err == nil && got != id {
							err = errors.New("wrong X509 identity")
						}
					}
					result <- err
					return
				}
				var values []spiffe.JWTSVID
				var err error
				if parent == "" {
					values, err = wl.FetchJWTSVIDs(ctx, []string{"qa"}, []string{"unix"})
				} else {
					values, err = wl.FetchJWTSVIDsForNode(ctx, parent, []string{"qa"}, []string{"unix"})
				}
				if err == nil && len(values) != 1 {
					err = errors.New("expected one JWT identity")
				}
				if err == nil {
					bundle, e := ca.JWTBundle(ctx)
					err = e
					if err == nil {
						claims, e := crypto.VerifyJWT(values[0].Token, bundle)
						err = e
						if err == nil {
							var c struct {
								Sub string `json:"sub"`
							}
							err = json.Unmarshal(claims, &c)
							if err == nil && c.Sub != id {
								err = errors.New("wrong JWT identity")
							}
						}
					}
				}
				result <- err
			}()
			joined := false
			defer func() {
				unblock()
				if !joined {
					<-result
				}
			}()
			select {
			case <-entered:
			case err := <-result:
				joined = true
				t.Fatalf("audit was not reached: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			called := false
			barrierErr := st.WithTenantServiceBarrier(ctx, tenant, func(context.Context) error { called = true; return nil })
			unblock()
			err = <-result
			joined = true
			if err != nil {
				t.Fatalf("returned identity failed verification: %v", err)
			}
			if auditErr != nil {
				t.Fatalf("audit append failed: %v", auditErr)
			}
			if _, ok := g.Node(id); !ok {
				t.Fatal("issued workload missing from graph")
			}
			if called || !errors.Is(barrierErr, store.ErrTenantServiceBusy) {
				t.Fatalf("lifecycle crossed unfinished audit/result: called=%v err=%v", called, barrierErr)
			}
			if err := st.WithTenantServiceBarrier(ctx, tenant, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("finished operation retained lock: %v", err)
			}
		})
	}
}
