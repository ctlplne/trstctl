// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
	"trstctl.com/trstctl/internal/store"
)

type tenantAdditionalSVIDFunc func(context.Context, string, time.Time) (spiffe.AdditionalX509SVID, error)

func (f tenantAdditionalSVIDFunc) IssueAdditionalX509SVID(ctx context.Context, id string, expiry time.Time) (spiffe.AdditionalX509SVID, error) {
	return f(ctx, id, expiry)
}

type tenantX509ResponseStream struct {
	grpc.ServerStream
	ctx  context.Context
	send func(*workloadpb.X509SVIDResponse) error
}

func (s tenantX509ResponseStream) Context() context.Context                  { return s.ctx }
func (s tenantX509ResponseStream) Send(r *workloadpb.X509SVIDResponse) error { return s.send(r) }

// This adapter test uses real signatures and PostgreSQL exclusion. The stream
// receiver is controlled; stock-client tests separately cover the gRPC transport.
func TestTenantServiceSPIFFEResponseIncludesAdditionalIssuerAndSend(t *testing.T) {
	st := newServerTestStore(t)
	log := openServerFederationSeamTestLog(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const tenant = "66b7fef9-0313-40c9-b927-80dbffbc043a"
	const id = "spiffe://response.test/workload"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "SPIFFE response"}); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	caDER, err := crypto.SelfSignedCACert(key, "response test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca := &spiffe.CAIssuer{CACertDER: caDER, CASigner: key, JWTSigner: key, JWTKeyID: "qa"}
	for _, lane := range []string{"x509", "x509-send-failure", "jwt"} {
		t.Run(lane, func(t *testing.T) {
			var observed []string
			var violations []string
			inspect := func(point string) {
				observed = append(observed, point)
				called := false
				err := st.WithTenantServiceBarrier(ctx, tenant, func(context.Context) error { called = true; return nil })
				if called || !errors.Is(err, store.ErrTenantServiceBusy) {
					violations = append(violations, fmt.Sprintf("%s: called=%v err=%v", point, called, err))
				}
			}
			sink := audit.NewAuditor(log)
			wl, err := spiffe.New(spiffe.Config{
				TenantID: tenant, TenantServiceWork: st.BeginTenantService,
				Issuer:  tenantSPIFFEIssuer{Issuer: ca, tenantID: tenant, work: st.BeginTenantService},
				Entries: []spiffe.RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}}},
				Audit: auditsink.AuditorFunc(func(work context.Context, kind, tenantID string, data []byte) error {
					if kind == "spiffe.workload_api.local_socket_used" {
						inspect("socket audit")
					}
					if strings.Contains(string(data), "x509-additional:") {
						inspect("additional audit")
					}
					return sink.Audit(work, kind, tenantID, data)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			additional := tenantAdditionalSVIDFunc(func(work context.Context, spiffeID string, expiry time.Time) (spiffe.AdditionalX509SVID, error) {
				inspect("additional signing")
				k, e := crypto.GenerateLockedKey(crypto.ECDSAP256)
				if e != nil {
					return spiffe.AdditionalX509SVID{}, e
				}
				defer k.Destroy()
				der, e := crypto.SignSVID(caDER, key, k.Public().DER, spiffeID, time.Until(expiry))
				if e != nil {
					return spiffe.AdditionalX509SVID{}, e
				}
				pk, e := k.PKCS8()
				if e != nil {
					return spiffe.AdditionalX509SVID{}, e
				}
				return spiffe.AdditionalX509SVID{CertificateDER: der, PrivateKeyPKCS8: pk, Hint: "qa-second-key"}, nil
			})
			api := spiffe.NewWorkloadAPIServer(wl, []string{"unix"}, spiffe.WithAdditionalX509SVIDIssuer(additional))
			request := metadata.NewIncomingContext(ctx, metadata.Pairs(spiffe.SecurityHeaderKey, spiffe.SecurityHeaderValue))
			if strings.HasPrefix(lane, "x509") {
				var sent *workloadpb.X509SVIDResponse
				sendFailure := errors.New("controlled send failure")
				stream := tenantX509ResponseStream{ctx: request, send: func(r *workloadpb.X509SVIDResponse) error {
					inspect("response send")
					sent = r
					if len(r.Svids) != 2 {
						return errors.New("expected two distinct-key identities")
					}
					for _, v := range r.Svids {
						if v.SpiffeId != id || len(v.X509SvidKey) == 0 {
							return errors.New("response identity or key missing")
						}
						if err := crypto.VerifyLeafSignedByCA(v.X509Svid, caDER); err != nil {
							return err
						}
					}
					if lane == "x509-send-failure" {
						return sendFailure
					}
					return nil
				}}
				err := api.FetchX509SVID(&workloadpb.X509SVIDRequest{}, stream)
				if lane == "x509-send-failure" {
					if !errors.Is(err, sendFailure) {
						t.Fatalf("send failure lost: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				for _, v := range sent.Svids {
					if v.X509SvidKey != nil {
						t.Fatal("response key was not wiped after send")
					}
				}
				if len(observed) != 4 {
					t.Fatalf("incomplete response probe: %v", observed)
				}
			} else {
				r, err := api.FetchJWTSVID(request, &workloadpb.JWTSVIDRequest{Audience: []string{"qa"}})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Svids) != 1 || r.Svids[0].SpiffeId != id {
					t.Fatal("wrong JWT identity")
				}
				bundle, err := ca.JWTBundle(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := crypto.VerifyJWT(r.Svids[0].Svid, bundle); err != nil {
					t.Fatal(err)
				}
				if len(observed) != 1 {
					t.Fatalf("incomplete JWT response probe: %v", observed)
				}
			}
			if len(violations) > 0 {
				t.Fatalf("lifecycle crossed response work: %v", violations)
			}
			if err := st.WithTenantServiceBarrier(ctx, tenant, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("finished response retained lock: %v", err)
			}
		})
	}
}
