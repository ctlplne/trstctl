// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

func TestCR024SVIDsAreWithheldWhenIssuanceAuditFails(t *testing.T) {
	const id = "spiffe://example.org/ns/default/sa/audit-failure"
	appendErr := errors.New("injected audit append failure")
	for _, kind := range []string{"x509", "jwt"} {
		t.Run(kind, func(t *testing.T) {
			g := graph.New()
			srv, err := New(Config{
				Issuer: testIssuer(t), TenantID: "tenant-a", Graph: g,
				Audit:   auditsink.AuditorFunc(func(context.Context, string, string, []byte) error { return appendErr }),
				Entries: []RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix:uid:101"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if kind == "x509" {
				key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
				if err != nil {
					t.Fatal(err)
				}
				defer key.Destroy()
				got, err := srv.FetchX509SVIDs(t.Context(), key.Public().DER, []string{"unix:uid:101"})
				if !errors.Is(err, appendErr) || len(got) != 0 {
					t.Fatalf("X509-SVID escaped without an audit record: count=%d err=%v", len(got), err)
				}
			} else {
				got, err := srv.FetchJWTSVIDs(t.Context(), []string{"service"}, []string{"unix:uid:101"})
				if !errors.Is(err, appendErr) || len(got) != 0 {
					t.Fatalf("JWT-SVID escaped without an audit record: count=%d err=%v", len(got), err)
				}
			}
			if _, ok := g.Node(id); ok {
				t.Fatal("credential graph recorded an issuance without its audit event")
			}
		})
	}
}

func TestCR024WorkloadAPIMapsAuditFailureToRetryableSafeError(t *testing.T) {
	api, _, cancel := newX509StreamProbe(t, 0)
	defer cancel()
	api.wl.cfg.Audit = auditsink.AuditorFunc(func(context.Context, string, string, []byte) error {
		return errors.New("private audit append path /tmp/secret-fixture")
	})
	if resp, err := api.buildX509SVIDResponse(t.Context()); resp != nil || status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private audit append path") {
		t.Fatalf("X509 audit outage returned response or unsafe status: response_present=%t err=%v", resp != nil, err)
	}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(SecurityHeaderKey, SecurityHeaderValue))
	if resp, err := api.FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{Audience: []string{"service"}}); resp != nil || status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private audit append path") {
		t.Fatalf("JWT audit outage returned response or unsafe status: response_present=%t err=%v", resp != nil, err)
	}
}

func TestCR024AdditionalSVIDIsWithheldWhenItsAuditFails(t *testing.T) {
	api, _, cancel := newX509StreamProbe(t, 0)
	defer cancel()
	var issued int
	api.wl.cfg.Audit = auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, payload []byte) error {
		if eventType == "spiffe.svid.issued" {
			issued++
			if bytes.Contains(payload, []byte(`"type":"x509-additional:alternate"`)) {
				return errors.New("private additional issuer audit path")
			}
		}
		return nil
	})
	api.additionalX509SVIDIssuer = &additionalSVIDProbe{}
	resp, err := api.buildX509SVIDResponse(t.Context())
	if resp != nil || status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private additional issuer audit path") || issued != 2 {
		t.Fatalf("additional SVID audit outage escaped: response_present=%t status=%v issued_events=%d", resp != nil, status.Code(err), issued)
	}
}
