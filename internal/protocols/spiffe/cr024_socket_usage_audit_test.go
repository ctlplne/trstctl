// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

func TestCR024LocalSocketUsageAuditFailureWithholdsSVIDs(t *testing.T) {
	for _, kind := range []string{"x509", "jwt"} {
		t.Run(kind, func(t *testing.T) {
			api, _, cancel := newX509StreamProbe(t, 0)
			defer cancel()
			api.wl.cfg.Audit = auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
				if eventType == "spiffe.workload_api.local_socket_used" {
					return errors.New("injected socket-use audit failure")
				}
				return nil
			})
			if kind == "x509" {
				resp, err := api.buildX509SVIDResponse(t.Context())
				if resp != nil || status.Code(err) != codes.Unavailable {
					t.Fatalf("X509-SVID escaped socket-use audit failure: response_present=%t status=%v", resp != nil, status.Code(err))
				}
				return
			}
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(SecurityHeaderKey, SecurityHeaderValue))
			resp, err := api.FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{Audience: []string{"service"}})
			if resp != nil || status.Code(err) != codes.Unavailable {
				t.Fatalf("JWT-SVID escaped socket-use audit failure: response_present=%t status=%v", resp != nil, status.Code(err))
			}
		})
	}
}

func TestCR024LocalSocketRefusalsExposeAuditOutage(t *testing.T) {
	for _, kind := range []string{"local-workloads-off", "keygen-off"} {
		t.Run(kind, func(t *testing.T) {
			api, _, cancel := newX509StreamProbe(t, 0)
			defer cancel()
			api.wl.cfg.Audit = auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
				if eventType == "spiffe.workload_api.local_socket_used" {
					return errors.New("injected refusal audit failure")
				}
				return nil
			})
			var err error
			if kind == "local-workloads-off" {
				err = api.refuseLocalIssuance(t.Context(), "x509")
			} else {
				api.x509KeygenCheck = func(context.Context) error { return errors.New("key generation disabled") }
				err = api.refuseX509Keygen(t.Context())
			}
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("refusal hid audit outage: status=%v", status.Code(err))
			}
		})
	}
}
