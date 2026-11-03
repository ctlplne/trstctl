// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// An agent whose tenant is refused hears the same PermissionDenied for every
// condition: the reason admission names, and any text an inner error adds,
// stay on the server.
func TestAgentChannelTenantRefusalIsTheSameForEveryCondition(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	ca, err := mtls.NewCA("agent channel refusal fixture")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(agentCSRWithDNS(t, "agent-refused", nil), tenantID, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	state, err := crypto.TLSStateWithPeerCertificates([][]byte{leaf})
	if err != nil {
		t.Fatal(err)
	}
	ctx := peer.NewContext(t.Context(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *state.ConnectionState()}})

	const reason = "the tenant's erasure is pending"
	for name, refusal := range map[string]error{
		"refusal":            tenancy.Refused(reason),
		"wrapped refusal":    fmt.Errorf("admission: %w", tenancy.Refused(reason)),
		"sentinel with text": fmt.Errorf("%w: %s", tenancy.ErrServiceUnavailable, reason),
	} {
		t.Run(name, func(t *testing.T) {
			// The store is only required to be present before admission runs.
			svc := &agentService{store: &store.Store{}, tenantServiceCheck: func(_ context.Context, tenant string) error {
				if tenant != tenantID {
					t.Fatalf("admission asked about tenant %q; want the certificate's %q", tenant, tenantID)
				}
				return refusal
			}}
			_, err := svc.peerInfo(ctx)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("peerInfo = %v; want PermissionDenied", err)
			}
			if got := status.Convert(err).Message(); got != tenancy.ErrServiceUnavailable.Error() {
				t.Errorf("the agent hears %q; want %q", got, tenancy.ErrServiceUnavailable.Error())
			}
		})
	}
}
