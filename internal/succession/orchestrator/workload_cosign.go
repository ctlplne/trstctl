// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/succession/agent"
)

// Workload-held predecessor co-sign (A17, PCAS-claim-19).
//
// A workload agent that holds an identity's predecessor key serves the co-sign
// RPC (trstctl-agent --workload-cosign-listen). The control plane reaches it
// through one configured endpoint per (tenant, identity): a unix socket for a
// co-located agent, or host:port over the pinned mutual TLS the agent demands.
// The dialer hands the succession worker a PredecessorCoSigner for one request
// and closes the connection afterwards.

// WorkloadCoSignerEndpoint is one agent's co-sign endpoint.
type WorkloadCoSignerEndpoint struct {
	TenantID    string
	IdentityID  string
	Address     string
	TLSCertFile string
	TLSKeyFile  string
	PeerCAFile  string
	PeerPinHex  string
	ServerName  string
}

// WorkloadCoSignerDialer resolves a remote co-signer for a tenant identity.
type WorkloadCoSignerDialer interface {
	CoSigner(ctx context.Context, tenantID, identityID string) (agent.PredecessorCoSigner, func(), error)
}

// ErrNoWorkloadCoSigner reports an identity whose genesis anchors workload
// custody but has no configured co-sign endpoint.
var ErrNoWorkloadCoSigner = errors.New("pcas succession: no workload co-signer is configured for this identity")

// ConfiguredWorkloadCoSigners is the operator-configured dialer.
type ConfiguredWorkloadCoSigners struct {
	endpoints map[string]WorkloadCoSignerEndpoint
}

// NewConfiguredWorkloadCoSigners indexes endpoints by tenant and identity.
func NewConfiguredWorkloadCoSigners(endpoints []WorkloadCoSignerEndpoint) *ConfiguredWorkloadCoSigners {
	out := &ConfiguredWorkloadCoSigners{endpoints: make(map[string]WorkloadCoSignerEndpoint, len(endpoints))}
	for _, e := range endpoints {
		out.endpoints[coSignerKey(e.TenantID, e.IdentityID)] = e
	}
	return out
}

func coSignerKey(tenantID, identityID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(identityID)
}

// CoSigner dials the identity's endpoint. The returned release closes the
// connection; the co-signer is bound to ctx.
func (c *ConfiguredWorkloadCoSigners) CoSigner(ctx context.Context, tenantID, identityID string) (agent.PredecessorCoSigner, func(), error) {
	if c == nil {
		return nil, nil, ErrNoWorkloadCoSigner
	}
	e, ok := c.endpoints[coSignerKey(tenantID, identityID)]
	if !ok {
		return nil, nil, ErrNoWorkloadCoSigner
	}
	address := strings.TrimSpace(e.Address)
	var conn *grpc.ClientConn
	var err error
	switch {
	case strings.HasPrefix(address, "unix:"):
		// An owner-only local socket: the agent admits only the configured uid,
		// so transport authentication is the kernel's, not TLS.
		conn, err = grpc.NewClient("unix://"+strings.TrimPrefix(address, "unix:"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		creds, credsErr := mtls.SignerClientCredentials(mtls.SignerPeerConfig{
			CertFile: e.TLSCertFile, KeyFile: e.TLSKeyFile, PeerCAFile: e.PeerCAFile, PeerPinHex: e.PeerPinHex,
		}, e.ServerName)
		if credsErr != nil {
			return nil, nil, fmt.Errorf("pcas succession: workload co-signer %s: %w", identityID, credsErr)
		}
		conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("pcas succession: dial workload co-signer %s: %w", identityID, err)
	}
	return agent.NewRemoteCoSigner(conn).WithContext(ctx), func() { _ = conn.Close() }, nil
}
