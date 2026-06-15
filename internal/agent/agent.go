// Package agent is the trustctl in-network agent core (F3 base, F15, sprint S5.1):
// it registers with the control plane (one-time bootstrap token or, later,
// attestation), generates its key locally and submits only a CSR so the private
// key never leaves the host, talks mutual TLS with a short-lived client
// certificate that it rotates before expiry, and persists its identity so it
// survives a control-plane restart without re-bootstrapping.
//
// All cryptography routes through the internal/crypto/mtls boundary (AN-3); this
// package orchestrates and holds only opaque identities and credentials.
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"trustctl.io/trustctl/internal/crypto/mtls"
)

// Enroller is the control-plane enrollment transport: it signs an agent's CSR
// into a client-certificate chain (PEM), either against a one-time bootstrap
// token or — for rotation — against the agent's existing mTLS identity.
type Enroller interface {
	EnrollBootstrap(ctx context.Context, token string, csrDER []byte) (certChainPEM []byte, err error)
	EnrollRenewal(ctx context.Context, csrDER []byte) (certChainPEM []byte, err error)
}

// Config configures an agent.
type Config struct {
	CommonName     string // the agent's identity (client-cert subject)
	BootstrapToken string // one-time token for initial registration
	KeyPath        string // where the local private key is persisted (0600)
	CertPath       string // where the issued certificate chain is persisted
	ServerName     string // expected control-plane server name (TLS)
	ServerCAPEM    []byte // CA bundle (PEM) trusted to verify the control plane
	RefreshBefore  time.Duration
	Version        string // agent build version reported on the steady-state heartbeat
}

// Agent is the in-network agent.
type Agent struct {
	cfg      Config
	enroller Enroller

	mu       sync.Mutex
	identity *mtls.AgentIdentity
	source   *mtls.SwappableSource
}

// New constructs an agent with the given config and enrollment transport.
func New(cfg Config, enroller Enroller) *Agent {
	return &Agent{cfg: cfg, enroller: enroller}
}

// Bootstrap brings the agent online: if a persisted identity exists it is
// reloaded (the agent resumes after a restart without re-bootstrapping);
// otherwise the agent generates a local key, submits a CSR with its bootstrap
// token, adopts the issued certificate, and persists it.
func (a *Agent) Bootstrap(ctx context.Context) error {
	if a.persistedIdentityExists() {
		identity, err := mtls.LoadAgentIdentity(a.cfg.CommonName, a.cfg.KeyPath, a.cfg.CertPath)
		if err != nil {
			return fmt.Errorf("agent: reload identity: %w", err)
		}
		a.setIdentity(identity)
		return nil
	}

	identity, err := mtls.GenerateAgentKey(a.cfg.CommonName)
	if err != nil {
		return err
	}
	csr, err := identity.CSR()
	if err != nil {
		return err
	}
	chain, err := a.enroller.EnrollBootstrap(ctx, a.cfg.BootstrapToken, csr)
	if err != nil {
		return fmt.Errorf("agent: bootstrap enrollment: %w", err)
	}
	if err := identity.UseCertificate(chain); err != nil {
		return err
	}
	if err := a.persist(identity); err != nil {
		return err
	}
	a.setIdentity(identity)
	return nil
}

// Rotate replaces the agent's certificate with a freshly-keyed one via the
// renewal endpoint and presents it on subsequent handshakes. The new private key
// is again generated locally; only its CSR is transmitted.
func (a *Agent) Rotate(ctx context.Context) error {
	identity, err := mtls.GenerateAgentKey(a.cfg.CommonName)
	if err != nil {
		return err
	}
	csr, err := identity.CSR()
	if err != nil {
		return err
	}
	chain, err := a.enroller.EnrollRenewal(ctx, csr)
	if err != nil {
		return fmt.Errorf("agent: renewal enrollment: %w", err)
	}
	if err := identity.UseCertificate(chain); err != nil {
		return err
	}
	if err := a.persist(identity); err != nil {
		return err
	}
	a.setIdentity(identity)
	return nil
}

// Credentials returns gRPC transport credentials presenting the agent's current
// (and transparently rotated) client certificate and trusting the control plane.
func (a *Agent) Credentials() (credentials.TransportCredentials, error) {
	a.mu.Lock()
	src := a.source
	a.mu.Unlock()
	if src == nil {
		return nil, errors.New("agent: not bootstrapped")
	}
	return mtls.AgentClientCredentials(src, a.cfg.ServerCAPEM, a.cfg.ServerName, nil)
}

// CertificateSerial is the current certificate's serial (hex), for observability.
func (a *Agent) CertificateSerial() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == nil {
		return ""
	}
	return a.identity.Serial()
}

// CertificatePEM is the current certificate chain (PEM), for observability and the
// channel acceptance test (it inspects the renewed leaf).
func (a *Agent) CertificatePEM() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == nil {
		return nil
	}
	return a.identity.CertificatePEM()
}

// CertificateNotAfter is the current certificate's expiry.
func (a *Agent) CertificateNotAfter() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == nil {
		return time.Time{}
	}
	return a.identity.NotAfter()
}

// ChannelClient is the subset of the agent steady-state gRPC channel the agent uses:
// heartbeat its status and renew its certificate. *transport.AgentClient satisfies it;
// it is an interface here so the agent core has no hard dependency on the transport
// package and tests can drive it directly.
type ChannelClient interface {
	Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error)
	Renew(ctx context.Context, req *RenewRequest) (*RenewResponse, error)
}

// HeartbeatRequest / Response and RenewRequest / Response mirror the transport
// contract so the agent core does not import the transport message types directly. The
// cmd wiring adapts *transport.AgentClient to ChannelClient over these.
type (
	// HeartbeatRequest is the agent's status report.
	HeartbeatRequest struct {
		AgentID    string
		Version    string
		Status     string
		CertSerial string
		Inventory  map[string]int64
	}
	// HeartbeatResponse is the control plane's acknowledgement.
	HeartbeatResponse struct {
		TenantID             string
		NextHeartbeatSeconds int64
	}
	// RenewRequest carries the agent's rotation CSR (DER).
	RenewRequest struct{ CSRDER []byte }
	// RenewResponse returns the freshly minted chain (PEM).
	RenewResponse struct {
		CertChainPEM []byte
		NotAfterUnix int64
	}
)

// Heartbeat sends one steady-state beat over the agent channel, reporting the agent's
// version and current certificate serial under its (certificate-derived) tenant. The
// control plane records the agent and returns the next-beat hint.
func (a *Agent) Heartbeat(ctx context.Context, ch ChannelClient, inventory map[string]int64) (*HeartbeatResponse, error) {
	return ch.Heartbeat(ctx, &HeartbeatRequest{
		AgentID:    a.cfg.CommonName,
		Version:    a.cfg.Version,
		Status:     "active",
		CertSerial: a.CertificateSerial(),
		Inventory:  inventory,
	})
}

// RenewOverChannel rotates the agent's certificate over the steady-state gRPC channel
// (rather than the HTTP bootstrap/renewal endpoint): it generates a fresh local key,
// submits only its CSR, adopts the issued chain, and persists it. The new private key
// never leaves the host. It is the steady-state analogue of Rotate.
func (a *Agent) RenewOverChannel(ctx context.Context, ch ChannelClient) error {
	identity, err := mtls.GenerateAgentKey(a.cfg.CommonName)
	if err != nil {
		return err
	}
	csr, err := identity.CSR()
	if err != nil {
		return err
	}
	resp, err := ch.Renew(ctx, &RenewRequest{CSRDER: csr})
	if err != nil {
		return fmt.Errorf("agent: channel renewal: %w", err)
	}
	if err := identity.UseCertificate(resp.CertChainPEM); err != nil {
		return err
	}
	if err := a.persist(identity); err != nil {
		return err
	}
	a.setIdentity(identity)
	return nil
}

func (a *Agent) setIdentity(identity *mtls.AgentIdentity) {
	a.mu.Lock()
	a.identity = identity
	if a.source == nil {
		a.source = mtls.NewSwappableSource(identity)
	} else {
		a.source.Set(identity)
	}
	a.mu.Unlock()
}

func (a *Agent) persist(identity *mtls.AgentIdentity) error {
	if a.cfg.KeyPath == "" || a.cfg.CertPath == "" {
		return nil // in-memory only
	}
	if err := identity.Save(a.cfg.KeyPath, a.cfg.CertPath); err != nil {
		return fmt.Errorf("agent: persist identity: %w", err)
	}
	return nil
}

func (a *Agent) persistedIdentityExists() bool {
	if a.cfg.KeyPath == "" || a.cfg.CertPath == "" {
		return false
	}
	if _, err := os.Stat(a.cfg.KeyPath); err != nil {
		return false
	}
	if _, err := os.Stat(a.cfg.CertPath); err != nil {
		return false
	}
	return true
}
