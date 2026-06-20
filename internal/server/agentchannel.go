package server

// Served agent ↔ control-plane steady-state channel (WIRE-004 / OPS-005).
//
// This is the served half of the agent mTLS gRPC channel the audit found
// library-only: a real gRPC listener on the control plane (default :9443) that an
// enrolled agent connects to over mutual TLS to (a) heartbeat its inventory/status
// and (b) renew its own client certificate before expiry. It complements the
// bootstrap path (POST /enroll/bootstrap mints the agent's first cert): bootstrap
// gets the agent online; this channel keeps it online.
//
// Every non-negotiable is honored here, not by deployment topology:
//
//   - AN-1 (tenancy): the tenant is derived from the agent's VERIFIED client
//     certificate SPIFFE SAN (mtls.PeerCertInfoFromTLS), never a request field. The
//     heartbeat upserts the agent under that tenant's RLS; the renewal binds the new
//     certificate to the SAME tenant the presented certificate carries.
//   - AN-2 (event-sourced): a heartbeat emits agent.heartbeat and a renewal emits
//     agent.cert.renewed, so both are recorded on the append-only log; the agents read
//     model is projected from those events.
//   - AN-3/AN-4 (crypto boundary / isolated signer): the renewal CSR is signed by the
//     AGENT CA key held INSIDE the out-of-process signer, through internal/crypto. The
//     control plane never holds the agent CA private key.
//   - AN-5 (idempotency): a renewal runs under the orchestrator idempotency cache keyed
//     by the agent + presented serial, so a retried renewal returns the original chain
//     rather than minting a second certificate.
//
// The agent CA is custodied in the signer under a stable handle, so an agent's
// pinned CA survives a control-plane restart (the AN-4 deviation the audit called
// out — "agent CA regenerated per boot" — is closed).

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// agentCAHandle is the stable signer handle for the AGENT CA key (distinct from the
// issuing CA). A fixed handle lets a restarted, persistent signer hand back the same
// agent CA key — so an agent's pinned CA does not change across a control-plane
// restart (WIRE-004; the AN-4 deviation the audit flagged).
const agentCAHandle = "agent-ca"

// agentClientCertTTL bounds a renewed agent client certificate. It matches the
// bootstrap path's ClientCertTTL (24h) so the agent rotates on the same short cadence
// whether it (re)bootstrapped or renewed over the channel.
const agentClientCertTTL = mtls.ClientCertTTL

// agentServerCertTTL bounds the control plane's own agent-channel server certificate.
// It is reissued on each boot from the stable agent CA, so the agent — which pins the
// agent CA, not this leaf — keeps trusting the channel across restarts.
const agentServerCertTTL = 24 * time.Hour

// agentMaxConcurrentStreams bounds in-flight RPCs on a single agent-channel
// connection. The subsystem pool below is the primary AN-7 control; this transport
// cap prevents one TCP connection from becoming an unbounded stream fan-out.
const agentMaxConcurrentStreams uint32 = 256

type agentChannelService interface {
	transport.AgentServiceServer
}

// provisionAgentCA establishes the AGENT CA whose key lives inside the signer (AN-4),
// stable across restarts (WIRE-004). Like the issuing CA: if a persisted agent-CA cert
// exists AND the signer still holds the key, both are reused; otherwise it generates
// the key under the fixed handle (bound to PurposeCASign so the signer refuses to use
// it for anything else), self-signs, and persists the cert. It is a no-op returning
// (nil, nil) when no signer is available — the agent channel then simply does not serve.
func (s *Server) provisionAgentCA(ctx context.Context, c *signing.Client, certFile string) error {
	if c == nil {
		return nil
	}
	// Reuse path: persisted cert + a signer that still holds the agent CA key.
	if certFile != "" {
		if pemBytes, err := os.ReadFile(certFile); err == nil { //nolint:gosec // operator-configured CA path
			if blk, _ := pem.Decode(pemBytes); blk != nil && blk.Type == "CERTIFICATE" {
				if remote, herr := s.signerForPrivilegedHandle(ctx, c, agentCAHandle, signing.PurposeCASign); herr == nil {
					s.agentCASigner = remote
					s.agentCACertDER = blk.Bytes
					return nil
				}
			}
		}
	}
	// Fresh path: generate the agent CA key under the fixed handle (CA-signing only),
	// self-sign, and persist.
	remote, err := s.generatePrivilegedKeyHandle(ctx, c, crypto.ECDSAP256, agentCAHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if err != nil {
		return err
	}
	caDER, err := crypto.SelfSignedCACert(remote, "trstctl Agent CA", 90*24*time.Hour)
	if err != nil {
		return err
	}
	s.agentCASigner = remote
	s.agentCACertDER = caDER
	if certFile != "" {
		if err := writeCertPEM(certFile, caDER); err != nil {
			return fmt.Errorf("persist agent CA cert: %w", err)
		}
	}
	return nil
}

// agentCAIssuer adapts the signer-custodied agent CA to enroll.CAIssuer, so the served
// bootstrap-enrollment path signs agents' CSRs through the SAME agent CA the
// steady-state channel trusts (WIRE-004) — through the signer (AN-3/AN-4), tenant-
// attributed via the SPIFFE SAN (WIRE-003/AN-1). The CA private key never enters the
// control plane; only digests cross to the signer. This is what makes an agent's
// bootstrap certificate accepted on the channel and stable across a control-plane
// restart (the in-process per-boot CA the audit flagged is replaced when the channel
// is enabled).
type agentCAIssuer struct {
	caSigner  crypto.DigestSigner
	caCertDER []byte
}

func (i agentCAIssuer) SignClientCSRWithTenant(csrDER []byte, tenantID string, ttl time.Duration) ([]byte, error) {
	spiffeURI := mtls.AgentSPIFFEID(tenantID, "")
	cn, err := mtls.CSRCommonName(csrDER)
	if err == nil && cn != "" {
		spiffeURI = mtls.AgentSPIFFEID(tenantID, cn)
	}
	return crypto.SignAgentClientCSR(i.caCertDER, i.caSigner, csrDER, spiffeURI, ttl)
}

func (i agentCAIssuer) BundlePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.caCertDER})
}

// AgentCACertPEM returns the agent CA certificate (PEM) an agent pins/trusts to
// verify the control-plane agent channel and that anchors issued agent client certs,
// or nil when the agent channel is not provisioned.
func (s *Server) AgentCACertPEM() []byte {
	if s.agentCACertDER == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.agentCACertDER})
}

// AgentChannelServed reports whether the agent steady-state gRPC channel is built and
// ready to serve (an agent CA is custodied in the signer). RunAgentChannel is a no-op
// otherwise. Exposed for the acceptance test + the ops-surface wiring assertion.
func (s *Server) AgentChannelServed() bool {
	return s.agentCASigner != nil && len(s.agentCACertDER) > 0 && s.agentSvc != nil
}

// OutOfProcessAgentCA reports whether the agent CA key is held by the out-of-process
// signer (a *signing.RemoteSigner) rather than in-process — the AN-4 assertion for the
// agent CA, mirroring OutOfProcessSigning for the issuing CA.
func (s *Server) OutOfProcessAgentCA() bool {
	_, remote := s.agentCASigner.(*signing.RemoteSigner)
	return s.agentCASigner != nil && remote
}

// agentService implements the served agent steady-state RPCs
// (transport.AgentServiceServer). It holds no private key; the renewal signs through
// the signer-held agent CA. All access is tenant-scoped by the agent's verified
// certificate (AN-1).
type agentService struct {
	store        *store.Store
	log          *events.Log
	idem         idempotentRunner
	caSigner     crypto.DigestSigner
	caCertDER    []byte
	beatInterval time.Duration
	metrics      *agentChannelMetrics
}

// bulkheadedAgentService is the served AN-7 guard for the agent steady-state gRPC
// channel. The wrapped service does the tenant-scoped database, event-log, projection,
// idempotency, and signer work; this wrapper is the fire door in front of that work so
// a fleet heartbeat or renewal wave cannot consume unrelated API/protocol/outbox
// capacity.
type bulkheadedAgentService struct {
	next    agentChannelService
	pool    *bulkhead.Pool
	metrics *agentChannelMetrics
}

func newBulkheadedAgentService(next agentChannelService, pool *bulkhead.Pool, metrics *agentChannelMetrics) (agentChannelService, error) {
	if next == nil {
		return nil, errors.New("server: agent channel service is nil")
	}
	if pool == nil {
		return nil, errors.New("server: agent channel enabled but agent bulkhead is not configured")
	}
	return &bulkheadedAgentService{next: next, pool: pool, metrics: metrics}, nil
}

func (b *bulkheadedAgentService) Heartbeat(ctx context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "heartbeat", b.metrics, func(ctx context.Context) (*transport.HeartbeatResponse, error) {
		return b.next.Heartbeat(ctx, req)
	})
}

func (b *bulkheadedAgentService) Renew(ctx context.Context, req *transport.RenewRequest) (*transport.RenewResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "renew", b.metrics, func(ctx context.Context) (*transport.RenewResponse, error) {
		return b.next.Renew(ctx, req)
	})
}

func runAgentBulkhead[T any](ctx context.Context, pool *bulkhead.Pool, method string, metrics *agentChannelMetrics, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if pool == nil {
		return zero, status.Error(codes.Unavailable, "agent subsystem bulkhead is not configured")
	}
	done := make(chan struct{})
	var out T
	var err error
	submitErr := pool.Submit(func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				err = status.Errorf(codes.Internal, "agent %s panicked: %v", method, r)
			}
		}()
		out, err = fn(ctx)
	})
	if submitErr != nil {
		metrics.observeBulkheadRejection(method)
		return zero, agentBulkheadError(ctx, method, submitErr)
	}
	select {
	case <-done:
		return out, err
	case <-ctx.Done():
		return zero, status.FromContextError(ctx.Err()).Err()
	}
}

func agentBulkheadError(ctx context.Context, method string, err error) error {
	var rej *bulkhead.Rejected
	if errors.As(err, &rej) {
		if rej.Retryable() {
			_ = grpc.SetHeader(ctx, metadata.Pairs("retry-after", "1"))
			return status.Errorf(codes.ResourceExhausted,
				"agent %s overloaded: %s; retry after 1s", method, rej.Reason)
		}
		return status.Errorf(codes.Unavailable, "agent %s unavailable: %s", method, rej.Reason)
	}
	return status.Errorf(codes.Unavailable, "agent %s unavailable: %v", method, err)
}

// idempotentRunner is the subset of *orchestrator.Idempotency the agent renewal uses
// (a retry of the same renewal returns the original result — AN-5). Declared as an
// interface so the channel test can drive it without the full orchestrator when it
// wants, while the served path passes the real *orchestrator.Idempotency.
type idempotentRunner interface {
	Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error)
}

// peerInfo extracts the agent's verified certificate identity from the gRPC peer in
// ctx. It fails closed (Unauthenticated) when there is no verified mTLS peer or it
// carries no tenant SPIFFE SAN — so neither RPC can run without a tenant-attributed
// agent identity (AN-1). The tenant is the certificate's, never a request field.
func peerInfo(ctx context.Context) (mtls.PeerCertInfo, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return mtls.PeerCertInfo{}, status.Error(codes.Unauthenticated, "agent channel requires mutual TLS")
	}
	info, err := mtls.PeerCertInfoFromAuthInfo(p.AuthInfo)
	if err != nil {
		return mtls.PeerCertInfo{}, status.Errorf(codes.Unauthenticated, "agent certificate not tenant-attributed: %v", err)
	}
	return info, nil
}

// Heartbeat records the agent's inventory/status under its certificate-derived tenant
// (AN-1), emits an agent.heartbeat event (AN-2), projects that event into the agents
// read model, and returns the next-beat hint.
func (a *agentService) Heartbeat(ctx context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	resp, err := a.heartbeat(ctx, req)
	if err != nil {
		a.metrics.observeHeartbeat("failed")
		return nil, err
	}
	a.metrics.observeHeartbeat("success")
	return resp, nil
}

func (a *agentService) heartbeat(ctx context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	info, err := peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	// The agent id/name is the certificate's common name — the attacker-proof
	// identity — not the request's AgentID (which is advisory/observability only).
	name := info.CommonName
	status_ := req.Status
	if status_ == "" {
		status_ = "active"
	}
	if a.log == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent event log is not configured")
	}
	payload, err := json.Marshal(projections.AgentHeartbeat{
		ID: agentRowID(info.TenantID, name), Agent: name, Version: req.Version, Status: status_, CertSerial: info.Serial,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode agent heartbeat event: %v", err)
	}
	ev, err := a.log.Append(ctx, events.Event{Type: projections.EventAgentHeartbeat, TenantID: info.TenantID, Data: payload})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "record agent heartbeat event: %v", err)
	}
	if err := projections.New(a.store).Apply(ctx, ev); err != nil {
		return nil, status.Errorf(codes.Internal, "project agent heartbeat: %v", err)
	}
	beat := a.beatInterval
	if beat <= 0 {
		beat = 30 * time.Second
	}
	return &transport.HeartbeatResponse{
		TenantID:             info.TenantID,
		NextHeartbeatSeconds: int64(beat / time.Second),
	}, nil
}

// Renew signs the agent's rotation CSR into a fresh client certificate bound to the
// SAME tenant the presented certificate carries (AN-1) — through the AGENT CA key in
// the isolated signer (AN-3/AN-4). It is idempotent on (agent, presented serial): a
// retried renewal returns the original chain (AN-5). It emits agent.cert.renewed
// (AN-2). The agent's private key never reaches the control plane; only its CSR does.
func (a *agentService) Renew(ctx context.Context, req *transport.RenewRequest) (*transport.RenewResponse, error) {
	info, err := peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.CSRDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "renewal requires a CSR")
	}
	if a.caSigner == nil || len(a.caCertDER) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "agent CA is not provisioned")
	}
	if a.log == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent event log is not configured")
	}
	// The renewed certificate is attributed to the certificate's tenant via the
	// SPIFFE SAN — built from info.TenantID (the verified cert), never the CSR.
	spiffeURI := mtls.AgentSPIFFEID(info.TenantID, info.CommonName)
	// AN-5: dedupe on the agent + the serial it presented. A retried Renew over the
	// same current cert returns the original new chain rather than minting again.
	key := "agent-renew:" + info.CommonName + ":" + info.Serial
	out, err := a.idem.Do(ctx, info.TenantID, key, func(ctx context.Context) ([]byte, error) {
		chainPEM, serr := crypto.SignAgentClientCSR(a.caCertDER, a.caSigner, req.CSRDER, spiffeURI, agentClientCertTTL)
		if serr != nil {
			return nil, serr
		}
		// AN-2: record the renewal as an event (no key material — only the public
		// identity + serial). The read model can project agent cert state from it.
		if a.log != nil {
			serial := ""
			if leafDER, derr := mtls.FirstCertDER(chainPEM); derr == nil {
				if rs, rerr := mtls.CertSerialHex(leafDER); rerr == nil {
					serial = rs
				}
			}
			payload, perr := json.Marshal(projections.AgentCertRenewed{
				ID: agentRowID(info.TenantID, info.CommonName), Agent: info.CommonName, OldSerial: info.Serial, NewSerial: serial,
			})
			if perr != nil {
				return nil, perr
			}
			ev, aerr := a.log.Append(ctx, events.Event{Type: projections.EventAgentCertRenewed, TenantID: info.TenantID, Data: payload})
			if aerr != nil {
				return nil, aerr
			}
			if perr := projections.New(a.store).Apply(ctx, ev); perr != nil {
				return nil, perr
			}
		}
		return chainPEM, nil
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "renew agent certificate: %v", err)
	}
	naUnix, _ := mtls.CertNotAfterUnix(out)
	return &transport.RenewResponse{CertChainPEM: out, NotAfterUnix: naUnix}, nil
}

// agentChannelServerCreds mints the agent-channel server's mTLS credentials: it
// generates a LOCAL server key (never a CA key — AN-4), has the AGENT CA (whose key is
// in the signer) sign its CSR into a server certificate over the crypto boundary
// (AN-3), and assembles gRPC server credentials that REQUIRE + VERIFY the agent's
// client certificate against the agent CA. The agent CA private key never enters this
// path; only digests cross to the signer.
func (s *Server) agentChannelServerCreds(hosts []string) (credentials.TransportCredentials, error) {
	key, err := mtls.NewLocalServerKey()
	if err != nil {
		return nil, err
	}
	cn := "trstctl-agent-channel"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	csrDER, err := key.CSR(cn, dnsHostsOnly(hosts))
	if err != nil {
		return nil, err
	}
	chainPEM, err := crypto.SignServerCertFromCSR(s.agentCACertDER, s.agentCASigner, csrDER, hosts, agentServerCertTTL)
	if err != nil {
		return nil, err
	}
	return key.Credentials(chainPEM, s.AgentCACertPEM())
}

// agentChannelHosts are the SANs the agent-channel server certificate covers. They are
// the service DNS names the agent uses for --server-name, plus loopback so the
// acceptance test (and a co-located agent) can verify a localhost connection.
func (s *Server) agentChannelHosts() []string {
	hosts := []string{"localhost", "127.0.0.1"}
	if h := s.agentChannelServerName; h != "" {
		hosts = append([]string{h}, hosts...)
	}
	return hosts
}

// RunAgentChannel serves the agent steady-state gRPC channel (heartbeat + renewal)
// over mutual TLS on the configured address (default :9443) until ctx is cancelled
// (WIRE-004 / OPS-005). It is a no-op when the agent channel is not provisioned (the
// channel was disabled or no signer is available), so it is always safe to start in
// its own goroutine alongside the other Run workers — mirroring RunSPIFFE. The agent
// CA, server cert, and client verification all route through the crypto boundary
// (AN-3) and the signer (AN-4).
func (s *Server) RunAgentChannel(ctx context.Context) {
	if !s.AgentChannelServed() {
		return
	}
	ln, err := net.Listen("tcp", s.agentChannelAddr)
	if err != nil {
		s.logger.Error("agent channel listen failed", "addr", s.agentChannelAddr, "error", err.Error())
		return
	}
	s.serveAgentChannel(ctx, ln)
}

// serveAgentChannel builds the agent gRPC server (health + the heartbeat/renewal
// service) over freshly-minted mTLS credentials and serves it on ln until ctx is
// cancelled. It is the seam the acceptance test drives with its own ephemeral
// listener; RunAgentChannel wraps it with the configured listener.
func (s *Server) serveAgentChannel(ctx context.Context, ln net.Listener) {
	if !s.AgentChannelServed() {
		_ = ln.Close()
		return
	}
	creds, err := s.agentChannelServerCreds(s.agentChannelHosts())
	if err != nil {
		s.logger.Error("agent channel credentials failed", "error", err.Error())
		_ = ln.Close()
		return
	}
	srv := transport.NewServer(creds, s.agentSvc, grpc.MaxConcurrentStreams(agentMaxConcurrentStreams))
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	if serr := srv.Serve(ln); serr != nil && ctx.Err() == nil {
		s.logger.Warn("agent channel server stopped", "error", serr.Error())
	}
}

// AgentChannelAddr returns the address the agent gRPC channel listens on (default
// :9443), or "" when the channel is not served. Exposed for the ops-surface check.
func (s *Server) AgentChannelAddr() string {
	if !s.AgentChannelServed() {
		return ""
	}
	return s.agentChannelAddr
}

// dnsHostsOnly returns only the DNS (non-IP) hosts, for the CSR's dNSNames (the IPs are
// re-derived from the same host list by the signer when it stamps IPAddresses).
func dnsHostsOnly(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if net.ParseIP(h) == nil {
			out = append(out, h)
		}
	}
	return out
}

// agentNamespace is the fixed UUIDv5 namespace under which an agent's stable
// (tenant,name) identity is turned into its agents.id, so repeated heartbeats from the
// same agent upsert the same row (mirroring caNamespace for the CA id).
var agentNamespace = uuid.MustParse("b3d4e5f6-0a1b-5c2d-8e3f-4a5b6c7d8e9f")

// agentRowID derives a STABLE agents.id for an agent identified by (tenant, name), so
// repeated heartbeats from the same agent upsert the same row rather than inserting
// duplicates. It is a deterministic UUIDv5 over the tenant + name under the agent
// namespace (the same approach IssuingCAID uses for the CA id).
func agentRowID(tenantID, name string) string {
	return uuid.NewSHA1(agentNamespace, []byte(tenantID+"\x00"+name)).String()
}
