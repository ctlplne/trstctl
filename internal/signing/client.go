// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"sync/atomic"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Client is a control-plane client of the signing service over a Unix domain
// socket. UDS is a local channel, so transport security is the socket's
// filesystem permissions plus SO_PEERCRED peer authentication (see peer.go),
// not TLS.
type Client struct {
	conn      *grpc.ClientConn
	svc       signerpb.SignerServiceClient
	admission atomic.Value // admissionHook; scoped to this signer connection
}

// signerCallTimeoutNanos bounds every signer RPC that arrives without a
// tighter caller deadline, so a hung or partitioned signer yields a bounded
// structured failure instead of a stuck issuance (OPS-TIMEOUTS-001). The
// server assembly may override it once from validated configuration.
var signerCallTimeoutNanos atomic.Int64

const (
	defaultSignerCallTimeout = 10 * time.Second
	minSignerCallTimeout     = 50 * time.Millisecond
	maxSignerCallTimeout     = 2 * time.Minute
)

// SignerCallTimeout returns the active per-call signer deadline.
func SignerCallTimeout() time.Duration {
	if v := signerCallTimeoutNanos.Load(); v != 0 {
		return time.Duration(v)
	}
	return defaultSignerCallTimeout
}

// SetSignerCallTimeout configures the per-call signer deadline from validated
// operator configuration; out-of-bounds values fail closed to the previous.
func SetSignerCallTimeout(d time.Duration) error {
	if d < minSignerCallTimeout || d > maxSignerCallTimeout {
		return fmt.Errorf("signing: per-call timeout %v outside [%v, %v]", d, minSignerCallTimeout, maxSignerCallTimeout)
	}
	signerCallTimeoutNanos.Store(int64(d))
	return nil
}

// perCallDeadline is a unary interceptor that guarantees every signer RPC has
// a deadline no looser than SignerCallTimeout.
func perCallDeadline(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	limit := SignerCallTimeout()
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > limit {
		bounded, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		ctx = bounded
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

// SetAdmission installs the admission hook every RPC on this signer connection
// passes through. It is deliberately per-client: a process-global hook lets one
// assembled server overwrite another and leaves unrelated clients bound to a
// closed pool after shutdown. Passing nil restores direct admission.
func (c *Client) SetAdmission(admit func(call func() error) error) {
	if c != nil {
		c.admission.Store(admissionHook{admit: admit})
	}
}

// AdmissionInstalled reports whether this connection is bound to an admission
// hook. Assembly tests use it to prove bulkheads.signing binds real RPC work
// without relying on process-global state (AUD-6).
func (c *Client) AdmissionInstalled() bool {
	if c == nil {
		return false
	}
	hook, _ := c.admission.Load().(admissionHook)
	return hook.admit != nil
}

// admissionHook wraps the hook so atomic.Value tolerates a nil function (a bare
// nil func cannot be Stored and a typed nil would not round-trip cleanly).
type admissionHook struct {
	admit func(call func() error) error
}

// admissionGate is a unary interceptor that routes this client's signer RPCs
// through its installed admission hook. A saturated pool rejects fast with a
// structured error before the RPC is attempted — backpressure, not queue-and-hope.
func (c *Client) admissionGate(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	hook, _ := c.admission.Load().(admissionHook)
	if hook.admit == nil {
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	return hook.admit(func() error {
		return invoker(ctx, method, req, reply, cc, opts...)
	})
}

// Dial connects to the signing service listening at socketPath.
func Dial(socketPath string) (*Client, error) {
	client := &Client{}
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(perCallDeadline, client.admissionGate),
	)
	if err != nil {
		return nil, fmt.Errorf("dial signer: %w", err)
	}
	client.conn = conn
	client.svc = signerpb.NewSignerServiceClient(conn)
	return client, nil
}

// DialMTLS connects to an isolated signer over the cross-node mTLS channel
// (SIGNER-005 / design §3, §5.2): the control plane presents its own client
// certificate (tlsCfg.Cert), verifies the signer against tlsCfg.PeerCA, and PINS
// the signer's key (tlsCfg.PeerPin) — a signer that does not present exactly that
// key, or whose certificate does not chain to PeerCA, is rejected at the TLS
// handshake. serverName is the signer certificate's expected SAN. The channel is
// TLS 1.3, AEAD-only; this is the cross-host alternative to the local UDS Dial.
// addr is host:port. Fails closed on any missing/invalid material.
func DialMTLS(addr string, tlsCfg mtls.SignerPeerConfig, serverName string) (*Client, error) {
	creds, err := mtls.SignerClientCredentials(tlsCfg, serverName)
	if err != nil {
		return nil, fmt.Errorf("signer mTLS credentials: %w", err)
	}
	client := &Client{}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithChainUnaryInterceptor(perCallDeadline, client.admissionGate))
	if err != nil {
		return nil, fmt.Errorf("dial signer over mTLS: %w", err)
	}
	client.conn = conn
	client.svc = signerpb.NewSignerServiceClient(conn)
	return client, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// MintSuccessor asks the isolated signer to mint a dual-signed PCAS succession
// record over the authenticated transport (INT-01). The request carries no private
// key material (the predecessor is a handle); the response carries only the
// successor public key and the opaque encoded record. This method makes *Client a
// remote succession minter: it satisfies the control-plane orchestrator's Minter
// interface, so the control-plane process requests successions without ever
// constructing a key backend or holding key material (claims 1/12/49).
func (c *Client) MintSuccessor(ctx context.Context, req MintRequest) (MintResult, error) {
	resp, err := c.svc.MintSuccessor(ctx, mintRequestToProto(req))
	if err != nil {
		return MintResult{}, err
	}
	return mintResultFromProto(resp), nil
}

// GatedIssue asks the isolated signer to drive a gated agent-credential issuance over the
// authenticated transport (AGID-INT-WIRE). The request carries no private key material --
// the delegation chain / attestation / agent-stack representation are opaque bytes the
// signer's attached issuance gate re-verifies BEFORE any key op (INV-A1); alg is the
// agent-key algorithm to generate INSIDE the signer on approval. The response carries only
// public material: the approval flag, the signed refusal on a refusal, and, on approval,
// the opaque binding material + the issued credential public key + the opaque encoded
// record. This method makes *Client a remote issuance driver: the control-plane process
// requests a chain-bound issuance without ever obtaining private key material -- it can
// request, but cannot forge.
func (c *Client) GatedIssue(ctx context.Context, req IssuancePreconditions, alg crypto.Algorithm) (IssuanceDecision, error) {
	resp, err := c.svc.GatedIssue(ctx, gatedIssueRequestToProto(req, alg))
	if err != nil {
		return IssuanceDecision{}, err
	}
	return issuanceDecisionFromProto(resp), nil
}

// SignArtifact asks the isolated signer to sign an opaque artifact through its
// attached artifact signer. The request carries no private key material; the
// response carries only the public key, algorithm, and signature.
func (c *Client) SignArtifact(ctx context.Context, req ArtifactSignRequest) (ArtifactSignature, error) {
	resp, err := c.svc.SignArtifact(ctx, artifactSignRequestToProto(req))
	if err != nil {
		return ArtifactSignature{}, err
	}
	return artifactSignatureFromProto(resp)
}

// VerifyOperation asks the isolated signer to verify an opaque public operation
// through its attached operation gate. No private key material crosses the
// transport.
func (c *Client) VerifyOperation(ctx context.Context, req OperationRequest) (OperationDecision, error) {
	resp, err := c.svc.VerifyOperation(ctx, operationRequestToProto(req))
	if err != nil {
		return OperationDecision{}, err
	}
	return operationDecisionFromProto(resp), nil
}

// GatedDestroy asks the isolated signer to verify generic public destruction
// evidence inside the signer and destroy the signer-held handle only after the
// attached gate approves. No private key material crosses the transport.
func (c *Client) GatedDestroy(ctx context.Context, req GatedDestroyRequest) (GatedDestroyDecision, error) {
	resp, err := c.svc.GatedDestroy(ctx, gatedDestroyRequestToProto(req))
	if err != nil {
		return GatedDestroyDecision{}, err
	}
	return gatedDestroyDecisionFromProto(resp), nil
}

// DialReady connects to a signer at socketPath and waits up to timeout for it to
// report SERVING. The control plane uses it to attach to an externally deployed
// signer (R3.2 external mode), rather than supervising a child.
func DialReady(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	return dialReady(ctx, socketPath, timeout)
}

// DialReadyMTLS dials an isolated signer over mTLS (DialMTLS) and waits up to
// timeout for it to report SERVING. It is the cross-node analogue of DialReady:
// the control plane attaches to a separately-hosted signer pod over the
// authenticated, mutually-pinned network channel (SIGNER-005). On timeout (or a
// rejected handshake surfaced by a failing Health) it closes the connection and
// returns an error, so the served binary fails closed when the signer is absent
// or untrusted.
func DialReadyMTLS(ctx context.Context, addr string, tlsCfg mtls.SignerPeerConfig, serverName string, timeout time.Duration) (*Client, error) {
	client, err := DialMTLS(addr, tlsCfg, serverName)
	if err != nil {
		return nil, err
	}
	return waitReady(ctx, client, timeout)
}

// StaticProvider adapts a fixed Client to the control plane's signer-provider
// interface (external-signer mode: the signer is a separately deployed service,
// not a supervised child).
type StaticProvider struct{ C *Client }

// Client returns the wrapped client.
func (p StaticProvider) Client() *Client { return p.C }

// SetAdmission binds this provider's fixed connection to one control-plane
// bulkhead. It mirrors Supervisor.SetAdmission for external-signer mode.
func (p StaticProvider) SetAdmission(admit func(call func() error) error) {
	if p.C != nil {
		p.C.SetAdmission(admit)
	}
}

// Healthy reports whether the signer answers Health with SERVING.
func (c *Client) Healthy(ctx context.Context) bool {
	resp, err := c.svc.Health(ctx, &signerpb.HealthRequest{})
	return err == nil && resp.GetStatus() == signerpb.HealthResponse_STATUS_SERVING
}

// KeyPurpose is the signer-enforceable usage class for a key (SIGNER-002/003),
// re-exported so the control plane can constrain a key at creation and assert a
// purpose when signing without importing the generated proto package.
type KeyPurpose = signerpb.KeyPurpose

// Re-exported KeyPurpose values.
const (
	PurposeUnspecified   = signerpb.KeyPurpose_KEY_PURPOSE_UNSPECIFIED
	PurposeCASign        = signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN
	PurposeLeafTLS       = signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS
	PurposeSSHCert       = signerpb.KeyPurpose_KEY_PURPOSE_SSH_CERT
	PurposeCodeSign      = signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN
	PurposeGeneric       = signerpb.KeyPurpose_KEY_PURPOSE_GENERIC
	PurposeACMEAccount   = signerpb.KeyPurpose_KEY_PURPOSE_ACME_ACCOUNT
	PurposeAuditEvidence = signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE
)

// SignTokenProvider mints the per-request authorization token for a
// dual-control signer handle. In production this should be backed by an
// independent approval authority; tests may use *crypto.SignAuthorizer directly.
type SignTokenProvider interface {
	Authorize(crypto.SignIntent) ([]byte, error)
}

// GenerateKey asks the signer to create an unconstrained key and returns a
// RemoteSigner that signs through it. The private key never leaves the signer.
// Used for ephemeral/test keys; for a purpose-bound key (e.g. the issuing CA)
// use GenerateConstrainedKeyHandle.
func (c *Client) GenerateKey(ctx context.Context, algorithm crypto.Algorithm) (*RemoteSigner, error) {
	return c.GenerateConstrainedKeyHandle(ctx, algorithm, "", nil, PurposeGeneric)
}

// GenerateKeyHandle is GenerateKey with a caller-chosen handle and no usage
// constraints. A stable handle lets a persistent signer hand the same key back
// after a restart, so the issuing CA is not silently rotated (R3.2).
func (c *Client) GenerateKeyHandle(ctx context.Context, algorithm crypto.Algorithm, handle string) (*RemoteSigner, error) {
	return c.GenerateConstrainedKeyHandle(ctx, algorithm, handle, nil, PurposeGeneric)
}

// GenerateConstrainedKeyHandle creates a key bound to an allowed-purpose set
// (SIGNER-002/003) under a caller-chosen handle. When allowedPurposes is
// non-empty the signer refuses any Sign whose asserted purpose is outside the
// set; declaredPurpose is the purpose the returned RemoteSigner asserts on every
// Sign (it must be a member of allowedPurposes when the set is non-empty). An
// empty allowedPurposes creates an unconstrained key (back-compat).
func (c *Client) GenerateConstrainedKeyHandle(ctx context.Context, algorithm crypto.Algorithm, handle string, allowedPurposes []KeyPurpose, declaredPurpose KeyPurpose) (*RemoteSigner, error) {
	resp, err := c.svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       algorithmToProto(algorithm),
		RequestedId:     handle,
		AllowedPurposes: allowedPurposes,
	})
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{
		client:    c,
		handle:    resp.GetHandle(),
		algorithm: algorithm,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: resp.GetPublicKey()},
		purpose:   declaredPurpose,
	}, nil
}

// GenerateLicensedKeyHandle creates a key for a proprietary algorithm whose
// concrete name is owned by an EE package. The caller supplies the neutral
// signer-protocol slot and the algorithm label to bind onto the returned remote
// signer; core callers should use GenerateConstrainedKeyHandle instead.
func (c *Client) GenerateLicensedKeyHandle(ctx context.Context, protoAlg signerpb.Algorithm, algorithm crypto.Algorithm, handle string, allowedPurposes []KeyPurpose, declaredPurpose KeyPurpose) (*RemoteSigner, error) {
	resp, err := c.svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       protoAlg,
		RequestedId:     handle,
		AllowedPurposes: allowedPurposes,
	})
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{
		client:    c,
		handle:    resp.GetHandle(),
		algorithm: algorithm,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: resp.GetPublicKey()},
		purpose:   declaredPurpose,
	}, nil
}

// GenerateDualControlKeyHandle creates a DUAL-CONTROL key (RED-003): a key the
// signer refuses to use unless every Sign carries a valid authorization token over
// the exact signing tuple. It is the strongest signer-side bound for crown-jewel
// classes (CA/code-signing) — socket access plus the handle plus the right purpose
// is no longer sufficient to forge, because the on-socket caller also needs the
// out-of-band approver secret. The returned RemoteSigner carries `authorizer` (the
// Authorize side) so it can mint the per-Sign token; in a true dual-control
// deployment the Authorize secret is held by an approval authority and the
// returned signer is bound only after approval. The dual-control opt-in travels as
// GenerateKey metadata; per-Sign authorization tokens travel as SignRequest bytes.
// The signer must have been built with the matching verify-only authorizer or this
// call is refused.
func (c *Client) GenerateDualControlKeyHandle(ctx context.Context, algorithm crypto.Algorithm, handle string, allowedPurposes []KeyPurpose, declaredPurpose KeyPurpose, authorizer SignTokenProvider) (*RemoteSigner, error) {
	mdCtx := metadata.AppendToOutgoingContext(ctx, mdRequireAuth, "1")
	resp, err := c.svc.GenerateKey(mdCtx, &signerpb.GenerateKeyRequest{
		Algorithm:       algorithmToProto(algorithm),
		RequestedId:     handle,
		AllowedPurposes: allowedPurposes,
	})
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{
		client:     c,
		handle:     resp.GetHandle(),
		algorithm:  algorithm,
		public:     crypto.PublicKey{Algorithm: algorithm, DER: resp.GetPublicKey()},
		purpose:    declaredPurpose,
		authorizer: authorizer,
	}, nil
}

// SignerForDualControlHandle binds a RemoteSigner to an already-held dual-control
// key and supplies the authorizer that mints the per-Sign token. It is the restart
// / multi-replica analogue of GenerateDualControlKeyHandle: the key already exists
// (persisted, requireAuth sealed in), and the approval authority supplies the
// Authorize secret so the bound signer can produce valid tokens.
func (c *Client) SignerForDualControlHandle(ctx context.Context, handle string, declaredPurpose KeyPurpose, authorizer SignTokenProvider) (*RemoteSigner, error) {
	rs, err := c.SignerForHandleWithPurpose(ctx, handle, declaredPurpose)
	if err != nil {
		return nil, err
	}
	rs.authorizer = authorizer
	return rs, nil
}

// SignerForHandle binds a RemoteSigner to a key the signer already holds (e.g. a
// persisted CA key after a restart). It does not create a key; it errors if the
// handle is unknown. The signer asserts PurposeGeneric; use
// SignerForHandleWithPurpose for a purpose-bound persisted key.
func (c *Client) SignerForHandle(ctx context.Context, handle string) (*RemoteSigner, error) {
	return c.SignerForHandleWithPurpose(ctx, handle, PurposeGeneric)
}

// SignerForHandleWithPurpose binds a RemoteSigner to a persisted key and sets the
// purpose it asserts on every Sign. The caller knows the key's role (e.g. a
// reloaded issuing-CA key signs with PurposeCASign), so the signer's persisted
// constraint is satisfied across a restart.
func (c *Client) SignerForHandleWithPurpose(ctx context.Context, handle string, declaredPurpose KeyPurpose) (*RemoteSigner, error) {
	resp, err := c.svc.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: handle}})
	if err != nil {
		return nil, err
	}
	alg, err := algorithmFromProto(resp.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{
		client:    c,
		handle:    &signerpb.KeyHandle{Id: handle},
		algorithm: alg,
		public:    crypto.PublicKey{Algorithm: alg, DER: resp.GetPublicKey()},
		purpose:   declaredPurpose,
	}, nil
}

// RemoteSigner is a crypto.DigestSigner backed by a key held inside the signer.
// It carries the usage purpose it asserts on every Sign (SIGNER-002/003); the
// signer enforces that purpose against the key's allowed set.
type RemoteSigner struct {
	client    *Client
	handle    *signerpb.KeyHandle
	algorithm crypto.Algorithm
	public    crypto.PublicKey
	purpose   KeyPurpose
	// authorizer, when non-nil, mints the dual-control authorization token attached
	// to every Sign (RED-003). It is set only for a dual-control key; production
	// must source it from an independent approval authority, not from the digest
	// choosing control-plane process.
	authorizer SignTokenProvider
}

// Public returns the key's public key.
func (r *RemoteSigner) Public() crypto.PublicKey { return r.public }

// Algorithm reports the key's algorithm.
func (r *RemoteSigner) Algorithm() crypto.Algorithm { return r.algorithm }

// Purpose reports the usage class this signer asserts on every Sign.
func (r *RemoteSigner) Purpose() KeyPurpose { return r.purpose }

// SignDigest signs digest by calling the signer's Sign RPC over the UDS. It
// asserts the signer's bound purpose; if the key is purpose-constrained and the
// purpose is not permitted, the signer refuses with FailedPrecondition.
func (r *RemoteSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return r.signDigest("", digest, opts)
}

// SignDigestForOperation asks the persistent signer to journal the exact result
// under operationID before returning it. A redelivered durable outbox command
// therefore receives byte-identical ECDSA/RSA output; reusing operationID for a
// different tuple is rejected inside the isolated signer.
func (r *RemoteSigner) SignDigestForOperation(operationID string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if operationID == "" {
		return nil, fmt.Errorf("signing: operation id is required for durable signing")
	}
	return r.signDigest(operationID, digest, opts)
}

func (r *RemoteSigner) signDigest(operationID string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := &signerpb.SignRequest{
		Handle:      r.handle,
		Digest:      digest,
		Hash:        hashToProto(opts.Hash),
		RsaPadding:  paddingToProto(opts.RSAPadding),
		Purpose:     r.purpose,
		OperationId: operationID,
	}
	// For a dual-control key, mint and attach the authorization token over the exact
	// signing tuple as byte-native request material (RED-003). The token commits to
	// this digest, so the signer will only sign this specific object. The tuple is
	// derived from the SAME wire values the request carries (round-tripped through
	// the proto mapping) so the client's minted intent and the server's verified
	// intent are byte-equal even when opts left a field at its zero value (e.g.
	// empty RSAPadding -> PKCS1v15).
	if r.authorizer != nil {
		token, err := r.authorizer.Authorize(intentFor(req))
		if err != nil {
			return nil, fmt.Errorf("mint sign authorization: %w", err)
		}
		defer secret.Wipe(token)
		req.AuthorizationToken = token
	}
	resp, err := r.client.svc.Sign(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetSignature(), nil
}

// Destroy asks the signer to zeroize and forget the key.
func (r *RemoteSigner) Destroy(ctx context.Context) error {
	_, err := r.client.svc.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: r.handle})
	return err
}
