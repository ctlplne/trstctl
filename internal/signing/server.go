package signing

import (
	"context"
	"encoding/hex"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// heldKey is a key the signer holds: its locked private material plus the
// signer-enforceable usage constraints declared at creation (SIGNER-002/003).
type heldKey struct {
	signer      *crypto.LockedSigner
	constraints keyConstraints
}

// Server implements signerpb.SignerServiceServer. Private keys are held as
// LockedSigner values (AN-8: PKCS#8 DER in mlock'd, non-dumpable, zeroizable
// memory) in an in-memory store keyed by opaque handle. Private-key bytes never
// cross the gRPC boundary. Each key carries its usage constraints, which the
// signer enforces on every Sign (AN-7-bulkheaded at the transport).
type Server struct {
	signerpb.UnimplementedSignerServiceServer

	mu      sync.Mutex
	keys    map[string]*heldKey
	serving bool
	store   *KeyStore // optional sealed persistence; nil = in-memory only

	// authorizer, when non-nil, verifies the dual-control sign-intent attestation
	// that a DUAL-CONTROL key (keyConstraints.requireAuth) requires on every Sign
	// (RED-003). It is a VERIFY-only authorizer: the signer can check a token but
	// not mint one (minting is the approval authority's job, holding the secret the
	// signer holds too but the on-socket caller does not). nil = dual-control keys
	// cannot be created or used (the signer fails closed on them).
	authorizer *crypto.SignAuthorizer

	// signGate, when non-nil, is called inside Sign while it holds its in-flight
	// bulkhead slot. It is a test-only seam (set via export_test.go) used to make
	// the served saturation test deterministic; it is nil in production and has
	// zero effect there.
	signGate func()
}

// ServerOption configures a signing Server at construction.
type ServerOption func(*Server)

// WithAuthorizer installs the dual-control sign-intent verifier (RED-003). A
// server built with one can create and honor DUAL-CONTROL keys: keys that refuse
// every Sign unless the request carries a valid authorization token over the exact
// signing tuple. The authorizer should be VERIFY-only (the secret is shared with
// the out-of-band approval authority, never derivable from socket access). Without
// it, dual-control keys cannot be created or used and the signer fails closed on
// any it loads.
func WithAuthorizer(a *crypto.SignAuthorizer) ServerOption {
	return func(s *Server) { s.authorizer = a }
}

// NewServer returns a ready in-memory signing server (keys do not survive a
// restart).
func NewServer(opts ...ServerOption) *Server {
	s := &Server{keys: make(map[string]*heldKey), serving: true}
	for _, o := range opts {
		o(s)
	}
	return s
}

// NewPersistentServer returns a signing server backed by a sealed key store: it
// loads any persisted keys on construction (so a restart preserves the issuing CA
// rather than silently rotating it, R3.2) and seals new keys as they are
// generated. Usage constraints are sealed with the key and restored too, so a
// CA-class key stays purpose-bound across a restart.
func NewPersistentServer(store *KeyStore, opts ...ServerOption) (*Server, error) {
	keys, err := store.Load()
	if err != nil {
		return nil, err
	}
	s := &Server{keys: keys, serving: true, store: store}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// GenerateKey creates a new key inside the signer and returns its handle and
// public key. Any usage constraints on the request (allowed_purposes /
// allowed_hashes, SIGNER-002/003) are bound to the key and enforced on every
// subsequent Sign.
func (s *Server) GenerateKey(ctx context.Context, req *signerpb.GenerateKeyRequest) (*signerpb.GenerateKeyResponse, error) {
	alg, err := algorithmFromProto(req.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	constraints, err := constraintsFromGenerate(req)
	if err != nil {
		return nil, err
	}
	// Dual-control opt-in travels as metadata (the wire proto is frozen). A key may
	// only be marked dual-control if this signer has an authorizer to enforce it;
	// otherwise the key would be permanently unusable (every Sign would fail
	// closed). Refuse the request rather than mint a bricked key (RED-003).
	if requireAuthFromGenerateMD(ctx) {
		if s.authorizer == nil {
			return nil, status.Error(codes.FailedPrecondition,
				"dual-control key requested but this signer has no authorizer configured")
		}
		constraints.requireAuth = true
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}
	id := req.GetRequestedId()
	if id == "" {
		raw, err := crypto.RandomBytes(16)
		if err != nil {
			ls.Destroy()
			return nil, status.Errorf(codes.Internal, "generate handle: %v", err)
		}
		id = hex.EncodeToString(raw)
	}

	held := &heldKey{signer: ls, constraints: constraints}

	s.mu.Lock()
	if _, exists := s.keys[id]; exists {
		s.mu.Unlock()
		ls.Destroy()
		return nil, status.Error(codes.AlreadyExists, "key handle already exists")
	}
	s.keys[id] = held
	s.mu.Unlock()

	// Persist the new key sealed at rest (R3.2) so it survives a signer restart.
	// The usage constraints are sealed with the key (and bound to the handle as
	// AAD), so a CA-class key stays purpose-bound across a restart. On failure,
	// roll back the in-memory insert so state stays consistent.
	if s.store != nil {
		if err := s.store.Save(id, ls, constraints); err != nil {
			s.mu.Lock()
			delete(s.keys, id)
			s.mu.Unlock()
			ls.Destroy()
			return nil, status.Errorf(codes.Internal, "persist key: %v", err)
		}
	}

	return &signerpb.GenerateKeyResponse{
		Handle:    &signerpb.KeyHandle{Id: id},
		Algorithm: algorithmToProto(alg),
		PublicKey: ls.Public().DER,
	}, nil
}

// GetPublicKey returns the public key for a handle.
func (s *Server) GetPublicKey(_ context.Context, req *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	return &signerpb.GetPublicKeyResponse{
		Algorithm: algorithmToProto(held.signer.Algorithm()),
		PublicKey: held.signer.Public().DER,
	}, nil
}

// Sign signs a pre-computed digest with the keyed handle. If the key was created
// with usage constraints (SIGNER-002/003), the request's asserted purpose and
// hash must satisfy them or the signature is refused with FAILED_PRECONDITION —
// so socket access alone cannot coerce a key into signing outside its mandate. If
// the key is dual-control (RED-003), the request must additionally carry a valid
// authorization token (in metadata) over the exact signing tuple, or the signature
// is refused with PERMISSION_DENIED — so socket access cannot coerce a crown-jewel
// key into signing arbitrary, un-attested bytes.
func (s *Server) Sign(ctx context.Context, req *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	if err := held.constraints.check(req); err != nil {
		return nil, err
	}
	// Dual-control gate (RED-003): a key marked requireAuth refuses every Sign that
	// does not carry a valid authorization token over the exact signing tuple, so
	// socket access alone cannot coerce a crown-jewel key into signing arbitrary
	// bytes. Enforced AFTER the purpose/hash constraints (both must pass).
	if held.constraints.requireAuth {
		if err := s.enforceDualControl(ctx, req); err != nil {
			return nil, err
		}
	}
	if s.signGate != nil {
		s.signGate() // test-only: hold the in-flight slot (nil in production)
	}
	hash, _, _ := hashFromProto(req.GetHash()) // validated above
	sig, err := held.signer.SignDigest(req.GetDigest(), crypto.SignOptions{
		Hash:       hash,
		RSAPadding: paddingFromProto(req.GetRsaPadding()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &signerpb.SignResponse{Signature: sig}, nil
}

// DestroyKey zeroizes and forgets a handle. It is idempotent.
func (s *Server) DestroyKey(_ context.Context, req *signerpb.DestroyKeyRequest) (*signerpb.DestroyKeyResponse, error) {
	h := req.GetHandle()
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	held, ok := s.keys[h.GetId()]
	if ok {
		delete(s.keys, h.GetId())
	}
	s.mu.Unlock()
	if ok {
		held.signer.Destroy()
		if s.store != nil {
			if err := s.store.Remove(h.GetId()); err != nil {
				return nil, status.Errorf(codes.Internal, "remove persisted key: %v", err)
			}
		}
	}
	return &signerpb.DestroyKeyResponse{}, nil
}

// Health reports whether the server is serving or draining.
func (s *Server) Health(_ context.Context, _ *signerpb.HealthRequest) (*signerpb.HealthResponse, error) {
	s.mu.Lock()
	serving := s.serving
	s.mu.Unlock()
	st := signerpb.HealthResponse_STATUS_SERVING
	if !serving {
		st = signerpb.HealthResponse_STATUS_DRAINING
	}
	return &signerpb.HealthResponse{Status: st}, nil
}

// Shutdown marks the server draining and zeroizes every key it holds.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serving = false
	for id, held := range s.keys {
		held.signer.Destroy()
		delete(s.keys, id)
	}
}

func (s *Server) lookup(h *signerpb.KeyHandle) (*heldKey, error) {
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.keys[h.GetId()]; ok {
		return held, nil
	}
	// Reload-on-miss from a (possibly SHARED) sealed keystore (RESIL-002): on a
	// multi-replica HA deployment the control planes share a signer key store, and the
	// issuing-CA key is generated by whichever replica wins the first-boot provisioning
	// lock. A signer that started before that key was sealed would not have it in its
	// in-memory map; rather than report the handle missing, it loads it from the store
	// once and caches it. This keeps AN-4 intact (no new surface — the signer already
	// owns this store) and lets every replica's sidecar signer converge on the same CA
	// key without restarting. A signer with no persistent store (in-memory) skips this.
	if s.store != nil {
		if held, err := s.store.LoadHandle(h.GetId()); err != nil {
			return nil, status.Errorf(codes.Internal, "reload key handle: %v", err)
		} else if held != nil {
			s.keys[h.GetId()] = held
			return held, nil
		}
	}
	return nil, status.Error(codes.NotFound, "unknown key handle")
}
