// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// heldKey is a key the signer holds: its locked private material plus the
// signer-enforceable usage constraints declared at creation (SIGNER-002/003).
type heldKey struct {
	signer      signerKey
	constraints keyConstraints
}

// Server implements signerpb.SignerServiceServer. Private keys are held as
// locked, zeroizable crypto.DigestSigner values in an in-memory store keyed by
// opaque handle. Private-key bytes never cross the gRPC boundary. Each key
// carries its usage constraints, which the signer enforces on every Sign
// (AN-7-bulkheaded at the transport).
type Server struct {
	signerpb.UnimplementedSignerServiceServer

	mu   sync.Mutex
	keys map[string]*heldKey
	// revocations holds the administrative key revocations of a signer without
	// a key store; a persistent signer keeps them beside the sealed keys.
	revocations      map[string]KeyRevocation
	serving          bool
	store            *KeyStore // optional sealed persistence; nil = in-memory only
	keyspec          KeyFactory
	keyImportClock   func() time.Time                // test clock for preparation and expiry
	beforeImportOpen func()                          // test observer for the HPKE open boundary
	checkImportedKey func(crypto.DigestSigner) error // test observer across the import ceremony check
	// managedKeys owns remote KMS/HSM lifecycle backends in this isolated
	// process. The control plane can reach them only through ManageKey over the
	// authenticated signer transport; provider credentials and key operations
	// therefore never enter the HTTP/control-plane address space (AN-4).
	managedKeys *managedKeyRuntime
	// readiness reports managed-key providers' workload identity exchanges
	// (A169-L2).
	readiness *managedKeyReadiness

	// minter, when non-nil, is the attached generic successor-minting extension
	// (WithSuccessionMinter). The core defines only the seam; the concrete
	// succession semantics (commitment forming, dual-signing, epoch discipline)
	// live in an edition implementation. nil = the signer mints no successions
	// (core-only build).
	minter          SuccessionMinter
	delegationStore DelegationStore

	// issuanceGate, when non-nil, is the attached generic issuance-precondition
	// extension (WithIssuanceGate). The core defines only the seam; the concrete
	// precondition semantics live in an edition implementation and are opaque to
	// core. nil = the signer gates no issuance and the gatedIssue path fails closed
	// with ErrNoIssuanceGate (core-only build). Guarded by mu, like minter.
	issuanceGate IssuanceGate
	// agentRootAnchors is the signer-local, first-writer public AGID trust floor.
	// The control plane reaches it only over the authenticated signer transport.
	agentRootAnchors      AgentRootAnchorStore
	agentReachabilityKeys AgentReachabilityKeyStore
	agentAttestors        AgentAttestorStore

	// issuanceKeyOp, when non-nil, is the attached generic after-approval issuance key op
	// (WithIssuanceKeyOp). It performs the real key operation INSIDE the boundary on an
	// APPROVED gated issuance -- generating the agent credential key here and certifying it
	// under the signer-held issuing CA -- and returns only public material (the credential
	// public key + the opaque encoded record). The core defines only the seam; the concrete
	// certify/binding semantics live in an edition implementation and are opaque to core.
	// nil = the GatedIssue RPC fails closed with UNIMPLEMENTED (core-only build). Guarded by
	// mu, like minter/issuanceGate. INV-A1 holds by construction: gatedIssue runs this ONLY
	// after the gate approved.
	issuanceKeyOp IssuanceKeyOp

	// kemCustody, when non-nil, is the attached KEM private-key custody surface for
	// PCAS re-wrap. KEM keys are deliberately separate from signing keys: Sign cannot
	// address them. The custody methods re-wrap and verify data keys inside the
	// signer and return only ciphertext or a digest to the control plane.
	kemCustody KEMCustody

	// tenantKEK, when non-nil, holds tenant domain KEKs under operator HSM
	// wrapper keys (A123). The control plane persists only wrapped domain KEKs
	// and reaches the keys only through the tenant KEK RPCs.
	tenantKEK TenantKEKCustody

	// artifactSigner, when non-nil, signs opaque artifact payloads inside the
	// isolated signer. The core defines only this generic surface; concrete
	// artifact semantics live in an edition implementation.
	artifactSigner ArtifactSigner

	// operationGate, when non-nil, verifies opaque public operation evidence inside
	// the signer before a caller-provided key operation may run. Core owns only the
	// ordering and transport seam; edition code owns the semantics.
	operationGate OperationGate

	// gatedDestroyer, when non-nil, verifies opaque destruction preconditions
	// inside the signer before a caller-provided destroy operation may run. Core
	// owns only the generic ordering seam; edition code owns the semantics.
	gatedDestroyer GatedDestroyer
	// Serializes signer-owned destruction intent/result journaling with handle
	// removal. Two commands must never both observe one handle as live.
	gatedDestroyMu      sync.Mutex
	gatedDestroyOps     map[string]gatedDestroyJournalRecord
	gatedDestroyStreams *limiter

	// authorizer, when non-nil, verifies the dual-control sign-intent attestation
	// that a DUAL-CONTROL key (keyConstraints.requireAuth) requires on every Sign
	// (RED-003). The signer uses it as verifier material; production token minting
	// belongs to an independent approval-token authority, not the control-plane
	// process that chooses the digest. nil = dual-control keys cannot be created or
	// used (the signer fails closed on them).
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

// WithKeyFactory installs the compile-time key factory for this signer process.
// Core passes none and receives only MPL algorithms. The EE signer attach seam
// may pass a factory for proprietary algorithms without importing ee/ into core.
func WithKeyFactory(factory KeyFactory) ServerOption {
	return func(s *Server) {
		if factory != nil {
			s.keyspec = factory
		}
	}
}

// NewServer returns a ready in-memory signing server (keys do not survive a
// restart).
func NewServer(opts ...ServerOption) *Server {
	s := &Server{keys: make(map[string]*heldKey), revocations: make(map[string]KeyRevocation), serving: true, keyspec: defaultKeyFactory{}, gatedDestroyStreams: newLimiter(2)}
	for _, o := range opts {
		o(s)
	}
	s.bindMinterCustody()
	s.bindIssuanceKeyOpCustody()
	s.readiness.start()
	return s
}

// NewPersistentServer returns a signing server backed by a sealed key store: it
// loads any persisted keys on construction (so a restart preserves the issuing CA
// rather than silently rotating it, R3.2) and seals new keys as they are
// generated. Usage constraints are sealed with the key and restored too, so a
// CA-class key stays purpose-bound across a restart.
func NewPersistentServer(store *KeyStore, opts ...ServerOption) (*Server, error) {
	s := &Server{serving: true, store: store, revocations: make(map[string]KeyRevocation), keyspec: defaultKeyFactory{}, gatedDestroyStreams: newLimiter(2)}
	for _, o := range opts {
		o(s)
	}
	store.withKeyFactory(s.keyspec)
	keys, err := store.Load()
	if err != nil {
		return nil, err
	}
	s.keys = keys
	s.bindMinterCustody()
	s.bindIssuanceKeyOpCustody()
	s.readiness.start()
	return s, nil
}

// GenerateKey creates a new key inside the signer and returns its handle and
// public key. Any usage constraints on the request (allowed_purposes /
// allowed_hashes, SIGNER-002/003) are bound to the key and enforced on every
// subsequent Sign.
func (s *Server) GenerateKey(ctx context.Context, req *signerpb.GenerateKeyRequest) (*signerpb.GenerateKeyResponse, error) {
	if req.GetAlgorithm() == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "unsupported algorithm ALGORITHM_UNSPECIFIED")
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
	owner, class, err := requestedKeyOwnership(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if owner != "" {
		constraints.ownerTenantID, constraints.keyClass = owner, class
		if !constraints.isTenantCAFor(owner) {
			return nil, status.Error(codes.InvalidArgument, "tenant CA ownership requires CA_SIGN and dual control")
		}
	}
	ls, err := s.keyspec.GenerateSigningKeyFromProto(req.GetAlgorithm())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}
	if err := ceremonyCheck(ls); err != nil {
		ls.Destroy()
		return nil, status.Errorf(codes.Internal, "key ceremony check: %v", err)
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
	if owner != "" && reservedTenantCAHandle(id) {
		ls.Destroy()
		return nil, status.Error(codes.PermissionDenied, "reserved signer key handle cannot be tenant-owned")
	}
	if isPCASGenericPairedHandle(id) {
		// Older paired KEM rewraps created this key with GenerateKey. Keep
		// its sealed origin for historical readback, but generic Sign refuses
		// all successor handles regardless of that legacy marker.
		constraints.genericPCAS = true
	}
	if id == "audit-export" {
		constraints.artifactOnly = true
	}

	held := &heldKey{signer: ls, constraints: constraints}
	if err := s.mintHeldKey(id, held); err != nil {
		ls.Destroy()
		return nil, hierarchyCustodyStatus("persist key", err)
	}

	return &signerpb.GenerateKeyResponse{
		Handle:    &signerpb.KeyHandle{Id: id},
		Algorithm: s.keyspec.ProtoFromAlgorithm(ls.Algorithm()),
		PublicKey: ls.Public().DER,
	}, nil
}

// errKeyHandleExists distinguishes the duplicate-handle refusal from a persist
// failure inside mintHeldKey, so each caller keeps its own message and status.
var errKeyHandleExists = errors.New("signing: key handle already exists")

// mintHeldKey is the ONE mint path: persist the new key sealed at rest (R3.2),
// then publish its handle — never publishing a handle that is not yet durable.
//
// The primary GenerateKey RPC used to insert into s.keys, unlock, and only
// then save — with a compensating delete on failure. That left a window where
// the handle resolved to a key no restart would recover, and a concurrent Sign
// could produce a signature the delete cannot undo (AUD-201 follow-up C1/V19;
// GenerateSuccessorKey was fixed in the same commit that condemned the old
// ordering while the RPC kept it).
//
// The expensive half of the save — sealing and writing the key file — is staged
// OUTSIDE s.mu, so it no longer stalls every concurrent Sign (which takes s.mu
// only to resolve a handle). Under s.mu we do just the exists check, the
// destroyed-tombstone check, the fast atomic rename (commit), and the in-memory
// publish — keeping the key durable before it is visible, and keeping the
// tombstone check atomic with the rename so a concurrent destroy cannot be
// resurrected. staging touches only the filesystem and the seal wrapper — it
// never re-enters the server — so this cannot deadlock.
func (s *Server) mintHeldKey(id string, held *heldKey) error {
	var staged *stagedSave
	if s.store != nil {
		hierarchy, err := hierarchyCustodySlot(id)
		if err != nil {
			return err
		}
		if hierarchy {
			unlock, err := s.store.lockHierarchyWriter(id)
			if err != nil {
				return err
			}
			defer unlock()
			s.mu.Lock()
			_, exists := s.keys[id]
			s.mu.Unlock()
			if exists {
				return errKeyHandleExists
			}
			if err := s.store.saveHierarchyKeyLocked(id, held.signer, held.constraints); err != nil {
				return err
			}
			s.mu.Lock()
			s.keys[id] = held
			s.mu.Unlock()
			return nil
		}
		st, err := s.store.stageSave(id, held.signer, held.constraints)
		if err != nil {
			return err
		}
		staged = st
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[id]; exists {
		if staged != nil {
			staged.discard()
		}
		return errKeyHandleExists
	}
	if staged != nil {
		if err := staged.commit(); err != nil {
			return err
		}
	}
	s.keys[id] = held
	return nil
}

// GetPublicKey returns the public key for a handle.
func (s *Server) GetPublicKey(ctx context.Context, req *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	owner, _, err := requestedKeyOwnership(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if owner != "" && (reservedTenantCAHandle(req.GetHandle().GetId()) || !held.constraints.isTenantCAFor(owner)) {
		return nil, status.Error(codes.PermissionDenied, "signer key is not an importable CA owned by this tenant")
	}
	revoked, err := s.revoked(req.GetHandle().GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read key revocation: %v", err)
	}
	return &signerpb.GetPublicKeyResponse{
		Algorithm:             s.keyspec.ProtoFromAlgorithm(held.signer.Algorithm()),
		PublicKey:             held.signer.Public().DER,
		RequiresAuthorization: held.constraints.requireAuth,
		Revoked:               revoked,
	}, nil
}

// Sign signs a pre-computed digest with the keyed handle. If the key was created
// with usage constraints (SIGNER-002/003), the request's asserted purpose and
// hash must satisfy them or the signature is refused with FAILED_PRECONDITION —
// so socket access alone cannot coerce a key into signing outside its mandate. If
// the key is dual-control (RED-003), the request must additionally carry a valid
// byte-native authorization token over the exact signing tuple, or the signature
// is refused with PERMISSION_DENIED — so socket access cannot coerce a crown-jewel
// key into signing arbitrary, un-attested bytes.
func (s *Server) Sign(ctx context.Context, req *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	held, err := s.lookupSigning(req.GetHandle())
	if err != nil {
		return nil, err
	}
	if isCustodyHandleNamespace(req.GetHandle().GetId()) {
		return nil, status.Error(codes.FailedPrecondition, "custody key handle cannot be used through generic Sign")
	}
	// Older audit-export keys predate the sealed artifactOnly bit. The fixed
	// handle reservation closes their raw Sign path without a key rotation.
	if req.GetHandle().GetId() == "audit-export" || held.constraints.artifactOnly {
		return nil, status.Error(codes.FailedPrecondition, "audit evidence key requires SignArtifact admission")
	}
	if err := held.constraints.check(req); err != nil {
		return nil, err
	}
	// A pure-message request is only meaningful for a key family that signs
	// the message itself (ML-DSA, SLH-DSA). A classical key would sign
	// arbitrary bytes as if they were a digest, so it refuses (RFC 9881).
	if req.GetHash() == signerpb.Hash_HASH_NONE && !crypto.PureMessageSignatureAlgorithm(held.signer.Algorithm()) {
		return nil, status.Errorf(codes.InvalidArgument,
			"pure-message signing needs a post-quantum signature key; this key is %s", held.signer.Algorithm())
	}
	// Dual-control gate (RED-003): a key marked requireAuth refuses every Sign that
	// does not carry a valid authorization token over the exact signing tuple, so
	// socket access alone cannot coerce a crown-jewel key into signing arbitrary
	// bytes. Enforced AFTER the purpose/hash constraints (both must pass).
	if held.constraints.requireAuth {
		if err := s.enforceDualControl(req); err != nil {
			return nil, err
		}
	}
	if req.GetOperationId() != "" {
		if s.store == nil {
			return nil, status.Error(codes.FailedPrecondition, "sign: operation journaling requires a persistent signer")
		}
		unlock := s.store.lockSignOperation(req.GetOperationId())
		defer unlock()
		prior, replayed, err := s.store.beginSignOperation(req)
		if err != nil {
			switch {
			case errors.Is(err, errSignOperationConflict):
				return nil, status.Errorf(codes.AlreadyExists, "sign journal: %v", err)
			default:
				return nil, status.Errorf(codes.Internal, "sign journal: %v", err)
			}
		}
		if replayed {
			return &signerpb.SignResponse{Signature: prior, Replayed: true}, nil
		}
	}
	if s.signGate != nil {
		s.signGate() // test-only: hold the actual private-key operation (nil in production)
	}
	hash, _, _ := hashFromProto(req.GetHash()) // validated above
	sig, err := held.signer.SignDigest(req.GetDigest(), crypto.SignOptions{
		Hash:       hash,
		RSAPadding: paddingFromProto(req.GetRsaPadding()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	if req.GetOperationId() != "" {
		if err := s.store.completeSignOperation(req, sig); err != nil {
			return nil, status.Errorf(codes.Internal, "sign journal completion: %v", err)
		}
	}
	return &signerpb.SignResponse{Signature: sig}, nil
}

// SignArtifact signs an opaque artifact through the attached signer-side
// extension. It fails closed in core-only builds where no extension is attached.
func (s *Server) SignArtifact(ctx context.Context, req *signerpb.SignArtifactRequest) (*signerpb.SignArtifactResponse, error) {
	areq, err := artifactSignRequestFromProto(req)
	if err != nil {
		return nil, err
	}
	res, err := s.signArtifact(ctx, areq)
	if err != nil {
		if errors.Is(err, ErrNoArtifactSigner) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, status.Errorf(codes.FailedPrecondition, "sign artifact: %v", err)
	}
	return artifactSignatureToProto(res)
}

// VerifyOperation verifies an opaque public operation request through the
// attached signer-side gate. It fails closed in core-only builds where no gate is
// attached.
func (s *Server) VerifyOperation(ctx context.Context, req *signerpb.OperationRequest) (*signerpb.OperationResponse, error) {
	oreq, err := operationRequestFromProto(req)
	if err != nil {
		return nil, err
	}
	decision, err := s.verifyOperation(ctx, oreq)
	if err != nil {
		if errors.Is(err, ErrNoOperationGate) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		return nil, status.Errorf(codes.FailedPrecondition, "verify operation: %v", err)
	}
	return operationDecisionToProto(decision), nil
}

// GatedDestroy verifies opaque destruction evidence through the attached
// signer-side gate, then destroys the signer-local key handle only after the gate
// approves. It fails closed in core-only builds where no gate is attached. The
// free DestroyKey RPC below is deliberately separate and remains ungated.
func (s *Server) GatedDestroy(ctx context.Context, req *signerpb.GatedDestroyRequest) (*signerpb.GatedDestroyResponse, error) {
	greq, err := gatedDestroyRequestFromProto(req)
	if err != nil {
		return nil, err
	}
	decision, err := s.gatedDestroy(ctx, greq, s.destroyGatedKeyHandle, true)
	if err != nil {
		if errors.Is(err, ErrNoGatedDestroyer) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		if status.Code(err) == codes.Unavailable {
			return nil, err
		}
		return nil, status.Errorf(codes.FailedPrecondition, "gated destroy: %v", err)
	}
	return gatedDestroyDecisionToProto(decision), nil
}

// DestroyKey zeroizes and forgets a handle. It is idempotent.
func (s *Server) DestroyKey(ctx context.Context, req *signerpb.DestroyKeyRequest) (*signerpb.DestroyKeyResponse, error) {
	h := req.GetHandle()
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	if err := s.destroyKeyHandle(ctx, h.GetId()); err != nil {
		return nil, err
	}
	return &signerpb.DestroyKeyResponse{}, nil
}

func (s *Server) destroyKeyHandle(_ context.Context, handle string) error {
	if handle == "" {
		return status.Error(codes.InvalidArgument, "missing key handle")
	}
	if handled, err := s.destroyHierarchyKey(handle, false); handled || err != nil {
		return err
	}
	if _, err := s.lookup(&signerpb.KeyHandle{Id: handle}); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	return s.destroyGatedKeyHandle(context.Background(), handle)
}

// destroyGatedKeyHandle is reached only after the durable gated-destruction
// journal proves this exact command observed the handle alive. Its tombstone is
// shared signer state: another signer process that cached the same persisted
// key will reject it on its next lookup instead of continuing to sign.
func (s *Server) destroyGatedKeyHandle(_ context.Context, handle string) error {
	if handle == "" {
		return status.Error(codes.InvalidArgument, "missing key handle")
	}
	if handled, err := s.destroyHierarchyKey(handle, true); handled || err != nil {
		return err
	}
	if s.store != nil {
		if err := s.store.markDestroyed(handle); err != nil {
			return status.Errorf(codes.Internal, "persist destroyed-key tombstone: %v", err)
		}
	}
	held := s.forgetKey(handle)
	if held != nil {
		held.signer.Destroy()
		if s.store != nil {
			if err := s.store.Remove(handle); err != nil {
				return status.Errorf(codes.Internal, "remove persisted key: %v", err)
			}
		}
	}
	return nil
}

func (s *Server) forgetKey(handle string) *heldKey {
	s.mu.Lock()
	held := s.keys[handle]
	delete(s.keys, handle)
	delete(s.revocations, handle)
	s.mu.Unlock()
	return held
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
	return &signerpb.HealthResponse{Status: st, ManagedKeyProviders: s.readiness.snapshot()}, nil
}

// Shutdown marks the server draining and zeroizes every key it holds.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serving = false
	s.readiness.close()
	for id, held := range s.keys {
		held.signer.Destroy()
		delete(s.keys, id)
	}
	if s.kemCustody != nil {
		s.kemCustody.DestroyAll()
	}
	if closer, ok := s.tenantKEK.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	if destroyer, ok := s.artifactSigner.(interface{ Destroy() }); ok {
		destroyer.Destroy()
	}
	if destroyer, ok := s.gatedDestroyer.(interface{ Destroy() }); ok {
		destroyer.Destroy()
	}
	if s.managedKeys != nil {
		s.managedKeys.Close()
	}
}

func (s *Server) lookup(h *signerpb.KeyHandle) (*heldKey, error) {
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	if s.store != nil {
		hierarchy, err := hierarchyCustodySlot(h.GetId())
		if err != nil {
			return nil, hierarchyCustodyStatus("resolve key handle", err)
		}
		if hierarchy {
			return s.lookupHierarchyKey(h.GetId())
		}
	}
	s.mu.Lock()
	if s.store != nil {
		destroyed, err := s.store.IsDestroyed(h.GetId())
		if err != nil {
			s.mu.Unlock()
			return nil, status.Errorf(codes.Internal, "read destroyed-key tombstone: %v", err)
		}
		if destroyed {
			held := s.keys[h.GetId()]
			delete(s.keys, h.GetId())
			s.mu.Unlock()
			if held != nil {
				held.signer.Destroy()
			}
			return nil, status.Error(codes.NotFound, "destroyed key handle")
		}
	}
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

func (s *Server) lookupHierarchyKey(handle string) (*heldKey, error) {
	destroyed, err := s.store.IsDestroyed(handle)
	if err != nil {
		return nil, hierarchyCustodyStatus("read destroyed-key tombstone", err)
	}
	s.mu.Lock()
	held := s.keys[handle]
	if destroyed {
		delete(s.keys, handle)
	}
	s.mu.Unlock()
	if destroyed {
		if held != nil {
			held.signer.Destroy()
		}
		return nil, status.Error(codes.NotFound, "destroyed key handle")
	}
	if held != nil {
		return held, nil
	}
	unlock, err := s.store.lockHierarchyCustody(handle)
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Error(codes.NotFound, "unknown key handle")
	}
	if err != nil {
		return nil, hierarchyCustodyStatus("load key handle", err)
	}
	defer unlock()
	s.mu.Lock()
	held = s.keys[handle]
	s.mu.Unlock()
	if held != nil {
		destroyed, err := s.store.IsDestroyed(handle)
		if err != nil {
			return nil, hierarchyCustodyStatus("read destroyed-key tombstone", err)
		}
		if destroyed {
			return nil, status.Error(codes.NotFound, "destroyed key handle")
		}
		return held, nil
	}
	held, err = s.store.loadHierarchyKeyLocked(handle)
	if err != nil {
		return nil, hierarchyCustodyStatus("load key handle", err)
	}
	if held == nil {
		return nil, status.Error(codes.NotFound, "unknown key handle")
	}
	s.mu.Lock()
	s.keys[handle] = held
	s.mu.Unlock()
	return held, nil
}
