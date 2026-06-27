// Package kmip implements the served KMIP operation model (S18.2, F66) and a
// bounded TTLV decoder/encoder for enterprise key-management clients. Operations
// are gated by verified TLS client-certificate authentication, tenant-scoped
// (AN-1), audited through the event log (AN-2), and mounted by the server package
// behind the protocols bulkhead (AN-7).
package kmip

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Authenticator authenticates a KMIP client by its TLS client certificate.
type Authenticator interface {
	Authenticate(clientCertDER []byte) (clientID string, ok bool)
}

// VerifiedClientCertAuthenticator admits any non-empty certificate DER supplied
// by the mTLS layer after chain verification. The returned ID is a stable
// fingerprint for audit correlation; authorization policy can narrow this later
// without changing the KMIP wire handler.
type VerifiedClientCertAuthenticator struct{}

// Authenticate implements Authenticator.
func (VerifiedClientCertAuthenticator) Authenticate(clientCertDER []byte) (string, bool) {
	if len(clientCertDER) == 0 {
		return "", false
	}
	return "sha256:" + crypto.SHA256Hex(clientCertDER), true
}

// ObjectState is the lifecycle state of a managed object.
type ObjectState string

const (
	StateActive    ObjectState = "active"
	StateRevoked   ObjectState = "revoked"
	StateDestroyed ObjectState = "destroyed"
)

// ManagedObject is a KMIP managed cryptographic object (a symmetric key).
type ManagedObject struct {
	ID        string
	Algorithm string
	State     ObjectState
	Version   int
	key       []byte // AN-8: []byte, never logged
}

// ManagedObjectView is a copy-safe view of an active KMIP object. Key must be
// wiped by the caller after encoding or using it.
type ManagedObjectView struct {
	ID        string
	Algorithm string
	Version   int
	Key       []byte
}

// Server is the KMIP server.
type Server struct {
	tenantID string
	auth     Authenticator
	audit    auditsink.Auditor
	mu       sync.Mutex
	objects  map[string]*ManagedObject
	n        int
}

// New constructs a KMIP Server.
func New(tenantID string, auth Authenticator, audit auditsink.Auditor) *Server {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &Server{tenantID: tenantID, auth: auth, audit: audit, objects: map[string]*ManagedObject{}}
}

func (s *Server) authClient(ctx context.Context, op string, clientCertDER []byte) (string, error) {
	id, ok := s.auth.Authenticate(clientCertDER)
	if !ok {
		_ = auditsink.Emit(ctx, s.audit, nil, "kmip.unauthenticated", s.tenantID, []byte(fmt.Sprintf(`{"op":%q}`, op)))
		return "", fmt.Errorf("kmip: client certificate not authenticated")
	}
	return id, nil
}

// DecodeTTLVRequest authenticates a KMIP client certificate and decodes a bounded
// TTLV RequestMessage. It is the server-side library ingress a future network
// listener must call before dispatching operations.
func (s *Server) DecodeTTLVRequest(ctx context.Context, clientCertDER []byte, frame []byte) (RequestMessage, error) {
	if _, err := s.authClient(ctx, "decode_ttlv", clientCertDER); err != nil {
		return RequestMessage{}, err
	}
	return DecodeRequestMessage(frame)
}

// Create generates a new symmetric key and returns its unique identifier.
func (s *Server) Create(ctx context.Context, clientCertDER []byte, algorithm string) (string, error) {
	if _, err := s.authClient(ctx, "create", clientCertDER); err != nil {
		return "", err
	}
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return s.register(ctx, algorithm, key), nil
}

// Register stores a client-supplied key and returns its unique identifier.
func (s *Server) Register(ctx context.Context, clientCertDER []byte, algorithm string, key []byte) (string, error) {
	if _, err := s.authClient(ctx, "register", clientCertDER); err != nil {
		return "", err
	}
	return s.register(ctx, algorithm, append([]byte(nil), key...)), nil
}

func (s *Server) register(ctx context.Context, algorithm string, key []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	id := fmt.Sprintf("kmip-%d", s.n)
	s.objects[id] = &ManagedObject{ID: id, Algorithm: algorithm, State: StateActive, Version: 1, key: key}
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.created", s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"alg":%q}`, id, algorithm)))
	return id
}

// Get returns the key material of an active managed object to an authenticated
// client (the KMIP model: the client holds the key).
func (s *Server) Get(ctx context.Context, clientCertDER []byte, id string) ([]byte, error) {
	obj, err := s.GetObject(ctx, clientCertDER, id)
	if err != nil {
		return nil, err
	}
	return obj.Key, nil
}

// GetObject returns an active object's metadata and key material copy.
func (s *Server) GetObject(ctx context.Context, clientCertDER []byte, id string) (ManagedObjectView, error) {
	if _, err := s.authClient(ctx, "get", clientCertDER); err != nil {
		return ManagedObjectView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok || obj.State != StateActive {
		return ManagedObjectView{}, fmt.Errorf("kmip: object %q not available", id)
	}
	return ManagedObjectView{
		ID:        obj.ID,
		Algorithm: obj.Algorithm,
		Version:   obj.Version,
		Key:       append([]byte(nil), obj.key...),
	}, nil
}

// Locate returns the ids of active objects of the given algorithm.
func (s *Server) Locate(ctx context.Context, clientCertDER []byte, algorithm string) ([]string, error) {
	if _, err := s.authClient(ctx, "locate", clientCertDER); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, o := range s.objects {
		if o.State == StateActive && (algorithm == "" || o.Algorithm == algorithm) {
			out = append(out, id)
		}
	}
	return out, nil
}

// ReKey rotates an object's key material, returning the new version.
func (s *Server) ReKey(ctx context.Context, clientCertDER []byte, id string) (int, error) {
	if _, err := s.authClient(ctx, "rekey", clientCertDER); err != nil {
		return 0, err
	}
	key, err := crypto.RandomBytes(32)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok || obj.State != StateActive {
		secret.Wipe(key)
		return 0, fmt.Errorf("kmip: object %q not active", id)
	}
	secret.Wipe(obj.key)
	obj.key = key
	obj.Version++
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.rekeyed", s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"version":%d}`, id, obj.Version)))
	return obj.Version, nil
}

// Revoke marks an object revoked (no longer usable, still present).
func (s *Server) Revoke(ctx context.Context, clientCertDER []byte, id string) error {
	return s.transition(ctx, clientCertDER, "revoke", id, StateRevoked)
}

// Destroy zeroizes and removes an object's key material.
func (s *Server) Destroy(ctx context.Context, clientCertDER []byte, id string) error {
	if _, err := s.authClient(ctx, "destroy", clientCertDER); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return fmt.Errorf("kmip: object %q not found", id)
	}
	secret.Wipe(obj.key)
	obj.key = nil
	obj.State = StateDestroyed
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.destroyed", s.tenantID, []byte(fmt.Sprintf(`{"id":%q}`, id)))
	return nil
}

// Close zeroizes every in-memory managed object. The served KMIP listener keeps
// key material in RAM only for this process lifetime; shutdown must scrub it.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, obj := range s.objects {
		secret.Wipe(obj.key)
		obj.key = nil
		obj.State = StateDestroyed
	}
	clear(s.objects)
}

func (s *Server) transition(ctx context.Context, clientCertDER []byte, op, id string, to ObjectState) error {
	if _, err := s.authClient(ctx, op, clientCertDER); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return fmt.Errorf("kmip: object %q not found", id)
	}
	obj.State = to
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object."+op, s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"state":%q}`, id, to)))
	return nil
}
