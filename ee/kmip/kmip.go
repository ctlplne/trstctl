// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package kmip implements the served KMIP operation model (S18.2, F66) and a
// bounded TTLV decoder/encoder for enterprise key-management clients. Operations
// are gated by verified TLS client-certificate authentication, tenant-scoped
// (AN-1), audited through the event log (AN-2), and mounted by the server package
// behind the protocols bulkhead (AN-7).
package kmip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	kmipStateCreatedEventType    = "kmip.state.object.created"
	kmipStateRegisteredEventType = "kmip.state.object.registered"
	kmipStateRekeyedEventType    = "kmip.state.object.rekeyed"
	kmipStateRevokedEventType    = "kmip.state.object.revoked"
	kmipStateDestroyedEventType  = "kmip.state.object.destroyed"
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
	sealedKey []byte // ciphertext only; plaintext is opened for one fenced request
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
	log      *events.Log
	wrapper  seal.KeyWrapper
	crypto   tenantseal.Access
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

// NewDurable constructs a KMIP server whose managed-object lifecycle is rebuilt
// from the tenant's append-only event stream. Key bytes are envelope-sealed by a
// stable KeyWrapper before entering an event; plaintext is never persisted.
func NewDurable(ctx context.Context, tenantID string, auth Authenticator, audit auditsink.Auditor, log *events.Log, wrapper seal.KeyWrapper, tenantCrypto ...tenantseal.Access) (*Server, error) {
	if log == nil {
		return nil, errors.New("kmip: durable server requires an event log")
	}
	if wrapper == nil {
		return nil, errors.New("kmip: durable server requires a key wrapper")
	}
	s := New(tenantID, auth, audit)
	s.log = log
	s.wrapper = wrapper
	if len(tenantCrypto) > 0 {
		s.crypto = tenantCrypto[0]
	}
	if err := s.replay(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

type tenantCipherContextKey struct{}

type legacyTenantCipher struct{ wrapper seal.KeyWrapper }

func (c legacyTenantCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.wrapper, plaintext, aad)
}

func (c legacyTenantCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.wrapper, container, aad)
}

func (s *Server) withTenantCipher(ctx context.Context, fn func(context.Context, tenantseal.Cipher) error) error {
	if cipher, ok := ctx.Value(tenantCipherContextKey{}).(tenantseal.Cipher); ok {
		return fn(ctx, cipher)
	}
	if s.crypto != nil {
		return s.crypto.WithTenant(ctx, s.tenantID, func(cipher tenantseal.Cipher) error {
			return fn(context.WithValue(ctx, tenantCipherContextKey{}, cipher), cipher)
		})
	}
	if s.wrapper == nil {
		return errors.New("kmip: tenant cryptographic access is not configured")
	}
	return fn(ctx, legacyTenantCipher{wrapper: s.wrapper})
}

type kmipStateEvent struct {
	ID        string      `json:"id"`
	Algorithm string      `json:"algorithm,omitempty"`
	State     ObjectState `json:"state,omitempty"`
	Version   int         `json:"version,omitempty"`
	SealedKey []byte      `json:"sealed_key,omitempty"`
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
	return s.register(ctx, algorithm, key, "kmip.object.created", kmipStateCreatedEventType)
}

// Register stores a client-supplied key and returns its unique identifier.
func (s *Server) Register(ctx context.Context, clientCertDER []byte, algorithm string, key []byte) (string, error) {
	if _, err := s.authClient(ctx, "register", clientCertDER); err != nil {
		return "", err
	}
	if algorithm != "AES" || len(key) != 32 {
		return "", fmt.Errorf("kmip: Register supports only AES-256 key material")
	}
	return s.register(ctx, algorithm, append([]byte(nil), key...), "kmip.object.registered", kmipStateRegisteredEventType)
}

func (s *Server) register(ctx context.Context, algorithm string, key []byte, auditEventType, stateEventType string) (string, error) {
	defer secret.Wipe(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	id := fmt.Sprintf("kmip-%d", s.n)
	obj := &ManagedObject{ID: id, Algorithm: algorithm, State: StateActive, Version: 1}
	sealedKey, err := s.persistKeyState(ctx, stateEventType, obj, key)
	if err != nil {
		s.n--
		return "", err
	}
	obj.sealedKey = sealedKey
	s.objects[id] = obj
	_ = auditsink.Emit(ctx, s.audit, nil, auditEventType, s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"alg":%q}`, id, algorithm)))
	return id, nil
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
	var key []byte
	var err error
	if s.log == nil {
		key = append([]byte(nil), obj.sealedKey...)
	} else {
		err = s.withTenantCipher(ctx, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
			key, err = cipher.Open(obj.sealedKey, s.stateAAD(obj.ID, obj.Version))
			return err
		})
	}
	if err != nil {
		secret.Wipe(key)
		return ManagedObjectView{}, fmt.Errorf("kmip: open managed object: %w", err)
	}
	if len(key) != 32 {
		secret.Wipe(key)
		return ManagedObjectView{}, errors.New("kmip: managed AES key has invalid length")
	}
	return ManagedObjectView{
		ID:        obj.ID,
		Algorithm: obj.Algorithm,
		Version:   obj.Version,
		Key:       key,
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
	version := obj.Version + 1
	sealedKey, err := s.persistKeyState(ctx, kmipStateRekeyedEventType, &ManagedObject{ID: obj.ID, Algorithm: obj.Algorithm, State: obj.State, Version: version}, key)
	secret.Wipe(key)
	if err != nil {
		return 0, err
	}
	secret.Wipe(obj.sealedKey)
	obj.sealedKey = sealedKey
	obj.Version = version
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
	if err := s.persistState(ctx, kmipStateDestroyedEventType, kmipStateEvent{ID: id, State: StateDestroyed, Version: obj.Version}); err != nil {
		return err
	}
	secret.Wipe(obj.sealedKey)
	obj.sealedKey = nil
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
		secret.Wipe(obj.sealedKey)
		obj.sealedKey = nil
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
	stateEventType := kmipStateRevokedEventType
	if err := s.persistState(ctx, stateEventType, kmipStateEvent{ID: id, State: to, Version: obj.Version}); err != nil {
		return err
	}
	obj.State = to
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object."+op, s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"state":%q}`, id, to)))
	return nil
}

func (s *Server) persistKeyState(ctx context.Context, eventType string, obj *ManagedObject, key []byte) ([]byte, error) {
	if s.log == nil {
		return append([]byte(nil), key...), nil
	}
	var sealed []byte
	err := s.withTenantCipher(ctx, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
		sealed, err = cipher.Seal(key, s.stateAAD(obj.ID, obj.Version))
		return err
	})
	if err != nil {
		secret.Wipe(sealed)
		return nil, fmt.Errorf("kmip: seal state key: %w", err)
	}
	if err := s.persistState(ctx, eventType, kmipStateEvent{
		ID: obj.ID, Algorithm: obj.Algorithm, State: obj.State, Version: obj.Version,
		SealedKey: sealed,
	}); err != nil {
		secret.Wipe(sealed)
		return nil, err
	}
	return sealed, nil
}

func (s *Server) persistState(ctx context.Context, eventType string, payload kmipStateEvent) error {
	if s.log == nil {
		return nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := s.log.Append(ctx, events.Event{Type: eventType, TenantID: s.tenantID, Data: data}); err != nil {
		return fmt.Errorf("kmip: append state event: %w", err)
	}
	return nil
}

func (s *Server) replay(ctx context.Context) error {
	return s.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != s.tenantID {
			return nil
		}
		switch ev.Type {
		case kmipStateCreatedEventType, kmipStateRegisteredEventType, kmipStateRekeyedEventType:
			var payload kmipStateEvent
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return fmt.Errorf("kmip: replay key state: %w", err)
			}
			if payload.ID == "" || payload.Algorithm != "AES" || payload.Version < 1 || len(payload.SealedKey) == 0 {
				return errors.New("kmip: replay key state is malformed")
			}
			if old := s.objects[payload.ID]; old != nil {
				secret.Wipe(old.sealedKey)
			}
			s.objects[payload.ID] = &ManagedObject{ID: payload.ID, Algorithm: payload.Algorithm, State: StateActive, Version: payload.Version, sealedKey: append([]byte(nil), payload.SealedKey...)}
			s.observeNumericID(payload.ID)
		case kmipStateRevokedEventType, kmipStateDestroyedEventType:
			var payload kmipStateEvent
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return fmt.Errorf("kmip: replay lifecycle state: %w", err)
			}
			obj := s.objects[payload.ID]
			if obj == nil {
				return fmt.Errorf("kmip: replay lifecycle references unknown object %q", payload.ID)
			}
			if ev.Type == kmipStateDestroyedEventType {
				secret.Wipe(obj.sealedKey)
				obj.sealedKey = nil
				obj.State = StateDestroyed
			} else {
				obj.State = StateRevoked
			}
		}
		return nil
	})
}

func (s *Server) stateAAD(id string, version int) []byte {
	return []byte("trstctl.kmip.state.v1|" + s.tenantID + "|" + id + "|" + strconv.Itoa(version))
}

func (s *Server) observeNumericID(id string) {
	raw, ok := strings.CutPrefix(id, "kmip-")
	if !ok {
		return
	}
	n, err := strconv.Atoi(raw)
	if err == nil && n > s.n {
		s.n = n
	}
}
