// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
)

// The asymmetric profile (A197): the server generates RSA and ECDSA key pairs,
// keeps the private key sealed like every key it holds, and signs and verifies
// with them for clients. A pair starts Pre-Active and is used only after
// Activate. A generated private key is not extractable unless the client asked
// for an extractable one when creating the pair, so by default it never leaves
// the server.

// KeyPairSpec is what a Create Key Pair asks for.
type KeyPairSpec struct {
	Algorithm string // RSA or ECDSA
	Length    int    // RSA modulus bits (2048, 3072, 4096); ECDSA curve bits (256, 384)
	// Usage masks per half; zero takes the defaults, Sign for the private key
	// and Verify for the public key.
	PrivateMask, PublicMask   int32
	PrivateNames, PublicNames []string
	// PrivateExtractable is the client's Extractable for the private key; nil
	// leaves it unextractable.
	PrivateExtractable *bool
}

// SignatureParams selects a signature scheme: the hash, and for RSA the
// padding. Algorithm, when set, must match the key's.
type SignatureParams struct {
	Algorithm string
	Hash      crypto.Hash
	Padding   crypto.RSAPadding
}

// KeyView is a copy-safe view of a key Get returns: the key's DER (PKCS#8 for
// a private key, SubjectPublicKeyInfo for a public one). Material must be
// wiped by the caller.
type KeyView struct {
	ID        string
	Type      ObjectType
	Algorithm string
	Length    int
	Material  []byte
}

// LocateFilter narrows Locate: object type, algorithm and name, each optional.
type LocateFilter struct {
	Type      *ObjectType
	Algorithm string
	Name      string
}

func keyPairAlgorithm(algorithm string, length int) (crypto.Algorithm, error) {
	switch {
	case algorithm == "RSA" && length == 2048:
		return crypto.RSA2048, nil
	case algorithm == "RSA" && length == 3072:
		return crypto.RSA3072, nil
	case algorithm == "RSA" && length == 4096:
		return crypto.RSA4096, nil
	case algorithm == "ECDSA" && length == 256:
		return crypto.ECDSAP256, nil
	case algorithm == "ECDSA" && length == 384:
		return crypto.ECDSAP384, nil
	}
	return "", wireError{reason: resultReasonInvalidField, message: fmt.Sprintf(
		"key pairs are RSA 2048, 3072 or 4096 or ECDSA 256 (P-256) or 384 (P-384), not %s %d", algorithm, length)}
}

// CreateKeyPair generates a key pair and returns the private and public keys'
// identifiers. Each links to the other, and both start Pre-Active.
func (s *Server) CreateKeyPair(ctx context.Context, clientCertDER []byte, spec KeyPairSpec) (string, string, error) {
	if _, err := s.authClient(ctx, "create_key_pair", clientCertDER); err != nil {
		return "", "", err
	}
	alg, err := keyPairAlgorithm(spec.Algorithm, spec.Length)
	if err != nil {
		return "", "", err
	}
	der, err := crypto.GeneratePKCS8(alg)
	if err != nil {
		return "", "", fmt.Errorf("kmip: generate key pair: %w", err)
	}
	defer secret.Wipe(der)
	signer, err := crypto.NewLockedSignerFromPKCS8(alg, der)
	if err != nil {
		return "", "", fmt.Errorf("kmip: read generated key pair: %w", err)
	}
	public := append([]byte(nil), signer.Public().DER...)
	signer.Destroy()

	privateMask, publicMask := spec.PrivateMask, spec.PublicMask
	if privateMask == 0 {
		privateMask = usageMaskSign
	}
	if publicMask == 0 {
		publicMask = usageMaskVerify
	}
	extractable := spec.PrivateExtractable != nil && *spec.PrivateExtractable
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	privateID, publicID := fmt.Sprintf("kmip-%d", s.n+1), fmt.Sprintf("kmip-%d", s.n+2)
	priv := &ManagedObject{ID: privateID, Type: ObjectPrivateKey, Algorithm: spec.Algorithm, Length: spec.Length,
		State: StatePreActive, Version: 1, UsageMask: privateMask, Link: publicID,
		Extractable: extractable, NeverExtractable: !extractable, Initial: now, LastChange: now}
	pub := &ManagedObject{ID: publicID, Type: ObjectPublicKey, Algorithm: spec.Algorithm, Length: spec.Length,
		State: StatePreActive, Version: 1, UsageMask: publicMask, Link: privateID, PublicDER: public,
		Extractable: true, Initial: now, LastChange: now}
	sealed, err := s.persistKeyState(ctx, kmipStateCreatedEventType, priv, der)
	if err != nil {
		return "", "", err
	}
	// Both identifiers are spent once the private half is recorded.
	s.n += 2
	priv.sealedKey = sealed
	if err := s.persistState(ctx, kmipStateCreatedEventType, stateEventFor(pub, nil)); err != nil {
		// Destroy the recorded private half rather than leave a pair with no
		// public key.
		_ = s.persistState(ctx, kmipStateDestroyedEventType, kmipStateEvent{ID: privateID, State: StateDestroyed, Version: 1})
		secret.Wipe(priv.sealedKey)
		return "", "", err
	}
	s.objects[privateID], s.objects[publicID] = priv, pub
	for _, half := range []struct {
		obj   *ManagedObject
		names []string
	}{{priv, spec.PrivateNames}, {pub, spec.PublicNames}} {
		if len(half.names) == 0 {
			continue
		}
		half.obj.Names = append([]string(nil), half.names...)
		if err := s.persistAttributes(ctx, half.obj); err != nil {
			return "", "", err
		}
	}
	for _, obj := range []*ManagedObject{priv, pub} {
		_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.created", s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"alg":%q}`, obj.ID, obj.Algorithm)))
	}
	return privateID, publicID, nil
}

// Activate moves a Pre-Active object to Active and records its Activation
// Date. Only a Pre-Active object can be activated.
func (s *Server) Activate(ctx context.Context, clientCertDER []byte, id string) error {
	if _, err := s.authClient(ctx, "activate", clientCertDER); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return fmt.Errorf("kmip: object %q not found", id)
	}
	if obj.State != StatePreActive {
		return wireError{reason: resultReasonPermissionDenied, message: "only a Pre-Active object can be activated; this one is " + string(obj.State)}
	}
	if err := s.persistState(ctx, kmipStateActivatedEventType, kmipStateEvent{ID: id, State: StateActive, Version: obj.Version}); err != nil {
		return err
	}
	now := time.Now().UTC()
	obj.State, obj.Activated, obj.LastChange = StateActive, now, now
	_ = auditsink.Emit(ctx, s.audit, nil, "kmip.object.activated", s.tenantID, []byte(fmt.Sprintf(`{"id":%q,"state":%q}`, id, StateActive)))
	return nil
}

// Sign signs data with an active private key whose usage mask allows Sign.
func (s *Server) Sign(ctx context.Context, clientCertDER []byte, id string, params SignatureParams, data []byte) ([]byte, error) {
	if _, err := s.authClient(ctx, "sign", clientCertDER); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return nil, fmt.Errorf("kmip: object %q not found", id)
	}
	if obj.Type != ObjectPrivateKey {
		return nil, wireError{reason: resultReasonInvalidField, message: "Sign takes a private key"}
	}
	if obj.State != StateActive {
		return nil, wireError{reason: resultReasonPermissionDenied, message: "the private key is " + string(obj.State) + "; only an active key signs"}
	}
	if obj.UsageMask != 0 && obj.UsageMask&usageMaskSign == 0 {
		return nil, wireError{reason: resultReasonPermissionDenied, message: "the private key's usage mask does not allow Sign"}
	}
	opts, err := signOptionsFor(obj, params)
	if err != nil {
		return nil, err
	}
	der, err := s.openKey(ctx, obj)
	if err != nil {
		return nil, err
	}
	alg, err := keyPairAlgorithm(obj.Algorithm, obj.Length)
	if err != nil {
		secret.Wipe(der)
		return nil, err
	}
	signer, err := crypto.NewLockedSignerFromPKCS8(alg, der)
	secret.Wipe(der)
	if err != nil {
		return nil, fmt.Errorf("kmip: load private key: %w", err)
	}
	defer signer.Destroy()
	digest, err := crypto.Digest(opts.Hash, data)
	if err != nil {
		return nil, wireError{reason: resultReasonCryptographicFailure, message: err.Error()}
	}
	signature, err := signer.SignDigest(digest, opts)
	if err != nil {
		return nil, wireError{reason: resultReasonCryptographicFailure, message: "signing failed"}
	}
	return signature, nil
}

// SignatureVerify checks a signature with a public key. An active or
// deactivated key verifies; a pre-active, compromised or destroyed one does
// not.
func (s *Server) SignatureVerify(ctx context.Context, clientCertDER []byte, id string, params SignatureParams, data, signature []byte) (bool, error) {
	if _, err := s.authClient(ctx, "signature_verify", clientCertDER); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return false, fmt.Errorf("kmip: object %q not found", id)
	}
	if obj.Type != ObjectPublicKey {
		return false, wireError{reason: resultReasonInvalidField, message: "Signature Verify takes a public key"}
	}
	if obj.State != StateActive && obj.State != StateRevoked {
		return false, wireError{reason: resultReasonPermissionDenied, message: "the public key is " + string(obj.State) + "; only an active or deactivated key verifies"}
	}
	if obj.UsageMask != 0 && obj.UsageMask&usageMaskVerify == 0 {
		return false, wireError{reason: resultReasonPermissionDenied, message: "the public key's usage mask does not allow Verify"}
	}
	opts, err := signOptionsFor(obj, params)
	if err != nil {
		return false, err
	}
	alg, err := keyPairAlgorithm(obj.Algorithm, obj.Length)
	if err != nil {
		return false, err
	}
	digest, err := crypto.Digest(opts.Hash, data)
	if err != nil {
		return false, wireError{reason: resultReasonCryptographicFailure, message: err.Error()}
	}
	return crypto.VerifyDigest(crypto.PublicKey{Algorithm: alg, DER: obj.PublicDER}, digest, signature, opts) == nil, nil
}

// signOptionsFor checks a request's signature parameters against the key and
// fills the defaults: SHA-256, and PKCS#1 v1.5 padding for RSA.
func signOptionsFor(obj *ManagedObject, params SignatureParams) (crypto.SignOptions, error) {
	if params.Algorithm != "" && params.Algorithm != obj.Algorithm {
		return crypto.SignOptions{}, wireError{reason: resultReasonInvalidField, message: "the requested algorithm " + params.Algorithm + " does not match the " + obj.Algorithm + " key"}
	}
	opts := crypto.SignOptions{Hash: params.Hash, RSAPadding: params.Padding}
	if opts.Hash == "" {
		opts.Hash = crypto.SHA256
	}
	switch obj.Algorithm {
	case "RSA":
		if opts.RSAPadding == "" {
			opts.RSAPadding = crypto.RSAPKCS1v15
		}
	default:
		if opts.RSAPadding != "" {
			return crypto.SignOptions{}, wireError{reason: resultReasonInvalidField, message: "a padding method applies only to RSA keys"}
		}
	}
	return opts, nil
}

// GetKey returns a key pair half for Get. A public key always returns; a
// private key returns only if it is extractable. Destroyed objects return
// nothing.
func (s *Server) GetKey(ctx context.Context, clientCertDER []byte, id string) (KeyView, error) {
	if _, err := s.authClient(ctx, "get", clientCertDER); err != nil {
		return KeyView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok || obj.State == StateDestroyed {
		return KeyView{}, fmt.Errorf("kmip: object %q not available", id)
	}
	view := KeyView{ID: obj.ID, Type: obj.Type, Algorithm: obj.Algorithm, Length: obj.Length}
	switch obj.Type {
	case ObjectPublicKey:
		view.Material = append([]byte(nil), obj.PublicDER...)
	case ObjectPrivateKey:
		if !obj.Extractable {
			return KeyView{}, wireError{reason: resultReasonNotExtractable, message: "the private key is not extractable; it signs here and does not leave the server"}
		}
		der, err := s.openKey(ctx, obj)
		if err != nil {
			return KeyView{}, err
		}
		view.Material = der
	default:
		return KeyView{}, errors.New("kmip: GetKey serves key pair halves")
	}
	return view, nil
}

// objectType reports an object's type, and whether it exists.
func (s *Server) objectType(id string) (ObjectType, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[id]
	if !ok {
		return "", false
	}
	return obj.Type, true
}

// LocateMatching returns the ids of active and pre-active objects that match
// the filter, in order.
func (s *Server) LocateMatching(ctx context.Context, clientCertDER []byte, f LocateFilter) ([]string, error) {
	if _, err := s.authClient(ctx, "locate", clientCertDER); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, o := range s.objects {
		if o.State != StateActive && o.State != StatePreActive {
			continue
		}
		if (f.Type != nil && o.Type != *f.Type) || (f.Algorithm != "" && o.Algorithm != f.Algorithm) ||
			(f.Name != "" && !slices.Contains(o.Names, f.Name)) {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// openKey opens an object's sealed key material. The caller wipes it.
func (s *Server) openKey(ctx context.Context, obj *ManagedObject) ([]byte, error) {
	if s.log == nil {
		return append([]byte(nil), obj.sealedKey...), nil
	}
	var key []byte
	err := s.withTenantCipher(ctx, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
		key, err = cipher.Open(obj.sealedKey, s.stateAAD(obj.ID, obj.Version))
		return err
	})
	if err != nil {
		secret.Wipe(key)
		return nil, fmt.Errorf("kmip: open managed object: %w", err)
	}
	return key, nil
}

// stateEventFor is the state event for an object. A symmetric key keeps the
// original profile's payload exactly.
func stateEventFor(obj *ManagedObject, sealed []byte) kmipStateEvent {
	ev := kmipStateEvent{ID: obj.ID, Algorithm: obj.Algorithm, State: obj.State, Version: obj.Version, SealedKey: sealed}
	if obj.Type == ObjectSymmetricKey {
		return ev
	}
	extractable := obj.Extractable
	ev.ObjectType, ev.Length, ev.UsageMask, ev.Link, ev.Extractable = obj.Type, obj.Length, obj.UsageMask, obj.Link, &extractable
	if obj.Type == ObjectPublicKey {
		ev.PublicKey = obj.PublicDER
	}
	return ev
}

// replayedObject rebuilds an object from its created, registered or rekeyed
// event.
func replayedObject(p kmipStateEvent, at time.Time) (*ManagedObject, error) {
	at = at.UTC()
	obj := &ManagedObject{ID: p.ID, Algorithm: p.Algorithm, State: p.State, Version: p.Version, Type: p.ObjectType,
		Length: p.Length, UsageMask: p.UsageMask, Link: p.Link, Initial: at, LastChange: at}
	malformed := p.ID == "" || p.Version < 1
	switch p.ObjectType {
	case ObjectSymmetricKey:
		malformed = malformed || p.Algorithm != "AES" || len(p.SealedKey) == 0
		obj.State, obj.Activated, obj.Extractable = StateActive, at, true
		if obj.Length == 0 {
			obj.Length = 256
		}
	case ObjectPrivateKey:
		malformed = malformed || len(p.SealedKey) == 0 || p.Link == ""
		obj.Extractable = p.Extractable != nil && *p.Extractable
		obj.NeverExtractable = !obj.Extractable
	case ObjectPublicKey:
		malformed = malformed || len(p.PublicKey) == 0 || p.Link == ""
		obj.PublicDER, obj.Extractable = append([]byte(nil), p.PublicKey...), true
	default:
		malformed = true
	}
	if p.ObjectType != ObjectSymmetricKey {
		if _, err := keyPairAlgorithm(p.Algorithm, p.Length); err != nil {
			malformed = true
		}
		if obj.State == "" {
			obj.State = StatePreActive
		}
	}
	if malformed {
		return nil, errors.New("kmip: replay key state is malformed")
	}
	obj.sealedKey = append([]byte(nil), p.SealedKey...)
	return obj, nil
}

// replayLifecycle applies an activated, revoked or destroyed event.
func replayLifecycle(obj *ManagedObject, eventType string, state ObjectState, at time.Time) {
	at = at.UTC()
	switch eventType {
	case kmipStateDestroyedEventType:
		secret.Wipe(obj.sealedKey)
		obj.sealedKey = nil
		obj.State = StateDestroyed
	case kmipStateActivatedEventType:
		obj.State, obj.Activated = StateActive, at
	default:
		obj.State = StateRevoked
		if state == StateCompromised {
			obj.State = StateCompromised
		}
	}
	obj.LastChange = at
}
