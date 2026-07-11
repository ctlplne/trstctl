// SPDX-License-Identifier: MPL-2.0

//go:build cgo

package pkcs11

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	p11 "github.com/miekg/pkcs11"

	"trstctl.com/trstctl/internal/crypto"
)

// ModuleConfig describes a logged-in PKCS#11 module session. ModulePath is the
// native PKCS#11 shared library, TokenLabel selects the initialized token, and
// UserPIN authenticates the user session. UserPIN is kept as []byte at this
// boundary; the upstream PKCS#11 wrapper requires a transient string only at
// C_Login.
type ModuleConfig struct {
	ModulePath     string
	TokenLabel     string
	UserPIN        []byte
	KeyLabelPrefix string
}

type moduleSession struct {
	mu      sync.Mutex
	ctx     *p11.Ctx
	session p11.SessionHandle
	label   string
	closed  bool
	handles map[string]objectPair
}

var _ Session = (*moduleSession)(nil)
var _ LifecycleSession = (*moduleSession)(nil)
var _ OperationSession = (*moduleSession)(nil)

type objectPair struct {
	public   p11.ObjectHandle
	private  p11.ObjectHandle
	revoked  bool
	zeroized bool
}

// OpenModuleSession opens, initializes, and logs into a real PKCS#11 module.
// This is the KMS-03 real-binding path: compile-time Go interface injection in
// the prior-art crypto.Signer/JCA/OpenSSL ENGINE/PKCS#11 style, not a runtime
// crypto-provider registry.
func OpenModuleSession(cfg ModuleConfig) (Session, error) {
	if cfg.ModulePath == "" {
		return nil, errors.New("pkcs11: module path is required")
	}
	if cfg.TokenLabel == "" {
		return nil, errors.New("pkcs11: token label is required")
	}
	if len(cfg.UserPIN) == 0 {
		return nil, errors.New("pkcs11: user PIN is required")
	}
	ctx := p11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: load module %q", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: initialize module: %w", err)
	}
	slot, err := findTokenSlot(ctx, cfg.TokenLabel)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}
	sh, err := ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: open session: %w", err)
	}
	pin := string(cfg.UserPIN)
	if err := ctx.Login(sh, p11.CKU_USER, pin); err != nil && !isPKCS11Error(err, p11.CKR_USER_ALREADY_LOGGED_IN) {
		_ = ctx.CloseSession(sh)
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: login user: %w", err)
	}
	label := cfg.KeyLabelPrefix
	if label == "" {
		label = "trstctl-pkcs11"
	}
	return &moduleSession{
		ctx:     ctx,
		session: sh,
		label:   label,
		handles: make(map[string]objectPair),
	}, nil
}

func findTokenSlot(ctx *p11.Ctx, label string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: list token slots: %w", err)
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if info.Label == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: token %q not found", label)
}

func isPKCS11Error(err error, code uint) bool {
	var e p11.Error
	return errors.As(err, &e) && uint(e) == code
}

func (s *moduleSession) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	keyID, err := crypto.RandomBytes(16)
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11: generate object id: %w", err)
	}
	return s.generateKeyWithID(alg, keyID)
}

func (s *moduleSession) GenerateKeyForOperation(operationID string, alg crypto.Algorithm) (string, []byte, error) {
	if operationID == "" || len(operationID) > 256 {
		return "", nil, fmt.Errorf("pkcs11: durable operation id is required and must be at most 256 bytes")
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("trstctl:pkcs11:managed-key:"+operationID))
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11: derive operation object id: %w", err)
	}
	return s.generateKeyWithID(alg, digest[:16])
}

func (s *moduleSession) generateKeyWithID(alg crypto.Algorithm, keyID []byte) (string, []byte, error) {
	if alg != crypto.RSA2048 {
		return "", nil, fmt.Errorf("pkcs11: unsupported algorithm %q", alg)
	}
	if len(keyID) != 16 {
		return "", nil, fmt.Errorf("pkcs11: object id must be 16 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", nil, errors.New("pkcs11: session is closed")
	}
	handle := hex.EncodeToString(keyID)
	pub, priv, err := s.findObjectsByIDLocked(handle, keyID)
	if err != nil {
		return "", nil, err
	}
	if pub != 0 || priv != 0 {
		if pub == 0 || priv == 0 {
			return "", nil, fmt.Errorf("pkcs11: operation object %q is only partially present", handle)
		}
		der, err := s.publicDERLocked(pub)
		if err != nil {
			return "", nil, err
		}
		s.handles[handle] = objectPair{public: pub, private: priv}
		return handle, der, nil
	}
	label := fmt.Sprintf("%s-%s", s.label, hex.EncodeToString(keyID))
	publicAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11.NewAttribute(p11.CKA_MODULUS_BITS, 2048),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_ID, keyID),
	}
	privateAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SIGN, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_ID, keyID),
	}
	pub, priv, err = s.ctx.GenerateKeyPair(s.session,
		[]*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicAttrs,
		privateAttrs,
	)
	if err != nil {
		// A different signer process can win the deterministic CKA_ID race
		// while this request is in flight. Resolve that exact pair before
		// declaring the operation indeterminate.
		existingPub, existingPriv, lookupErr := s.findObjectsByIDLocked(handle, keyID)
		if lookupErr == nil && existingPub != 0 && existingPriv != 0 {
			der, readErr := s.publicDERLocked(existingPub)
			if readErr == nil {
				s.handles[handle] = objectPair{public: existingPub, private: existingPriv}
				return handle, der, nil
			}
		}
		return "", nil, fmt.Errorf("pkcs11: generate RSA key pair: %w", err)
	}
	der, err := s.publicDERLocked(pub)
	if err != nil {
		return "", nil, err
	}
	s.handles[handle] = objectPair{public: pub, private: priv}
	return handle, der, nil
}

func (s *moduleSession) publicDERLocked(pub p11.ObjectHandle) ([]byte, error) {
	attrs, err := s.ctx.GetAttributeValue(s.session, pub, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_MODULUS, nil),
		p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read RSA public key attributes: %w", err)
	}
	modulus, exponent, err := rsaPublicComponents(attrs)
	if err != nil {
		return nil, err
	}
	der, err := crypto.RSAPublicKeyDERFromComponents(modulus, exponent)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func rsaPublicComponents(attrs []*p11.Attribute) ([]byte, []byte, error) {
	var modulus, exponent []byte
	for _, attr := range attrs {
		switch attr.Type {
		case p11.CKA_MODULUS:
			modulus = bytes.Clone(attr.Value)
		case p11.CKA_PUBLIC_EXPONENT:
			exponent = bytes.Clone(attr.Value)
		}
	}
	if len(modulus) == 0 || len(exponent) == 0 {
		return nil, nil, errors.New("pkcs11: token did not return complete RSA public key attributes")
	}
	return modulus, exponent, nil
}

func (s *moduleSession) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if opts.Hash == "" {
		opts.Hash = crypto.SHA256
	}
	if opts.RSAPadding != "" && opts.RSAPadding != crypto.RSAPKCS1v15 {
		return nil, fmt.Errorf("pkcs11: unsupported RSA padding %q", opts.RSAPadding)
	}
	digestInfo, err := rsaDigestInfo(opts.Hash, digest)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("pkcs11: session is closed")
	}
	pair, err := s.findPairLocked(handle)
	if err != nil {
		return nil, err
	}
	if pair.revoked {
		return nil, fmt.Errorf("pkcs11: object handle %q is revoked", handle)
	}
	if pair.zeroized {
		return nil, fmt.Errorf("pkcs11: object handle %q is zeroized", handle)
	}
	if err := s.ctx.SignInit(s.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS, nil)}, pair.private); err != nil {
		return nil, fmt.Errorf("pkcs11: sign init: %w", err)
	}
	sig, err := s.ctx.Sign(s.session, digestInfo)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign digest: %w", err)
	}
	return sig, nil
}

func (s *moduleSession) RevokeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("pkcs11: session is closed")
	}
	keyID, err := decodeObjectHandle(handle)
	if err != nil {
		return err
	}
	pub, priv, err := s.findObjectsByIDLocked(handle, keyID)
	if err != nil {
		return err
	}
	if priv == 0 {
		// An absent private object cannot sign. This is the reconciled revoke
		// state even when a prior response was lost after deletion.
		delete(s.handles, handle)
		return nil
	}
	if err := s.ctx.SetAttributeValue(s.session, priv, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_SIGN, false),
	}); err != nil {
		return fmt.Errorf("pkcs11: disable signing for %q: %w", handle, err)
	}
	attrs, err := s.ctx.GetAttributeValue(s.session, priv, []*p11.Attribute{p11.NewAttribute(p11.CKA_SIGN, nil)})
	if err != nil {
		return fmt.Errorf("pkcs11: read back disabled signing for %q: %w", handle, err)
	}
	if len(attrs) != 1 || len(attrs[0].Value) == 0 || attrs[0].Value[0] != 0 {
		return fmt.Errorf("pkcs11: token did not confirm disabled signing for %q", handle)
	}
	s.handles[handle] = objectPair{public: pub, private: priv, revoked: true}
	return nil
}

func (s *moduleSession) RevokeKeyForOperation(operationID, handle string) error {
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("pkcs11: durable operation id is required and must be at most 256 bytes")
	}
	return s.RevokeKey(handle)
}

func (s *moduleSession) ZeroizeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("pkcs11: session is closed")
	}
	keyID, err := decodeObjectHandle(handle)
	if err != nil {
		return err
	}
	pub, priv, err := s.findObjectsByIDLocked(handle, keyID)
	if err != nil {
		return err
	}
	for _, obj := range []p11.ObjectHandle{priv, pub} {
		if obj == 0 {
			continue
		}
		if err := s.ctx.DestroyObject(s.session, obj); err != nil && !isPKCS11Error(err, p11.CKR_OBJECT_HANDLE_INVALID) {
			return fmt.Errorf("pkcs11: destroy object for %q: %w", handle, err)
		}
	}
	delete(s.handles, handle)
	pub, priv, err = s.findObjectsByIDLocked(handle, keyID)
	if err != nil {
		return fmt.Errorf("pkcs11: verify zeroized object %q: %w", handle, err)
	}
	if pub != 0 || priv != 0 {
		return fmt.Errorf("pkcs11: token did not confirm object %q was zeroized", handle)
	}
	return nil
}

func (s *moduleSession) ZeroizeKeyForOperation(operationID, handle string) error {
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("pkcs11: durable operation id is required and must be at most 256 bytes")
	}
	return s.ZeroizeKey(handle)
}

// findPairLocked resolves a provider-stable CKA_ID on demand. PKCS#11 object
// handles are session-local numbers, so persisting those numbers (or only an
// in-memory map) makes every managed key disappear after a signer restart. The
// public handle exposed to the control plane is instead the hex CKA_ID; a fresh
// signer session re-discovers both token objects from that id.
func (s *moduleSession) findPairLocked(handle string) (objectPair, error) {
	keyID, err := decodeObjectHandle(handle)
	if err != nil {
		return objectPair{}, err
	}
	pub, priv, err := s.findObjectsByIDLocked(handle, keyID)
	if err != nil {
		return objectPair{}, err
	}
	if pub == 0 || priv == 0 {
		return objectPair{}, fmt.Errorf("pkcs11: object handle %q does not resolve to a complete token key pair", handle)
	}
	pair := objectPair{public: pub, private: priv}
	s.handles[handle] = pair
	return pair, nil
}

func decodeObjectHandle(handle string) ([]byte, error) {
	keyID, err := hex.DecodeString(handle)
	if err != nil || len(keyID) == 0 {
		return nil, fmt.Errorf("pkcs11: invalid object handle %q", handle)
	}
	return keyID, nil
}

func (s *moduleSession) findObjectsByIDLocked(handle string, keyID []byte) (p11.ObjectHandle, p11.ObjectHandle, error) {
	find := func(class uint) (p11.ObjectHandle, error) {
		if err := s.ctx.FindObjectsInit(s.session, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_CLASS, class),
			p11.NewAttribute(p11.CKA_ID, keyID),
		}); err != nil {
			return 0, err
		}
		objects, _, findErr := s.ctx.FindObjects(s.session, 2)
		finalErr := s.ctx.FindObjectsFinal(s.session)
		if findErr != nil {
			return 0, findErr
		}
		if finalErr != nil {
			return 0, finalErr
		}
		if len(objects) > 1 {
			return 0, fmt.Errorf("pkcs11: object handle %q resolved to %d token objects", handle, len(objects))
		}
		if len(objects) == 0 {
			return 0, nil
		}
		return objects[0], nil
	}
	pub, err := find(p11.CKO_PUBLIC_KEY)
	if err != nil {
		return 0, 0, fmt.Errorf("pkcs11: resolve public object %q: %w", handle, err)
	}
	priv, err := find(p11.CKO_PRIVATE_KEY)
	if err != nil {
		return 0, 0, fmt.Errorf("pkcs11: resolve private object %q: %w", handle, err)
	}
	return pub, priv, nil
}

func rsaDigestInfo(hash crypto.Hash, digest []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var wantLen int
	switch hash {
	case "", crypto.SHA256:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
		wantLen = 32
	case crypto.SHA384:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
		wantLen = 48
	case crypto.SHA512:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
		wantLen = 64
	default:
		return nil, fmt.Errorf("pkcs11: unsupported hash %q", hash)
	}
	if len(digest) != wantLen {
		return nil, fmt.Errorf("pkcs11: %s digest length %d, want %d", hash, len(digest), wantLen)
	}
	return asn1.Marshal(struct {
		Algorithm pkixAlgorithmIdentifier
		Digest    []byte
	}{
		Algorithm: pkixAlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{Tag: 5}},
		Digest:    digest,
	})
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func (s *moduleSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if logoutErr := s.ctx.Logout(s.session); logoutErr != nil && !isPKCS11Error(logoutErr, p11.CKR_USER_NOT_LOGGED_IN) {
		err = errors.Join(err, fmt.Errorf("pkcs11: logout: %w", logoutErr))
	}
	if closeErr := s.ctx.CloseSession(s.session); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("pkcs11: close session: %w", closeErr))
	}
	if finalizeErr := s.ctx.Finalize(); finalizeErr != nil {
		err = errors.Join(err, fmt.Errorf("pkcs11: finalize module: %w", finalizeErr))
	}
	s.ctx.Destroy()
	s.handles = nil
	return err
}
