// SPDX-License-Identifier: MPL-2.0

// Package token is the PKCS #11 token behind libtrstctl-pkcs11: one slot whose
// objects are the code-signing keys an API token may use, each with the
// certificate chain trstctl serves for it. The private keys stay in trstctl's
// isolated signer — a private-key object here is a handle whose signatures
// come from the code-signing API — so no key material is ever in this process.
// The cgo adapter in ../../pkcs11 maps PKCS #11 calls onto this package.
package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"trstctl.com/clients/signing/trstctlsign"
)

// CKR_FUNCTION_REJECTED is PKCS #11's answer for a signature the user (here,
// trstctl's permissions, policy or an approver) refused.
const CKR_FUNCTION_REJECTED = 0x200

// API is what the token needs from trstctl's code-signing API.
type API interface {
	KeyCertificate(ctx context.Context, keyID string) (trstctlsign.KeyCertificate, error)
	SignDigest(ctx context.Context, keyID, artifactType string, digest []byte) (trstctlsign.Signature, error)
}

// Config names the keys the token offers and how to reach trstctl.
type Config struct {
	// KeyIDs are the code-signing keys to offer, each needing a configured
	// certificate chain.
	KeyIDs []string
	// Connect returns a client for an API token: the PIN given to C_Login.
	Connect func(apiToken string) (API, error)
	// Timeout bounds one call to trstctl; zero means two minutes.
	Timeout time.Duration
	// Log receives one line per refusal or skipped key, for the operator.
	Log io.Writer
}

// Attribute is one CK_ATTRIBUTE of a search template.
type Attribute struct {
	Type  uint64
	Value []byte
}

// Token is one slot's token. Its methods return PKCS #11 return values.
type Token struct {
	mu       sync.Mutex
	cfg      Config
	api      API
	loggedIn bool
	objects  []*object
	sessions map[uint64]*session
	next     uint64
}

type object struct {
	class   uint64
	keyID   string
	keyType uint64
	public  crypto.PublicKey
	sigLen  int
	attrs   map[uint64][]byte
}

type session struct {
	flags   uint64
	finding bool
	found   []uint64
	sign    *signOp
}

type signOp struct {
	mechanism uint64
	key       *object
	data      []byte
	multipart bool
}

// New returns a token with no session open.
func New(cfg Config) *Token {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	return &Token{cfg: cfg, sessions: map[uint64]*session{}}
}

// Mechanisms lists the signing mechanisms the token offers.
func Mechanisms() []uint64 {
	return []uint64{CKM_ECDSA, CKM_ECDSA_SHA256, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS}
}

// MechanismInfo returns a mechanism's key sizes (bits) and flags.
func MechanismInfo(mechanism uint64) (minBits, maxBits, flags, rv uint64) {
	switch mechanism {
	case CKM_ECDSA, CKM_ECDSA_SHA256:
		return 256, 256, CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS, CKR_OK
	case CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS:
		return 2048, 4096, CKF_SIGN, CKR_OK
	}
	return 0, 0, 0, CKR_MECHANISM_INVALID
}

// OpenSession opens a session; PKCS #11 requires the serial flag.
func (t *Token) OpenSession(flags uint64) (uint64, uint64) {
	if flags&CKF_SERIAL_SESSION == 0 {
		return 0, CKR_SESSION_PARALLEL_NOT_SUPPORTED
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	t.sessions[t.next] = &session{flags: flags}
	return t.next, CKR_OK
}

// CloseSession closes a session; closing the last one logs the user out.
func (t *Token) CloseSession(handle uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[handle]; !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	delete(t.sessions, handle)
	if len(t.sessions) == 0 {
		t.logout()
	}
	return CKR_OK
}

// CloseAllSessions closes every session and logs the user out.
func (t *Token) CloseAllSessions() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = map[uint64]*session{}
	t.logout()
	return CKR_OK
}

// SessionCount reports the open sessions and how many are read-write.
func (t *Token) SessionCount() (all, rw uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		all++
		if s.flags&CKF_RW_SESSION != 0 {
			rw++
		}
	}
	return all, rw
}

// SessionInfo returns a session's state and flags.
func (t *Token) SessionInfo(handle uint64) (state, flags, rv uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return 0, 0, CKR_SESSION_HANDLE_INVALID
	}
	rw := s.flags&CKF_RW_SESSION != 0
	switch {
	case t.loggedIn && rw:
		state = CKS_RW_USER_FUNCTIONS
	case t.loggedIn:
		state = CKS_RO_USER_FUNCTIONS
	case rw:
		state = CKS_RW_PUBLIC_SESSION
	default:
		state = CKS_RO_PUBLIC_SESSION
	}
	return state, s.flags, CKR_OK
}

// Login uses the PIN as the trstctl API token and loads the keys it may use.
func (t *Token) Login(handle, userType uint64, pin []byte) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[handle]; !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if userType != CKU_USER {
		return CKR_USER_TYPE_INVALID
	}
	if t.loggedIn {
		return CKR_USER_ALREADY_LOGGED_IN
	}
	if len(bytes.TrimSpace(pin)) == 0 || t.cfg.Connect == nil {
		return CKR_PIN_INCORRECT
	}
	api, err := t.cfg.Connect(string(pin))
	if err != nil {
		t.logf("connect: %v", err)
		return CKR_DEVICE_ERROR
	}
	var objects []*object
	for _, keyID := range t.cfg.KeyIDs {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
		cert, err := api.KeyCertificate(ctx, keyID)
		cancel()
		var refused *trstctlsign.APIError
		if errors.As(err, &refused) && (refused.Status == 401 || refused.Status == 403) {
			t.logf("key %s: %v", keyID, err)
			return CKR_PIN_INCORRECT
		}
		if err != nil {
			t.logf("key %s is not offered: %v", keyID, err)
			continue
		}
		keyObjects, err := keyObjectsFor(keyID, cert)
		if err != nil {
			t.logf("key %s is not offered: %v", keyID, err)
			continue
		}
		objects = append(objects, keyObjects...)
	}
	t.api, t.objects, t.loggedIn = api, objects, true
	return CKR_OK
}

// Logout forgets the API token and the keys.
func (t *Token) Logout(handle uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[handle]; !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if !t.loggedIn {
		return CKR_USER_NOT_LOGGED_IN
	}
	t.logout()
	return CKR_OK
}

func (t *Token) logout() {
	t.api, t.objects, t.loggedIn = nil, nil, false
	for _, s := range t.sessions {
		s.sign, s.finding, s.found = nil, false, nil
	}
}

// FindInit starts a search for objects matching every attribute of template.
func (t *Token) FindInit(handle uint64, template []Attribute) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if s.finding {
		return CKR_OPERATION_ACTIVE
	}
	s.finding, s.found = true, nil
	for i, obj := range t.objects {
		if obj.matches(template) {
			s.found = append(s.found, uint64(i+1))
		}
	}
	return CKR_OK
}

// Find returns up to max handles of the active search.
func (t *Token) Find(handle uint64, max int) ([]uint64, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}
	if !s.finding {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}
	if max > len(s.found) {
		max = len(s.found)
	}
	out := s.found[:max]
	s.found = s.found[max:]
	return out, CKR_OK
}

// FindFinal ends the active search.
func (t *Token) FindFinal(handle uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if !s.finding {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	s.finding, s.found = false, nil
	return CKR_OK
}

// AttributeValue returns one attribute of an object. A private key's secret
// parts are CKR_ATTRIBUTE_SENSITIVE: they are not in this process at all.
func (t *Token) AttributeValue(handle, objectHandle, attribute uint64) ([]byte, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[handle]; !ok {
		return nil, CKR_SESSION_HANDLE_INVALID
	}
	obj := t.object(objectHandle)
	if obj == nil {
		return nil, CKR_OBJECT_HANDLE_INVALID
	}
	if v, ok := obj.attrs[attribute]; ok {
		return v, CKR_OK
	}
	if obj.class == CKO_PRIVATE_KEY && sensitiveAttribute(attribute) {
		return nil, CKR_ATTRIBUTE_SENSITIVE
	}
	return nil, CKR_ATTRIBUTE_TYPE_INVALID
}

func sensitiveAttribute(attribute uint64) bool {
	switch attribute {
	case CKA_VALUE, CKA_PRIVATE_EXPONENT, 0x124, 0x125, 0x126, 0x127, 0x128: // value, d, p, q, dP, dQ, qInv
		return true
	}
	return false
}

// SignInit starts a signature with a private-key object.
func (t *Token) SignInit(handle, mechanism, keyHandle uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if !t.loggedIn {
		return CKR_USER_NOT_LOGGED_IN
	}
	if s.sign != nil {
		return CKR_OPERATION_ACTIVE
	}
	key := t.object(keyHandle)
	if key == nil || key.class != CKO_PRIVATE_KEY {
		return CKR_KEY_HANDLE_INVALID
	}
	switch mechanism {
	case CKM_ECDSA, CKM_ECDSA_SHA256:
		if key.keyType != CKK_EC {
			return CKR_KEY_TYPE_INCONSISTENT
		}
	case CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS:
		if key.keyType != CKK_RSA {
			return CKR_KEY_TYPE_INCONSISTENT
		}
	default:
		return CKR_MECHANISM_INVALID
	}
	s.sign = &signOp{mechanism: mechanism, key: key}
	return CKR_OK
}

// SignUpdate adds data to a multi-part signature (hash-and-sign mechanisms).
func (t *Token) SignUpdate(handle uint64, data []byte) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return CKR_SESSION_HANDLE_INVALID
	}
	if s.sign == nil {
		return CKR_OPERATION_NOT_INITIALIZED
	}
	if s.sign.mechanism != CKM_ECDSA_SHA256 && s.sign.mechanism != CKM_SHA256_RSA_PKCS {
		s.sign = nil
		return CKR_FUNCTION_NOT_SUPPORTED
	}
	s.sign.multipart = true
	s.sign.data = append(s.sign.data, data...)
	return CKR_OK
}

// Sign signs data in one part. With query set (a NULL output buffer) it only
// reports the signature's length; a buffer smaller than capacity needs gets
// CKR_BUFFER_TOO_SMALL. In both cases the operation stays active and nothing
// is signed, as PKCS #11 specifies.
func (t *Token) Sign(handle uint64, data []byte, capacity int, query bool) ([]byte, int, uint64) {
	return t.finish(handle, data, capacity, query, false)
}

// SignFinal finishes a multi-part signature, with Sign's length rules.
func (t *Token) SignFinal(handle uint64, capacity int, query bool) ([]byte, int, uint64) {
	return t.finish(handle, nil, capacity, query, true)
}

func (t *Token) finish(handle uint64, data []byte, capacity int, query, final bool) ([]byte, int, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[handle]
	if !ok {
		return nil, 0, CKR_SESSION_HANDLE_INVALID
	}
	op := s.sign
	if op == nil {
		return nil, 0, CKR_OPERATION_NOT_INITIALIZED
	}
	if final != op.multipart && !(final && len(op.data) == 0) {
		s.sign = nil
		return nil, 0, CKR_FUNCTION_FAILED
	}
	needed := op.key.sigLen
	if query {
		return nil, needed, CKR_OK
	}
	if capacity < needed {
		return nil, needed, CKR_BUFFER_TOO_SMALL
	}
	s.sign = nil
	if !final {
		op.data = data
	}
	digest, rv := digestFor(op.mechanism, op.data)
	if rv != CKR_OK {
		return nil, needed, rv
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.Timeout)
	defer cancel()
	signed, err := t.api.SignDigest(ctx, op.key.keyID, "pkcs11:"+MechanismName(op.mechanism), digest)
	if err != nil {
		t.logf("sign with %s: %v", op.key.keyID, err)
		var refused *trstctlsign.APIError
		if errors.As(err, &refused) && refused.Denied() {
			return nil, needed, CKR_FUNCTION_REJECTED
		}
		return nil, needed, CKR_DEVICE_ERROR
	}
	out, err := op.key.finishSignature(digest, signed.Signature)
	if err != nil {
		t.logf("sign with %s: %v", op.key.keyID, err)
		return nil, needed, CKR_DEVICE_ERROR
	}
	return out, needed, CKR_OK
}

// sha256DigestInfo prefixes are the DER DigestInfo for SHA-256, with and
// without the NULL parameters, that CKM_RSA_PKCS callers pass in.
var sha256DigestInfo = [][]byte{
	{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20},
}

// digestFor returns the SHA-256 digest trstctl signs for a mechanism's input.
// trstctl's code-signing keys sign SHA-256 digests, so a raw mechanism must be
// given one.
func digestFor(mechanism uint64, data []byte) ([]byte, uint64) {
	switch mechanism {
	case CKM_ECDSA:
		if len(data) != sha256.Size {
			return nil, CKR_DATA_LEN_RANGE
		}
		return append([]byte(nil), data...), CKR_OK
	case CKM_RSA_PKCS:
		for _, prefix := range sha256DigestInfo {
			if len(data) == len(prefix)+sha256.Size && bytes.HasPrefix(data, prefix) {
				return append([]byte(nil), data[len(prefix):]...), CKR_OK
			}
		}
		return nil, CKR_DATA_LEN_RANGE
	case CKM_ECDSA_SHA256, CKM_SHA256_RSA_PKCS:
		sum := sha256.Sum256(data)
		return sum[:], CKR_OK
	}
	return nil, CKR_MECHANISM_INVALID
}

// finishSignature checks trstctl's signature against the key's certificate
// and returns it in PKCS #11's form: r||s for ECDSA, as-is for RSA.
func (o *object) finishSignature(digest, signature []byte) ([]byte, error) {
	switch pub := o.public.(type) {
	case *ecdsa.PublicKey:
		var sig struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(signature, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
			return nil, errors.New("trstctl returned a signature that is not an ASN.1 ECDSA signature")
		}
		if !ecdsa.Verify(pub, digest, sig.R, sig.S) {
			return nil, errors.New("trstctl's signature does not verify against the key's certificate")
		}
		size := o.sigLen / 2
		out := make([]byte, o.sigLen)
		sig.R.FillBytes(out[:size])
		sig.S.FillBytes(out[size:])
		return out, nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, signature); err != nil {
			return nil, errors.New("trstctl's signature does not verify against the key's certificate")
		}
		return signature, nil
	}
	return nil, errors.New("unsupported key")
}

func (t *Token) object(handle uint64) *object {
	if handle == 0 || handle > uint64(len(t.objects)) {
		return nil
	}
	return t.objects[handle-1]
}

func (o *object) matches(template []Attribute) bool {
	for _, want := range template {
		got, ok := o.attrs[want.Type]
		if !ok || !bytes.Equal(got, want.Value) {
			return false
		}
	}
	return true
}

func (t *Token) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(t.cfg.Log, "trstctl-pkcs11: "+format+"\n", args...)
}

// keyObjectsFor builds a key's objects from the chain trstctl serves: the
// private-key handle, its public key, the leaf certificate (sharing CKA_ID and
// CKA_LABEL with the keys, as tools pair them) and the rest of the chain.
func keyObjectsFor(keyID string, cert trstctlsign.KeyCertificate) ([]*object, error) {
	chain := cert.ChainDER()
	if len(chain) == 0 {
		return nil, errors.New("no certificate chain is configured for this key")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("leaf certificate: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(spki, cert.PublicKeyDER) {
		return nil, errors.New("the leaf certificate does not name this key")
	}
	id := sha256.Sum256(spki)
	label := []byte(keyID)
	common := func(class uint64) map[uint64][]byte {
		return map[uint64][]byte{
			CKA_CLASS: ulong(class), CKA_TOKEN: boolean(true), CKA_MODIFIABLE: boolean(false),
			CKA_LABEL: label, CKA_ID: id[:20],
		}
	}
	priv := &object{class: CKO_PRIVATE_KEY, keyID: keyID, public: leaf.PublicKey, attrs: common(CKO_PRIVATE_KEY)}
	pub := &object{class: CKO_PUBLIC_KEY, keyID: keyID, public: leaf.PublicKey, attrs: common(CKO_PUBLIC_KEY)}
	for k, v := range map[uint64][]byte{
		CKA_PRIVATE: boolean(true), CKA_SIGN: boolean(true), CKA_SENSITIVE: boolean(true),
		CKA_EXTRACTABLE: boolean(false), CKA_ALWAYS_SENSITIVE: boolean(true), CKA_NEVER_EXTRACTABLE: boolean(true),
		CKA_DECRYPT: boolean(false), CKA_UNWRAP: boolean(false), CKA_DERIVE: boolean(false),
		CKA_SIGN_RECOVER: boolean(false), CKA_ALWAYS_AUTHENTICATE: boolean(false), CKA_LOCAL: boolean(false),
		CKA_SUBJECT: leaf.RawSubject,
	} {
		priv.attrs[k] = v
	}
	for k, v := range map[uint64][]byte{
		CKA_PRIVATE: boolean(false), CKA_VERIFY: boolean(true), CKA_ENCRYPT: boolean(false),
		CKA_WRAP: boolean(false), CKA_VERIFY_RECOVER: boolean(false), CKA_SUBJECT: leaf.RawSubject,
		CKA_VALUE: spki,
	} {
		pub.attrs[k] = v
	}
	switch key := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("only ECDSA P-256 keys are offered")
		}
		point, err := key.ECDH()
		if err != nil {
			return nil, err
		}
		params, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
		encodedPoint, _ := asn1.Marshal(point.Bytes())
		for _, o := range []*object{priv, pub} {
			o.keyType, o.sigLen = CKK_EC, 64
			o.attrs[CKA_KEY_TYPE], o.attrs[CKA_EC_PARAMS] = ulong(CKK_EC), params
		}
		// The point is public; libp11 reads it from the private-key object.
		pub.attrs[CKA_EC_POINT], priv.attrs[CKA_EC_POINT] = encodedPoint, encodedPoint
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if bits < 2048 {
			return nil, errors.New("RSA keys under 2048 bits are not offered")
		}
		for _, o := range []*object{priv, pub} {
			o.keyType, o.sigLen = CKK_RSA, (bits+7)/8
			o.attrs[CKA_KEY_TYPE] = ulong(CKK_RSA)
			o.attrs[CKA_MODULUS] = key.N.Bytes()
			o.attrs[CKA_PUBLIC_EXPONENT] = big.NewInt(int64(key.E)).Bytes()
		}
		pub.attrs[CKA_MODULUS_BITS] = ulong(uint64(bits))
	default:
		return nil, errors.New("unsupported key type")
	}
	objects := []*object{priv, pub}
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("chain certificate %d: %w", i, err)
		}
		serial, _ := asn1.Marshal(c.SerialNumber)
		attrs := common(CKO_CERTIFICATE)
		if i > 0 {
			sum := sha256.Sum256(der)
			attrs[CKA_ID], attrs[CKA_LABEL] = sum[:20], []byte(fmt.Sprintf("%s chain %d", keyID, i))
		}
		for k, v := range map[uint64][]byte{
			CKA_PRIVATE: boolean(false), CKA_CERTIFICATE_TYPE: ulong(CKC_X_509), CKA_TRUSTED: boolean(false),
			CKA_VALUE: der, CKA_SUBJECT: c.RawSubject, CKA_ISSUER: c.RawIssuer, CKA_SERIAL_NUMBER: serial,
		} {
			attrs[k] = v
		}
		objects = append(objects, &object{class: CKO_CERTIFICATE, keyID: keyID, attrs: attrs})
	}
	return objects, nil
}

// ulong encodes a CK_ULONG. The module is built for LP64 Linux and macOS,
// where CK_ULONG is a 64-bit unsigned long; the adapter checks that at load.
func ulong(v uint64) []byte {
	return binary.NativeEndian.AppendUint64(nil, v)
}

func boolean(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
