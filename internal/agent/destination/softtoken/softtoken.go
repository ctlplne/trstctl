// Package softtoken is an in-process, software PKCS#11 token used to exercise
// the PKCS#11 destination in tests and CI, where a real token (SoftHSM via CGO,
// or a hardware HSM) is unavailable. It models the part of the PKCS#11 object
// model the destination depends on: certificate and private-key objects keyed
// by label, and the access-control attributes (CKA_SENSITIVE, CKA_EXTRACTABLE,
// CKA_PRIVATE, CKA_TOKEN) that govern whether a key can leave the token.
//
// It deliberately enforces the custody invariant a real HSM enforces: an
// imported private key is sensitive and non-extractable, and there is no API to
// read its bytes back out. Stored PEM is copied in and out so callers cannot
// mutate token state through a shared slice. It holds no crypto/* imports.
package softtoken

import (
	"fmt"
	"sync"

	"certctl.io/certctl/internal/agent/destination"
)

// object classes (a subset of PKCS#11 CKO_* object classes).
type objectClass int

const (
	classCertificate objectClass = iota
	classPrivateKey
)

type object struct {
	class objectClass
	id    []byte
	pem   []byte
	attrs destination.KeyAttributes // meaningful for private-key objects
}

// Token is an in-process software token. The zero value is not usable; call New.
type Token struct {
	mu sync.RWMutex
	// objects keyed by label, then class — a label holds at most one cert and
	// one key object, matching how the destination stores a pair.
	objects map[string]map[objectClass]object
}

var _ destination.Token = (*Token)(nil)

// New returns an empty software token.
func New() *Token {
	return &Token{objects: make(map[string]map[objectClass]object)}
}

func (t *Token) put(label string, obj object) {
	if t.objects[label] == nil {
		t.objects[label] = make(map[objectClass]object)
	}
	t.objects[label][obj.class] = obj
}

// ImportKey stores keyPEM as a private-key object under (label, id) with the
// custody attributes a hardware token applies to an imported key: sensitive,
// non-extractable, private, and token-resident.
func (t *Token) ImportKey(label string, id []byte, keyPEM []byte) error {
	if len(keyPEM) == 0 {
		return fmt.Errorf("softtoken: empty key for label %q", label)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(label, object{
		class: classPrivateKey,
		id:    clone(id),
		pem:   clone(keyPEM),
		attrs: destination.KeyAttributes{Sensitive: true, Extractable: false, Private: true, Token: true},
	})
	return nil
}

// ImportCertificate stores certPEM as a certificate object under (label, id).
func (t *Token) ImportCertificate(label string, id []byte, certPEM []byte) error {
	if len(certPEM) == 0 {
		return fmt.Errorf("softtoken: empty certificate for label %q", label)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(label, object{class: classCertificate, id: clone(id), pem: clone(certPEM)})
	return nil
}

// FindCertificate returns a copy of the certificate object stored under label.
func (t *Token) FindCertificate(label string) ([]byte, bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	obj, ok := t.objects[label][classCertificate]
	if !ok {
		return nil, false, nil
	}
	return clone(obj.pem), true, nil
}

// KeyAttributes returns the access-control attributes of the private-key object
// under label. There is intentionally no method to read the key's value: a
// sensitive, non-extractable key cannot be exported from the token.
func (t *Token) KeyAttributes(label string) (destination.KeyAttributes, bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	obj, ok := t.objects[label][classPrivateKey]
	if !ok {
		return destination.KeyAttributes{}, false, nil
	}
	return obj.attrs, true, nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
