// SPDX-License-Identifier: MPL-2.0

package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"trstctl.com/clients/signing/trstctlsign"
)

// fakeAPI holds the keys trstctl's signer would hold and serves their chains.
type fakeAPI struct {
	token   string
	keys    map[string]crypto.Signer
	chains  map[string][]byte
	refuse  int
	signed  []string
	digests [][]byte
}

func (f *fakeAPI) KeyCertificate(_ context.Context, keyID string) (trstctlsign.KeyCertificate, error) {
	if f.refuse == 401 {
		return trstctlsign.KeyCertificate{}, &trstctlsign.APIError{Status: 401, Message: "invalid token"}
	}
	key, ok := f.keys[keyID]
	if !ok {
		return trstctlsign.KeyCertificate{}, &trstctlsign.APIError{Status: 404, Message: "no code-signing key with this id"}
	}
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	return trstctlsign.KeyCertificate{KeyID: keyID, PublicKeyDER: spki, ChainPEM: string(f.chains[keyID])}, nil
}

func (f *fakeAPI) SignDigest(_ context.Context, keyID, artifactType string, digest []byte) (trstctlsign.Signature, error) {
	if f.refuse != 0 {
		return trstctlsign.Signature{}, &trstctlsign.APIError{Status: f.refuse, Message: "approval_required:codesign:abc: the exact code-signing command awaits distinct approval"}
	}
	f.signed = append(f.signed, keyID+" "+artifactType)
	f.digests = append(f.digests, digest)
	switch key := f.keys[keyID].(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		return trstctlsign.Signature{Algorithm: "ECDSA-P256", Signature: sig}, err
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		return trstctlsign.Signature{Algorithm: "RSA-2048", Signature: sig}, err
	}
	return trstctlsign.Signature{}, &trstctlsign.APIError{Status: 404}
}

func chainFor(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test code-signing root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "release signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
}

func newTestToken(t *testing.T) (*Token, *fakeAPI, *bytes.Buffer) {
	t.Helper()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{token: "tok", keys: map[string]crypto.Signer{"ec-key": ecKey, "rsa-key": rsaKey, "bare-key": ecKey}}
	api.chains = map[string][]byte{"ec-key": chainFor(t, ecKey), "rsa-key": chainFor(t, rsaKey)}
	var log bytes.Buffer
	tok := New(Config{
		KeyIDs: []string{"ec-key", "rsa-key", "bare-key", "missing-key"},
		Connect: func(token string) (API, error) {
			if token != api.token {
				return &fakeAPI{refuse: 401}, nil
			}
			return api, nil
		},
		Log: &log,
	})
	return tok, api, &log
}

func find(t *testing.T, tok *Token, session uint64, template ...Attribute) []uint64 {
	t.Helper()
	if rv := tok.FindInit(session, template); rv != CKR_OK {
		t.Fatalf("FindInit = %#x", rv)
	}
	handles, rv := tok.Find(session, 100)
	if rv != CKR_OK {
		t.Fatalf("Find = %#x", rv)
	}
	if rv := tok.FindFinal(session); rv != CKR_OK {
		t.Fatalf("FindFinal = %#x", rv)
	}
	return handles
}

func attr(t *testing.T, tok *Token, session, handle, typ uint64) []byte {
	t.Helper()
	v, rv := tok.AttributeValue(session, handle, typ)
	if rv != CKR_OK {
		t.Fatalf("attribute %#x of %d = %#x", typ, handle, rv)
	}
	return v
}

// Login with the API token as the PIN offers each key that has a chain: a
// private-key handle, its public key and certificates, paired by CKA_ID; a
// key without a chain is skipped with a reason, and nothing is visible before
// login.
func TestLoginOffersKeysWithTheirChains(t *testing.T) {
	tok, _, log := newTestToken(t)
	session, rv := tok.OpenSession(CKF_SERIAL_SESSION)
	if rv != CKR_OK {
		t.Fatal(rv)
	}
	if got := find(t, tok, session); len(got) != 0 {
		t.Fatalf("objects before login: %v", got)
	}
	if rv := tok.Login(session, CKU_USER, []byte("wrong")); rv != CKR_PIN_INCORRECT {
		t.Fatalf("a wrong API token logged in: %#x", rv)
	}
	if rv := tok.Login(session, CKU_SO, []byte("tok")); rv != CKR_USER_TYPE_INVALID {
		t.Fatalf("security officer login = %#x", rv)
	}
	if rv := tok.Login(session, CKU_USER, []byte("tok")); rv != CKR_OK {
		t.Fatalf("login = %#x", rv)
	}
	if rv := tok.Login(session, CKU_USER, []byte("tok")); rv != CKR_USER_ALREADY_LOGGED_IN {
		t.Fatalf("second login = %#x", rv)
	}
	if !strings.Contains(log.String(), "bare-key is not offered") || !strings.Contains(log.String(), "missing-key is not offered") {
		t.Fatalf("skipped keys were not explained: %s", log)
	}
	privs := find(t, tok, session, Attribute{CKA_CLASS, ulong(CKO_PRIVATE_KEY)})
	certs := find(t, tok, session, Attribute{CKA_CLASS, ulong(CKO_CERTIFICATE)})
	if len(privs) != 2 || len(certs) != 4 {
		t.Fatalf("private keys %v, certificates %v", privs, certs)
	}
	ecPriv := find(t, tok, session, Attribute{CKA_CLASS, ulong(CKO_PRIVATE_KEY)}, Attribute{CKA_LABEL, []byte("ec-key")})
	if len(ecPriv) != 1 {
		t.Fatalf("ec-key private handle: %v", ecPriv)
	}
	id := attr(t, tok, session, ecPriv[0], CKA_ID)
	leaf := find(t, tok, session, Attribute{CKA_CLASS, ulong(CKO_CERTIFICATE)}, Attribute{CKA_ID, id})
	if len(leaf) != 1 {
		t.Fatalf("certificate paired with ec-key: %v", leaf)
	}
	if _, err := x509.ParseCertificate(attr(t, tok, session, leaf[0], CKA_VALUE)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(attr(t, tok, session, ecPriv[0], CKA_EC_PARAMS), []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}) {
		t.Fatal("ec-key's CKA_EC_PARAMS is not P-256")
	}
	if attr(t, tok, session, ecPriv[0], CKA_EXTRACTABLE)[0] != 0 || attr(t, tok, session, ecPriv[0], CKA_SENSITIVE)[0] != 1 {
		t.Fatal("the private-key handle claims to be extractable")
	}
	for _, secret := range []uint64{CKA_VALUE, CKA_PRIVATE_EXPONENT} {
		if _, rv := tok.AttributeValue(session, ecPriv[0], secret); rv != CKR_ATTRIBUTE_SENSITIVE {
			t.Fatalf("secret attribute %#x = %#x", secret, rv)
		}
	}
	if _, rv := tok.AttributeValue(session, ecPriv[0], 0x9999); rv != CKR_ATTRIBUTE_TYPE_INVALID {
		t.Fatalf("unknown attribute = %#x", rv)
	}
	if rv := tok.CloseSession(session); rv != CKR_OK {
		t.Fatal(rv)
	}
	again, _ := tok.OpenSession(CKF_SERIAL_SESSION)
	if got := find(t, tok, again); len(got) != 0 {
		t.Fatal("closing the last session did not log out")
	}
}

func loggedIn(t *testing.T) (*Token, *fakeAPI, uint64, *bytes.Buffer) {
	t.Helper()
	tok, api, log := newTestToken(t)
	session, _ := tok.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
	if rv := tok.Login(session, CKU_USER, []byte("tok")); rv != CKR_OK {
		t.Fatal(rv)
	}
	return tok, api, session, log
}

func keyHandle(t *testing.T, tok *Token, session uint64, label string) uint64 {
	t.Helper()
	got := find(t, tok, session, Attribute{CKA_CLASS, ulong(CKO_PRIVATE_KEY)}, Attribute{CKA_LABEL, []byte(label)})
	if len(got) != 1 {
		t.Fatalf("%s: %v", label, got)
	}
	return got[0]
}

// Each mechanism's signature verifies against the key's certificate, the
// mechanism is named in trstctl's request, and a length query signs nothing.
func TestSignaturesVerifyForEachMechanism(t *testing.T) {
	tok, api, session, _ := loggedIn(t)
	message := []byte("signed attributes")
	sum := sha256.Sum256(message)
	digestInfo := append(append([]byte(nil), sha256DigestInfo[0]...), sum[:]...)
	for _, tc := range []struct {
		key       string
		mechanism uint64
		input     []byte
		multipart bool
	}{
		{"ec-key", CKM_ECDSA, sum[:], false},
		{"ec-key", CKM_ECDSA_SHA256, message, false},
		{"ec-key", CKM_ECDSA_SHA256, message, true},
		{"rsa-key", CKM_RSA_PKCS, digestInfo, false},
		{"rsa-key", CKM_SHA256_RSA_PKCS, message, true},
	} {
		key := keyHandle(t, tok, session, tc.key)
		if rv := tok.SignInit(session, tc.mechanism, key); rv != CKR_OK {
			t.Fatalf("%s/%s SignInit = %#x", tc.key, MechanismName(tc.mechanism), rv)
		}
		before := len(api.signed)
		var sig []byte
		var needed int
		var rv uint64
		if tc.multipart {
			_ = tok.SignUpdate(session, tc.input[:5])
			_ = tok.SignUpdate(session, tc.input[5:])
			_, needed, rv = tok.SignFinal(session, 0, true)
			if rv != CKR_OK || len(api.signed) != before {
				t.Fatalf("a length query signed: %#x", rv)
			}
			if _, _, rv = tok.SignFinal(session, needed-1, false); rv != CKR_BUFFER_TOO_SMALL || len(api.signed) != before {
				t.Fatalf("a short buffer signed: %#x", rv)
			}
			sig, _, rv = tok.SignFinal(session, needed, false)
		} else {
			_, needed, rv = tok.Sign(session, tc.input, 0, true)
			if rv != CKR_OK || len(api.signed) != before {
				t.Fatalf("a length query signed: %#x", rv)
			}
			sig, _, rv = tok.Sign(session, tc.input, needed, false)
		}
		if rv != CKR_OK || len(sig) != needed || len(api.signed) != before+1 {
			t.Fatalf("%s/%s sign = %#x, %d bytes", tc.key, MechanismName(tc.mechanism), rv, len(sig))
		}
		if api.signed[before] != tc.key+" pkcs11:"+MechanismName(tc.mechanism) || !bytes.Equal(api.digests[before], sum[:]) {
			t.Fatalf("trstctl was asked %q for %x", api.signed[before], api.digests[before])
		}
		switch pub := api.keys[tc.key].Public().(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatalf("%s: r||s does not verify", MechanismName(tc.mechanism))
			}
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
				t.Fatalf("%s: %v", MechanismName(tc.mechanism), err)
			}
		}
		if _, _, rv := tok.Sign(session, tc.input, needed, false); rv != CKR_OPERATION_NOT_INITIALIZED {
			t.Fatalf("the operation outlived its signature: %#x", rv)
		}
	}
}

// What trstctl's signer cannot sign is refused before any request: a raw
// ECDSA hash that is not SHA-256, a DigestInfo for another hash, a mechanism
// for the other key type.
func TestRefusalsBeforeSigning(t *testing.T) {
	tok, api, session, _ := loggedIn(t)
	ec, rsaKey := keyHandle(t, tok, session, "ec-key"), keyHandle(t, tok, session, "rsa-key")
	if rv := tok.SignInit(session, CKM_RSA_PKCS, ec); rv != CKR_KEY_TYPE_INCONSISTENT {
		t.Fatalf("RSA mechanism on an EC key = %#x", rv)
	}
	if rv := tok.SignInit(session, 0x1042, ec); rv != CKR_MECHANISM_INVALID {
		t.Fatalf("an unknown mechanism = %#x", rv)
	}
	_ = tok.SignInit(session, CKM_ECDSA, ec)
	if _, _, rv := tok.Sign(session, make([]byte, 48), 64, false); rv != CKR_DATA_LEN_RANGE {
		t.Fatalf("a SHA-384 hash for CKM_ECDSA = %#x", rv)
	}
	_ = tok.SignInit(session, CKM_RSA_PKCS, rsaKey)
	sha1Info := append([]byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}, make([]byte, 20)...)
	if _, _, rv := tok.Sign(session, sha1Info, 256, false); rv != CKR_DATA_LEN_RANGE {
		t.Fatalf("a SHA-1 DigestInfo = %#x", rv)
	}
	_ = tok.SignInit(session, CKM_ECDSA, ec)
	if rv := tok.SignUpdate(session, []byte("x")); rv != CKR_FUNCTION_NOT_SUPPORTED {
		t.Fatalf("multi-part raw ECDSA = %#x", rv)
	}
	if len(api.signed) != 0 {
		t.Fatalf("a refused request reached trstctl: %v", api.signed)
	}
}

// A signature trstctl refuses — a missing permission, a pending or denied
// approval — is CKR_FUNCTION_REJECTED with the reason logged.
func TestADeniedSignatureIsRejected(t *testing.T) {
	tok, api, session, log := loggedIn(t)
	api.refuse = 403
	_ = tok.SignInit(session, CKM_ECDSA_SHA256, keyHandle(t, tok, session, "ec-key"))
	if _, _, rv := tok.Sign(session, []byte("artifact"), 64, false); rv != CKR_FUNCTION_REJECTED {
		t.Fatalf("a denied signature = %#x", rv)
	}
	if !strings.Contains(log.String(), "awaits distinct approval") {
		t.Fatalf("the reason was not logged: %s", log)
	}
	api.refuse = 503
	_ = tok.SignInit(session, CKM_ECDSA_SHA256, keyHandle(t, tok, session, "ec-key"))
	if _, _, rv := tok.Sign(session, []byte("artifact"), 64, false); rv != CKR_DEVICE_ERROR {
		t.Fatalf("an unavailable trstctl = %#x", rv)
	}
}

// A signature that does not verify against the key's certificate is never
// returned to the tool.
func TestASignatureFromAnotherKeyIsNotReturned(t *testing.T) {
	tok, api, session, _ := loggedIn(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	api.keys["ec-key"] = other
	_ = tok.SignInit(session, CKM_ECDSA_SHA256, keyHandle(t, tok, session, "ec-key"))
	if sig, _, rv := tok.Sign(session, []byte("artifact"), 64, false); rv != CKR_DEVICE_ERROR || sig != nil {
		t.Fatalf("a signature from another key = %#x", rv)
	}
}

func TestSessionsAndMechanisms(t *testing.T) {
	tok, _, _ := newTestToken(t)
	if _, rv := tok.OpenSession(0); rv != CKR_SESSION_PARALLEL_NOT_SUPPORTED {
		t.Fatalf("a non-serial session = %#x", rv)
	}
	s, _ := tok.OpenSession(CKF_SERIAL_SESSION)
	if state, _, rv := tok.SessionInfo(s); rv != CKR_OK || state != CKS_RO_PUBLIC_SESSION {
		t.Fatalf("state = %d %#x", state, rv)
	}
	_ = tok.Login(s, CKU_USER, []byte("tok"))
	if state, _, _ := tok.SessionInfo(s); state != CKS_RO_USER_FUNCTIONS {
		t.Fatalf("state after login = %d", state)
	}
	if rv := tok.SignInit(s+1, CKM_ECDSA, 1); rv != CKR_SESSION_HANDLE_INVALID {
		t.Fatalf("an unknown session = %#x", rv)
	}
	if rv := tok.Logout(s); rv != CKR_OK {
		t.Fatal(rv)
	}
	if rv := tok.SignInit(s, CKM_ECDSA, 1); rv != CKR_USER_NOT_LOGGED_IN {
		t.Fatalf("signing after logout = %#x", rv)
	}
	if min, max, flags, rv := MechanismInfo(CKM_SHA256_RSA_PKCS); rv != CKR_OK || min != 2048 || max != 4096 || flags&CKF_SIGN == 0 {
		t.Fatalf("RSA mechanism info = %d %d %#x %#x", min, max, flags, rv)
	}
	if _, _, _, rv := MechanismInfo(0x1042); rv != CKR_MECHANISM_INVALID {
		t.Fatal("an unknown mechanism has info")
	}
	if binary.NativeEndian.Uint64(ulong(CKO_PRIVATE_KEY)) != CKO_PRIVATE_KEY {
		t.Fatal("CK_ULONG encoding")
	}
}
