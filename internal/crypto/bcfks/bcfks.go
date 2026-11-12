// SPDX-License-Identifier: BUSL-1.1

// Package bcfks reads a Bouncy Castle FIPS keystore (BCFKS) for inventory
// (X2-L2), written from its ASN.1 module and checked against stores the
// Bouncy Castle provider writes through keytool. A BCFKS store is a DER
// ObjectStore: its ObjectStoreData encrypted under a key derived from the
// store password (PBES2: PBKDF2 and AES-CCM), and an integrity check (an
// HMAC under another password-derived key). Each derivation hashes the
// password and a purpose ("STORE_ENCRYPTION", "INTEGRITY_CHECK"), both as
// PKCS#12 BMP strings. Inside, each object is a certificate, a private key
// (an encrypted PKCS#8 key followed by its certificate chain in the clear) or
// a secret key. Only the store is decrypted, to reach the certificates; a
// private or secret key is never decrypted.
package bcfks

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 7}
	oidAES192CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 27}
	oidAES256CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 47}
)

const (
	purposeStore     = "STORE_ENCRYPTION"
	purposeIntegrity = "INTEGRITY_CHECK"

	// maxIterations bounds a key derivation a store asks for, so a hostile
	// file in an inventoried path cannot keep the agent hashing; the
	// provider writes 51,200 (16,384 in FIPS mode's minimum).
	maxIterations = 1 << 22
	maxSaltBytes  = 1024
	maxEntries    = 4096

	// Object types (BCFKS ObjectData.type).
	typeCertificate         = 0
	typePrivateKey          = 1
	typeSecretKey           = 2
	typeProtectedPrivateKey = 3
	typeProtectedSecretKey  = 4
)

// ErrIncorrectPassword reports a password that does not open the store.
var ErrIncorrectPassword = errors.New("bcfks: the password does not open this keystore")

// errUnsupported reports a BCFKS shape this reader does not handle.
var errUnsupported = errors.New("bcfks: unsupported keystore structure")

// Entry is one object of a BCFKS store: a key entry with its certificate
// chain (leaf first), a trusted certificate, or a secret key by alias.
type Entry struct {
	Alias     string
	KeyEntry  bool
	SecretKey bool
	ChainDER  [][]byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type objectStore struct {
	StoreData      asn1.RawValue
	IntegrityCheck asn1.RawValue
}

type encryptedObjectStoreData struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedContent    []byte
}

type pbkdMacIntegrityCheck struct {
	MacAlgorithm  algorithmIdentifier
	PbkdAlgorithm algorithmIdentifier
	Mac           []byte
}

type pbes2Params struct {
	KDF              algorithmIdentifier
	EncryptionScheme algorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

type ccmParams struct {
	Nonce  []byte
	ICVLen int `asn1:"optional,default:12"`
}

type objectStoreData struct {
	Version            int
	IntegrityAlgorithm algorithmIdentifier
	CreationDate       asn1.RawValue
	LastModifiedDate   asn1.RawValue
	ObjectDataSequence []objectData
	Comment            asn1.RawValue `asn1:"optional"`
}

type objectData struct {
	Type             int
	Identifier       string `asn1:"utf8"`
	CreationDate     asn1.RawValue
	LastModifiedDate asn1.RawValue
	Data             []byte
	Comment          asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyData struct {
	EncryptedPrivateKeyInfo asn1.RawValue
	Certificates            []asn1.RawValue
}

// IsBCFKS reports whether data is shaped like a BCFKS store: a DER SEQUENCE
// whose first element is a SEQUENCE. A PKCS#12 file's first element is its
// version INTEGER.
func IsBCFKS(data []byte) bool {
	var store objectStore
	rest, err := asn1.Unmarshal(data, &store)
	return err == nil && len(rest) == 0 && store.StoreData.Tag == asn1.TagSequence && store.StoreData.IsCompound
}

// Entries opens a BCFKS store with password: it checks the store's integrity
// MAC, decrypts the store and lists its objects. A wrong password returns
// ErrIncorrectPassword. No key is decrypted.
func Entries(data, password []byte) ([]Entry, error) {
	var store objectStore
	if rest, err := asn1.Unmarshal(data, &store); err != nil || len(rest) != 0 {
		return nil, errors.New("bcfks: not a BCFKS keystore")
	}
	var check pbkdMacIntegrityCheck
	if rest, err := asn1.Unmarshal(store.IntegrityCheck.FullBytes, &check); err != nil || len(rest) != 0 {
		// A signature-checked store ([0] SignatureCheck) is not read.
		return nil, fmt.Errorf("%w: integrity check", errUnsupported)
	}
	macKey, err := deriveKey(check.PbkdAlgorithm, password, purposeIntegrity, 0)
	if err != nil {
		return nil, err
	}
	h, err := hmacHash(check.MacAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(h, macKey)
	mac.Write(store.StoreData.FullBytes)
	if subtle.ConstantTimeCompare(mac.Sum(nil), check.Mac) != 1 {
		return nil, ErrIncorrectPassword
	}
	plain, err := openStore(store.StoreData.FullBytes, password)
	if err != nil {
		return nil, err
	}
	return objects(plain)
}

// openStore returns the store's ObjectStoreData: decrypted when the store is
// encrypted (PBES2 with PBKDF2 and AES-CCM), as it is when it is not.
func openStore(storeData, password []byte) ([]byte, error) {
	var enc encryptedObjectStoreData
	if rest, err := asn1.Unmarshal(storeData, &enc); err != nil || len(rest) != 0 {
		return storeData, nil // a plain ObjectStoreData
	}
	if !enc.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("%w: store encryption %s", errUnsupported, enc.EncryptionAlgorithm.Algorithm)
	}
	var params pbes2Params
	if rest, err := asn1.Unmarshal(enc.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: store encryption parameters", errUnsupported)
	}
	var keyBytes int
	switch scheme := params.EncryptionScheme.Algorithm; {
	case scheme.Equal(oidAES128CCM):
		keyBytes = 16
	case scheme.Equal(oidAES192CCM):
		keyBytes = 24
	case scheme.Equal(oidAES256CCM):
		keyBytes = 32
	default:
		return nil, fmt.Errorf("%w: store cipher %s", errUnsupported, scheme)
	}
	var ccm ccmParams
	if rest, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &ccm); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: CCM parameters", errUnsupported)
	}
	key, err := deriveKey(params.KDF, password, purposeStore, keyBytes)
	if err != nil {
		return nil, err
	}
	if len(key) != keyBytes {
		return nil, fmt.Errorf("%w: a %d-byte key for a %d-byte cipher", errUnsupported, len(key), keyBytes)
	}
	plain, err := ccmOpen(key, ccm.Nonce, enc.EncryptedContent, ccm.ICVLen)
	if err != nil {
		return nil, ErrIncorrectPassword
	}
	return plain, nil
}

// objects lists the decrypted store's objects.
func objects(plain []byte) ([]Entry, error) {
	var data objectStoreData
	if rest, err := asn1.Unmarshal(plain, &data); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: store data", errUnsupported)
	}
	if len(data.ObjectDataSequence) > maxEntries {
		return nil, fmt.Errorf("bcfks: the store holds %d objects", len(data.ObjectDataSequence))
	}
	entries := make([]Entry, 0, len(data.ObjectDataSequence))
	for _, object := range data.ObjectDataSequence {
		entry := Entry{Alias: object.Identifier}
		switch object.Type {
		case typeCertificate:
			entry.ChainDER = [][]byte{object.Data}
		case typePrivateKey, typeProtectedPrivateKey:
			var key encryptedPrivateKeyData
			if rest, err := asn1.Unmarshal(object.Data, &key); err != nil || len(rest) != 0 {
				return nil, fmt.Errorf("%w: private key entry %q", errUnsupported, object.Identifier)
			}
			entry.KeyEntry = true
			for _, cert := range key.Certificates {
				entry.ChainDER = append(entry.ChainDER, cert.FullBytes)
			}
		case typeSecretKey, typeProtectedSecretKey:
			entry.SecretKey = true
		default:
			return nil, fmt.Errorf("%w: object type %d", errUnsupported, object.Type)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// deriveKey derives a store key: PBKDF2 over the password and the purpose,
// each a PKCS#12 BMP string (UTF-16BE with a terminating zero).
func deriveKey(kdf algorithmIdentifier, password []byte, purpose string, defaultBytes int) ([]byte, error) {
	if !kdf.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("%w: key derivation %s", errUnsupported, kdf.Algorithm)
	}
	var params pbkdf2Params
	if rest, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: PBKDF2 parameters", errUnsupported)
	}
	if params.Iterations < 1 || params.Iterations > maxIterations || len(params.Salt) == 0 || len(params.Salt) > maxSaltBytes {
		return nil, fmt.Errorf("%w: PBKDF2 with %d iterations and a %d-byte salt", errUnsupported, params.Iterations, len(params.Salt))
	}
	size := params.KeyLength
	if size == 0 {
		size = defaultBytes
	}
	if size < 16 || size > 64 {
		return nil, fmt.Errorf("%w: a %d-byte derived key", errUnsupported, size)
	}
	h, err := hmacHash(params.PRF.Algorithm)
	if err != nil {
		return nil, err
	}
	secret := append(bmpString(string(password)), bmpString(purpose)...)
	return pbkdf2.Key(h, string(secret), params.Salt, params.Iterations, size)
}

func hmacHash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case oid.Equal(oidHMACSHA256):
		return sha256.New, nil
	case oid.Equal(oidHMACSHA384):
		return sha512.New384, nil
	case oid.Equal(oidHMACSHA512):
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: MAC %s", errUnsupported, oid)
}

// bmpString is s as a PKCS#12 BMP string: UTF-16BE code units and a
// terminating zero unit.
func bmpString(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u&0xff)) // #nosec G115 -- splitting a UTF-16 code unit into its two bytes (CWE-190)
	}
	return append(out, 0, 0)
}

// ccmOpen decrypts and authenticates AES-CCM (NIST SP 800-38C) without
// associated data: a nonce of 7 to 13 bytes and a tag of 4 to 16 even bytes.
func ccmOpen(key, nonce, sealed []byte, tagLen int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) < 7 || len(nonce) > 13 || tagLen < 4 || tagLen > 16 || tagLen%2 != 0 || len(sealed) < tagLen {
		return nil, errors.New("bcfks: unusable CCM parameters")
	}
	lenBytes := 15 - len(nonce) // the length field's size, L
	body, tag := sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:]
	if lenBytes < 8 && uint64(len(body)) >= uint64(1)<<(8*lenBytes) {
		return nil, errors.New("bcfks: CCM message too long for its nonce")
	}
	counter := func(i int) []byte {
		a := make([]byte, aes.BlockSize)
		a[0] = byte(lenBytes - 1) // #nosec G115 -- the CCM length field size L is 2..8 (CWE-190)
		copy(a[1:], nonce)
		for j, v := 0, i; j < lenBytes; j, v = j+1, v>>8 {
			a[aes.BlockSize-1-j] = byte(v & 0xff) // #nosec G115 -- one byte of a bounded block counter (CWE-190)
		}
		return a
	}
	plain := make([]byte, len(body))
	stream := make([]byte, aes.BlockSize)
	for off := 0; off < len(body); off += aes.BlockSize {
		block.Encrypt(stream, counter(off/aes.BlockSize+1))
		for j := off; j < len(body) && j < off+aes.BlockSize; j++ {
			plain[j] = body[j] ^ stream[j-off]
		}
	}
	// CBC-MAC over B0 (flags, nonce, message length) and the message.
	b0 := make([]byte, aes.BlockSize)
	b0[0] = byte((tagLen-2)/2<<3 | (lenBytes - 1)) // #nosec G115 -- flags from a bounded tag length and L (CWE-190)
	copy(b0[1:], nonce)
	for j, v := 0, len(plain); j < lenBytes; j, v = j+1, v>>8 {
		b0[aes.BlockSize-1-j] = byte(v & 0xff) // #nosec G115 -- one byte of the bounded message length (CWE-190)
	}
	x := make([]byte, aes.BlockSize)
	block.Encrypt(x, b0)
	for off := 0; off < len(plain); off += aes.BlockSize {
		for j := off; j < len(plain) && j < off+aes.BlockSize; j++ {
			x[j-off] ^= plain[j]
		}
		block.Encrypt(x, x)
	}
	s0 := make([]byte, aes.BlockSize)
	block.Encrypt(s0, counter(0))
	expected := make([]byte, tagLen)
	for j := range expected {
		expected[j] = x[j] ^ s0[j]
	}
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		clear(plain)
		return nil, errors.New("bcfks: CCM authentication failed")
	}
	return plain, nil
}
