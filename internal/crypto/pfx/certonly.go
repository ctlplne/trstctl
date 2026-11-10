// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- legacy PKCS#12 files encrypt their certificate contents with 3DES; reading them needs it, and nothing here encrypts (CWE-327)
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1" // #nosec G505 -- the PKCS#12 KDF, legacy MACs and PBES2 default PRF are defined over SHA-1; this only verifies and decrypts existing files (CWE-328)
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

// A certificate-only PKCS#12 reader (X2-L3), written from RFC 7292 (PKCS #12),
// RFC 8018 (PBES2, PBKDF2), RFC 9579 (PBMAC1) and RFC 2268 (RC2). Inventory
// needs a file's certificates, never its key: the library decoder decrypts the
// key on the way to the certificates and leaves its own copies of the
// decrypted key in memory. This reader verifies the file's MAC with the
// password, decrypts only the encrypted contents that hold certificate bags,
// and never decrypts, parses or copies a key bag: it only notes that one is
// there and which certificate it belongs to (by localKeyId).

var (
	oidData                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidKeyBag                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Certificate       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidLocalKeyID            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidSHA1                  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidPBMAC1                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidPBES2                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA512        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC            = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidPBEWithSHA3KeyDESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHA128BitRC2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHA40BitRC2CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

// errNotCertificateOnly reports a PKCS#12 shape this reader does not handle
// (BER, a signed authSafe, enveloped contents, an unknown algorithm).
var errNotCertificateOnly = errors.New("pfx: unsupported PKCS#12 structure")

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type pfxPDU struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

type pbes2Params struct {
	KDF              algorithmIdentifier
	EncryptionScheme algorithmIdentifier
}

type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

type pbmac1Params struct {
	KDF    algorithmIdentifier
	MacAlg algorithmIdentifier
}

// strictUnmarshal decodes exactly one DER value.
func strictUnmarshal(in []byte, out any) error {
	rest, err := asn1.Unmarshal(in, out)
	if err != nil {
		return fmt.Errorf("%w: %v", errNotCertificateOnly, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("%w: trailing data", errNotCertificateOnly)
	}
	return nil
}

// bmpPassword is the password as PKCS #12 keys it: a big-endian UTF-16 string
// with a two-byte NUL terminator (RFC 7292 B.1).
func bmpPassword(password string) ([]byte, error) {
	out := make([]byte, 0, 2*len(password)+2)
	for _, r := range password {
		if r > 0xFFFF {
			return nil, errors.New("pfx: password character outside the Basic Multilingual Plane")
		}
		out = append(out, byte(r>>8), byte(r)) // #nosec G115 -- r is at most 0xFFFF here, so its two bytes are exact (CWE-190)
	}
	return append(out, 0, 0), nil
}

// pkcs12KDF is RFC 7292 Appendix B.2: derive size bytes for purpose id (1 key,
// 2 IV, 3 MAC key) from a BMP password and salt with hash h (block size v).
func pkcs12KDF(h func() hash.Hash, v int, salt, password []byte, iterations, id, size int) []byte {
	if iterations < 1 {
		iterations = 1
	}
	u := h().Size()
	d := bytes.Repeat([]byte{byte(id)}, v) // #nosec G115 -- id is the KDF purpose, 1 to 3 (CWE-190)
	fill := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		n := v * ((len(src) + v - 1) / v)
		out := make([]byte, n)
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	i := append(fill(salt), fill(password)...)
	out := make([]byte, 0, size+u)
	for len(out) < size {
		digest := h()
		digest.Write(d)
		digest.Write(i)
		a := digest.Sum(nil)
		for r := 1; r < iterations; r++ {
			digest = h()
			digest.Write(a)
			a = digest.Sum(nil)
		}
		out = append(out, a...)
		if len(out) >= size {
			break
		}
		b := make([]byte, v)
		for k := range b {
			b[k] = a[k%u]
		}
		for j := 0; j < len(i); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(i[j+k]) + int(b[k]) + carry
				i[j+k] = byte(sum) // #nosec G115 -- RFC 7292 B.2 adds modulo 2^(8v): keeping the low byte and carrying is the algorithm (CWE-190)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

func hashFor(oid asn1.ObjectIdentifier) (func() hash.Hash, int, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return sha1.New, 64, true
	case oid.Equal(oidSHA256):
		return sha256.New, 64, true
	case oid.Equal(oidSHA512):
		return sha512.New, 128, true
	}
	return nil, 0, false
}

func hmacFor(oid asn1.ObjectIdentifier, absentIsSHA1 bool) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidHMACWithSHA1), absentIsSHA1 && len(oid) == 0:
		return sha1.New, true
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New, true
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New, true
	}
	return nil, false
}

// verifyMAC checks the file's integrity MAC with the password, which is how a
// wrong password is told from a damaged file.
func verifyMAC(mac macData, message, bmp []byte, password string) error {
	var want []byte
	switch alg := mac.Mac.Algorithm.Algorithm; {
	case alg.Equal(oidPBMAC1):
		var params pbmac1Params
		if err := strictUnmarshal(mac.Mac.Algorithm.Parameters.FullBytes, &params); err != nil {
			return err
		}
		if !params.KDF.Algorithm.Equal(oidPBKDF2) {
			return fmt.Errorf("%w: PBMAC1 key derivation %s", errNotCertificateOnly, params.KDF.Algorithm)
		}
		var kdf pbkdf2Params
		if err := strictUnmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
			return err
		}
		prf, ok := hmacFor(kdf.PRF.Algorithm, true)
		macHash, macOK := hmacFor(params.MacAlg.Algorithm, false)
		if !ok || !macOK || kdf.Salt.Tag != asn1.TagOctetString {
			return fmt.Errorf("%w: PBMAC1 parameters", errNotCertificateOnly)
		}
		// RFC 9579: the key length is mandatory, and a short one would let a
		// forged file pass (the authentication bypass behind CVE-2026-34181).
		if kdf.KeyLength < 20 {
			return fmt.Errorf("%w: PBMAC1 key length %d is under 20 octets", errNotCertificateOnly, kdf.KeyLength)
		}
		key, err := pbkdf2.Key(prf, password, kdf.Salt.Bytes, kdf.Iterations, kdf.KeyLength)
		if err != nil {
			return err
		}
		m := hmac.New(macHash, key)
		m.Write(message)
		want = m.Sum(nil)
	default:
		h, v, ok := hashFor(alg)
		if !ok {
			return fmt.Errorf("%w: MAC digest %s", errNotCertificateOnly, alg)
		}
		key := pkcs12KDF(h, v, mac.MacSalt, bmp, mac.Iterations, 3, h().Size())
		m := hmac.New(h, key)
		m.Write(message)
		want = m.Sum(nil)
	}
	if !hmac.Equal(mac.Mac.Digest, want) {
		return ErrIncorrectPassword
	}
	return nil
}

// decryptContents decrypts one encryptedData content (which holds
// certificate bags in every file this reader accepts; key bags are shrouded
// separately and never reach here).
func decryptContents(alg algorithmIdentifier, ciphertext, bmp []byte, password string) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	switch {
	case alg.Algorithm.Equal(oidPBEWithSHA3KeyDESCBC), alg.Algorithm.Equal(oidPBEWithSHA128BitRC2), alg.Algorithm.Equal(oidPBEWithSHA40BitRC2CBC):
		var params pbeParams
		if err := strictUnmarshal(alg.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		iv = pkcs12KDF(sha1.New, 64, params.Salt, bmp, params.Iterations, 2, 8)
		var err error
		switch {
		case alg.Algorithm.Equal(oidPBEWithSHA3KeyDESCBC):
			block, err = des.NewTripleDESCipher(pkcs12KDF(sha1.New, 64, params.Salt, bmp, params.Iterations, 1, 24)) // #nosec G405 -- decrypting a legacy file's certificate contents only (CWE-327)
		case alg.Algorithm.Equal(oidPBEWithSHA128BitRC2):
			block, err = newRC2(pkcs12KDF(sha1.New, 64, params.Salt, bmp, params.Iterations, 1, 16), 128)
		default:
			block, err = newRC2(pkcs12KDF(sha1.New, 64, params.Salt, bmp, params.Iterations, 1, 5), 40)
		}
		if err != nil {
			return nil, err
		}
	case alg.Algorithm.Equal(oidPBES2):
		var params pbes2Params
		if err := strictUnmarshal(alg.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		if !params.KDF.Algorithm.Equal(oidPBKDF2) {
			return nil, fmt.Errorf("%w: PBES2 key derivation %s", errNotCertificateOnly, params.KDF.Algorithm)
		}
		var kdf pbkdf2Params
		if err := strictUnmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
			return nil, err
		}
		prf, ok := hmacFor(kdf.PRF.Algorithm, true)
		if !ok || kdf.Salt.Tag != asn1.TagOctetString {
			return nil, fmt.Errorf("%w: PBES2 PRF", errNotCertificateOnly)
		}
		var keyLen int
		var newBlock func([]byte) (cipher.Block, error)
		switch scheme := params.EncryptionScheme.Algorithm; {
		case scheme.Equal(oidAES128CBC):
			keyLen, newBlock = 16, aes.NewCipher
		case scheme.Equal(oidAES192CBC):
			keyLen, newBlock = 24, aes.NewCipher
		case scheme.Equal(oidAES256CBC):
			keyLen, newBlock = 32, aes.NewCipher
		case scheme.Equal(oidDESEDE3CBC):
			keyLen, newBlock = 24, des.NewTripleDESCipher
		default:
			return nil, fmt.Errorf("%w: PBES2 cipher %s", errNotCertificateOnly, scheme)
		}
		if kdf.KeyLength != 0 && kdf.KeyLength != keyLen {
			return nil, fmt.Errorf("%w: PBES2 key length %d", errNotCertificateOnly, kdf.KeyLength)
		}
		if err := strictUnmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
			return nil, err
		}
		// PBES2 inside PKCS #12 keys PBKDF2 with the UTF-8 password, as the
		// library decoder and OpenSSL do.
		key, err := pbkdf2.Key(prf, password, kdf.Salt.Bytes, kdf.Iterations, keyLen)
		if err != nil {
			return nil, err
		}
		if block, err = newBlock(key); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: content encryption %s", errNotCertificateOnly, alg.Algorithm)
	}
	size := block.BlockSize()
	if len(iv) != size || len(ciphertext) == 0 || len(ciphertext)%size != 0 {
		return nil, fmt.Errorf("%w: encrypted content shape", errNotCertificateOnly)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > size || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) { // #nosec G115 -- pad is at most the block size (CWE-190)
		return nil, errors.New("pfx: encrypted certificates do not decrypt")
	}
	return plain[:len(plain)-pad], nil
}

func localKeyID(attrs []pkcs12Attribute) []byte {
	for _, attr := range attrs {
		if !attr.ID.Equal(oidLocalKeyID) {
			continue
		}
		var id []byte
		if _, err := asn1.Unmarshal(attr.Value.Bytes, &id); err == nil {
			return id
		}
	}
	return nil
}

// certificatesOnly returns a PKCS#12 file's certificates as DER — the key's
// certificate first when the file says which it is — and whether it holds a
// key, without decrypting any key.
func certificatesOnly(pfxData []byte, password string) ([][]byte, bool, error) {
	var pdu pfxPDU
	if err := strictUnmarshal(pfxData, &pdu); err != nil {
		return nil, false, err
	}
	if pdu.Version != 3 || !pdu.AuthSafe.ContentType.Equal(oidData) {
		return nil, false, fmt.Errorf("%w: version %d, authSafe %s", errNotCertificateOnly, pdu.Version, pdu.AuthSafe.ContentType)
	}
	var authSafe []byte
	if err := strictUnmarshal(pdu.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, false, err
	}
	bmp, err := bmpPassword(password)
	if err != nil {
		return nil, false, err
	}
	if len(pdu.MacData.Mac.Algorithm.Algorithm) == 0 {
		// Without a MAC nothing checks the password; only the empty password
		// opens such a file, so any other is the wrong one (and a caller trying
		// several reaches the empty password).
		if password != "" {
			return nil, false, ErrIncorrectPassword
		}
	} else if err := verifyMAC(pdu.MacData, authSafe, bmp, password); err != nil {
		return nil, false, err
	}
	var contents []contentInfo
	if err := strictUnmarshal(authSafe, &contents); err != nil {
		return nil, false, err
	}
	var certs []bagCertificate
	var keyIDs [][]byte
	hasKey := false
	for _, ci := range contents {
		var safeContents []byte
		switch {
		case ci.ContentType.Equal(oidData):
			if err := strictUnmarshal(ci.Content.Bytes, &safeContents); err != nil {
				return nil, false, err
			}
		case ci.ContentType.Equal(oidEncryptedData):
			var ed encryptedData
			if err := strictUnmarshal(ci.Content.Bytes, &ed); err != nil {
				return nil, false, err
			}
			plain, err := decryptContents(ed.EncryptedContentInfo.ContentEncryptionAlgorithm, ed.EncryptedContentInfo.EncryptedContent, bmp, password)
			if err != nil {
				return nil, false, err
			}
			safeContents = plain
		default:
			return nil, false, fmt.Errorf("%w: authSafe content %s", errNotCertificateOnly, ci.ContentType)
		}
		var bags []safeBag
		if err := strictUnmarshal(safeContents, &bags); err != nil {
			return nil, false, err
		}
		for _, bag := range bags {
			switch {
			case bag.ID.Equal(oidCertBag):
				var cb certBag
				if err := strictUnmarshal(bag.Value.Bytes, &cb); err != nil {
					return nil, false, err
				}
				if !cb.ID.Equal(oidX509Certificate) {
					continue
				}
				if _, err := x509.ParseCertificate(cb.Data); err != nil {
					return nil, false, fmt.Errorf("pfx: certificate bag: %w", err)
				}
				certs = append(certs, bagCertificate{der: cb.Data, keyID: localKeyID(bag.Attributes)})
			case bag.ID.Equal(oidShroudedKeyBag), bag.ID.Equal(oidKeyBag):
				// Noted, never decrypted or parsed.
				hasKey = true
				if id := localKeyID(bag.Attributes); len(id) > 0 {
					keyIDs = append(keyIDs, id)
				}
			}
		}
	}
	if len(certs) == 0 {
		return nil, hasKey, errors.New("pfx: the file holds no certificate")
	}
	out := make([][]byte, 0, len(certs))
	first := keyCertificate(certs, keyIDs, hasKey)
	out = append(out, certs[first].der)
	for i, c := range certs {
		if i != first {
			out = append(out, c.der)
		}
	}
	return out, hasKey, nil
}

type bagCertificate struct {
	der   []byte
	keyID []byte
}

// keyCertificate picks the certificate that belongs to the file's key without
// reading the key: the one whose localKeyId matches a key bag's, as OpenSSL,
// Windows and Java write them; failing that, when there is a key, the first
// certificate that is not a CA; otherwise the first certificate.
func keyCertificate(certs []bagCertificate, keyIDs [][]byte, hasKey bool) int {
	for i, c := range certs {
		for _, id := range keyIDs {
			if len(c.keyID) > 0 && bytes.Equal(c.keyID, id) {
				return i
			}
		}
	}
	if hasKey {
		for i, c := range certs {
			if parsed, err := x509.ParseCertificate(c.der); err == nil && !parsed.IsCA {
				return i
			}
		}
	}
	return 0
}
