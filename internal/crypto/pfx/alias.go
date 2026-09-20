// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// SSLMate's Modern2023 encoder does not expose private-key friendlyName.
// This adapter edits only the authenticated metadata of its freshly generated
// shrouded key bag. Encrypted key bytes, encrypted certificates, localKeyId,
// salts, IVs and algorithms remain byte-identical. Java uses this key alias
// and the unchanged localKeyId to associate the leaf and complete chain.
// It is not a general PFX importer: only the exact Modern2023 layout is accepted.
// ASN.1 structures and the single-block MAC derivation follow RFC 7292 §§4–5
// and Appendix B. No encryption or private-key operation is reimplemented.
var (
	aliasOIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	aliasOIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	aliasOIDShroudedKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	aliasOIDFriendlyName  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	aliasOIDLocalKeyID    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	aliasOIDSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	errAliasLayout        = errors.New("pfx: alias requires the authenticated Modern2023 single-key layout")
)

type aliasContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}
type aliasDigestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}
type aliasMACData struct {
	MAC        aliasDigestInfo
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}
type aliasPFX struct {
	Version  int
	AuthSafe aliasContentInfo
	MACData  aliasMACData `asn1:"optional"`
}
type aliasAttribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue
}
type aliasBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue    `asn1:"tag:0,explicit"`
	Attributes []aliasAttribute `asn1:"set,optional"`
}

func javaAliasAttribute(alias string) (aliasAttribute, error) {
	if alias == "" || len(alias) > 1024 || !utf8.ValidString(alias) {
		return aliasAttribute{}, errors.New("pfx: alias must contain 1–1024 valid UTF-8 bytes")
	}
	var bmp []byte
	for _, r := range alias {
		if r == 0 || r > 0xffff {
			return aliasAttribute{}, errors.New("pfx: alias must use BMP characters without NUL")
		}
		bmp = append(bmp, byte((r>>8)&0xff), byte(r&0xff))
	}
	encoded, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: bmp})
	return aliasAttribute{ID: aliasOIDFriendlyName,
		Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: encoded}}, err
}

// ValidateJavaAlias checks the metadata representation before issuance. Empty
// means retain the legacy unnamed entry for callers that do not select an alias.
func ValidateJavaAlias(alias string) error {
	if alias == "" {
		return nil
	}
	_, err := javaAliasAttribute(alias)
	return err
}

func aliasUnmarshal(raw []byte, value any) error {
	rest, err := asn1.Unmarshal(raw, value)
	if err != nil || len(rest) != 0 {
		return errAliasLayout
	}
	return nil
}

func nameGeneratedKeyEntry(blob, password []byte, name aliasAttribute) ([]byte, error) {
	var pfx aliasPFX
	if err := aliasUnmarshal(blob, &pfx); err != nil {
		return nil, err
	}
	if pfx.Version != 3 || !pfx.AuthSafe.ContentType.Equal(aliasOIDData) ||
		!pfx.MACData.MAC.Algorithm.Algorithm.Equal(aliasOIDSHA256) ||
		pfx.MACData.Iterations != 2048 || len(pfx.MACData.Salt) != 16 ||
		len(pfx.MACData.MAC.Digest) != sha256.Size {
		return nil, errAliasLayout
	}
	var safeDER []byte
	if err := aliasUnmarshal(pfx.AuthSafe.Content.Bytes, &safeDER); err != nil {
		return nil, err
	}
	macKey, err := modern2023MACKey(password, pfx.MACData.Salt)
	if err != nil {
		return nil, err
	}
	defer macKey.Destroy()
	mac := hmac.New(sha256.New, macKey.Bytes())
	_, _ = mac.Write(safeDER)
	if !hmac.Equal(mac.Sum(nil), pfx.MACData.MAC.Digest) {
		return nil, errAliasLayout
	}
	var safes []aliasContentInfo
	if err := aliasUnmarshal(safeDER, &safes); err != nil {
		return nil, err
	}
	if len(safes) != 2 || !safes[0].ContentType.Equal(aliasOIDEncryptedData) || !safes[1].ContentType.Equal(aliasOIDData) {
		return nil, errAliasLayout
	}
	var bagsDER []byte
	if err := aliasUnmarshal(safes[1].Content.Bytes, &bagsDER); err != nil {
		return nil, err
	}
	var bags []aliasBag
	if err := aliasUnmarshal(bagsDER, &bags); err != nil {
		return nil, err
	}
	if len(bags) != 1 || !bags[0].ID.Equal(aliasOIDShroudedKey) || len(bags[0].Attributes) != 1 ||
		!bags[0].Attributes[0].ID.Equal(aliasOIDLocalKeyID) {
		return nil, errAliasLayout
	}
	bags[0].Attributes = append(bags[0].Attributes, name)
	bagsDER, err = asn1.Marshal(bags)
	if err != nil {
		return nil, err
	}
	encodedBags, err := asn1.Marshal(bagsDER)
	if err != nil {
		return nil, err
	}
	safes[1].Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encodedBags}
	safeDER, err = asn1.Marshal(safes)
	if err != nil {
		return nil, err
	}
	mac.Reset()
	_, _ = mac.Write(safeDER)
	pfx.MACData.MAC.Digest = mac.Sum(nil)
	encodedSafe, err := asn1.Marshal(safeDER)
	if err != nil {
		return nil, err
	}
	pfx.AuthSafe.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encodedSafe}
	return asn1.Marshal(pfx)
}

// modern2023MACKey implements only the one 32-byte block needed by HMAC-SHA256:
// SHA256 iterated 2048 times over D || S || P, where D is 64 bytes of 3 and S/P
// repeat to whole 64-byte blocks. P is the zero-terminated big-endian BMP password.
// General multi-block PKCS#12 derivation is deliberately absent. Secret buffers
// are locked and wiped; the password never becomes an immutable Go string.
func modern2023MACKey(password, salt []byte) (*secret.Buffer, error) {
	if len(salt) != 16 || !utf8.Valid(password) {
		return nil, errAliasLayout
	}
	pw, err := secret.New(2 * (utf8.RuneCount(password) + 1))
	if err != nil {
		return nil, err
	}
	defer pw.Destroy()
	for remaining, offset := password, 0; len(remaining) != 0; offset += 2 {
		r, size := utf8.DecodeRune(remaining)
		if r > 0xffff {
			return nil, errAliasLayout
		}
		pw.Bytes()[offset], pw.Bytes()[offset+1] = byte((r>>8)&0xff), byte(r&0xff)
		remaining = remaining[size:]
	}
	paddedPassword := (pw.Len() + 63) / 64 * 64
	input, err := secret.New(128 + paddedPassword)
	if err != nil {
		return nil, err
	}
	defer input.Destroy()
	copy(input.Bytes()[:64], bytes.Repeat([]byte{3}, 64))
	for i := 0; i < 64; i++ {
		input.Bytes()[64+i] = salt[i%len(salt)]
	}
	for i := 0; i < paddedPassword; i++ {
		input.Bytes()[128+i] = pw.Bytes()[i%pw.Len()]
	}
	sum := sha256.Sum256(input.Bytes())
	defer secret.Wipe(sum[:])
	for i := 1; i < 2048; i++ {
		sum = sha256.Sum256(sum[:])
	}
	return secret.NewFrom(sum[:])
}
