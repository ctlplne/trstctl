// SPDX-License-Identifier: BUSL-1.1

package jks

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- a JCEKS keystore's integrity digest is defined over SHA-1; this only verifies existing files (CWE-328)
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"
)

// A JCEKS keystore reader for inventory (X2-L2), written from the format the
// JDK's JCEKS keystore writes: the magic 0xCECECECE, a version (1, or 2 when
// certificates carry their type), an entry count, then per entry a tag
// (1 private key, 2 trusted certificate, 3 secret key), the alias, a creation
// time and the entry, and finally a SHA-1 digest over the password (UTF-16BE),
// the bytes "Mighty Aphrodite" and everything before it. Certificates are
// stored in the clear. A private key is an encrypted PKCS#8 blob and a secret
// key a Java-serialized sealed object: neither is decrypted; a private key's
// blob is skipped by its length, and a secret key's object by walking the
// serialization grammar without building anything.

const (
	jceksMagic       = 0xCECECECE
	jceksMaxEntries  = 4096
	jceksMaxChain    = 64
	jceksDigestBytes = sha1.Size
)

// IsJCEKS reports whether data starts with the JCEKS magic number.
func IsJCEKS(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data) == jceksMagic
}

// JCEKSEntries lists a JCEKS keystore's entries for inventory (X2-L2): key
// entries with their certificate chains, trusted certificates, and secret
// key entries by alias (SecretKey set, no chain). verified reports whether one
// of passwords (or the empty password) matched the store's integrity digest;
// like JKS, the entries are listed when none does. A private or secret key is
// never decrypted.
func JCEKSEntries(data []byte, passwords [][]byte) (entries []Entry, verified bool, err error) {
	if !IsJCEKS(data) {
		return nil, false, errors.New("jks: not a JCEKS keystore")
	}
	if len(data) < 12+jceksDigestBytes {
		return nil, false, errors.New("jks: JCEKS keystore is truncated")
	}
	body, digest := data[:len(data)-jceksDigestBytes], data[len(data)-jceksDigestBytes:]
	entries, err = parseJCEKS(body)
	if err != nil {
		return nil, false, err
	}
	for _, password := range append(append([][]byte(nil), passwords...), nil) {
		if subtle.ConstantTimeCompare(jceksDigest(password, body), digest) == 1 {
			return entries, true, nil
		}
	}
	return entries, false, nil
}

// jceksDigest is the store's integrity digest for password: SHA-1 over the
// password's UTF-16BE code units, "Mighty Aphrodite" and the store's bytes.
func jceksDigest(password, body []byte) []byte {
	h := sha1.New() // #nosec G401 -- the JCEKS integrity digest is SHA-1 by definition; verification only (CWE-328)
	for _, unit := range utf16.Encode([]rune(string(password))) {
		h.Write(binary.BigEndian.AppendUint16(nil, unit))
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(body)
	return h.Sum(nil)
}

func parseJCEKS(body []byte) ([]Entry, error) {
	r := &jceksReader{b: body}
	r.u32() // magic
	version := r.u32()
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("jks: JCEKS version %d is not read", version)
	}
	count := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if count > jceksMaxEntries {
		return nil, fmt.Errorf("jks: JCEKS keystore claims %d entries", count)
	}
	entries := make([]Entry, 0, count)
	for i := uint32(0); i < count && r.err == nil; i++ {
		tag := r.u32()
		alias := r.utf()
		r.skip(8) // creation time
		switch tag {
		case 1:
			r.skip(int(r.u32())) // the encrypted key, never read
			n := r.u32()
			if n > jceksMaxChain {
				return nil, fmt.Errorf("jks: JCEKS entry %q claims %d certificates", alias, n)
			}
			entry := Entry{Alias: alias, KeyEntry: true}
			for j := uint32(0); j < n && r.err == nil; j++ {
				entry.ChainDER = append(entry.ChainDER, r.certificate(version))
			}
			entries = append(entries, entry)
		case 2:
			entries = append(entries, Entry{Alias: alias, ChainDER: [][]byte{r.certificate(version)}})
		case 3:
			if r.err == nil {
				n, err := skipSerializedObject(r.b[r.off:])
				if err != nil {
					return nil, fmt.Errorf("jks: JCEKS secret key %q: %w", alias, err)
				}
				r.skip(n)
			}
			entries = append(entries, Entry{Alias: alias, SecretKey: true})
		default:
			return nil, fmt.Errorf("jks: JCEKS entry %q has unknown tag %d", alias, tag)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(body) {
		return nil, errors.New("jks: JCEKS keystore has bytes after its entries")
	}
	return entries, nil
}

type jceksReader struct {
	b   []byte
	off int
	err error
}

func (r *jceksReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.off {
		r.err = errors.New("jks: JCEKS keystore is truncated")
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *jceksReader) skip(n int) { r.take(n) }

func (r *jceksReader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *jceksReader) utf() string {
	b := r.take(2)
	if b == nil {
		return ""
	}
	return string(r.take(int(binary.BigEndian.Uint16(b))))
}

func (r *jceksReader) certificate(version uint32) []byte {
	if version == 2 {
		if kind := r.utf(); r.err == nil && kind != "X.509" {
			r.err = fmt.Errorf("jks: JCEKS certificate of type %q is not read", kind)
			return nil
		}
	}
	return bytes.Clone(r.take(int(r.u32())))
}

// Java object serialization (the JDK's Object Serialization Stream Protocol):
// enough of the grammar to step over one object — a JCEKS secret key's
// sealed object — without instantiating anything.
const (
	tcNull           = 0x70
	tcReference      = 0x71
	tcClassDesc      = 0x72
	tcObject         = 0x73
	tcString         = 0x74
	tcArray          = 0x75
	tcClass          = 0x76
	tcBlockData      = 0x77
	tcEndBlockData   = 0x78
	tcBlockDataLong  = 0x7A
	tcLongString     = 0x7C
	tcProxyClassDesc = 0x7D
	tcEnum           = 0x7E

	baseWireHandle = 0x7E0000

	scWriteMethod    = 0x01
	scSerializable   = 0x02
	scExternalizable = 0x04
	scBlockData      = 0x08

	javaMaxDepth   = 32
	javaMaxHandles = 4096
	javaMaxFields  = 1024
)

var errJavaStream = errors.New("unreadable Java serialization stream")

// javaClassDesc is a class descriptor: enough to step over its instances.
type javaClassDesc struct {
	name   string
	flags  byte
	fields []byte // each field's type code
	super  *javaClassDesc
}

type javaHandle struct {
	desc *javaClassDesc // set for a class descriptor
}

type javaStream struct {
	r       jceksReader
	handles []javaHandle
	depth   int
}

// skipSerializedObject returns how many bytes of b one serialization stream
// (its header and one object) takes.
func skipSerializedObject(b []byte) (int, error) {
	s := &javaStream{r: jceksReader{b: b}}
	if h := s.r.take(4); h == nil || !bytes.Equal(h, []byte{0xAC, 0xED, 0x00, 0x05}) {
		return 0, errJavaStream
	}
	if err := s.content(); err != nil {
		return 0, err
	}
	if s.r.err != nil {
		return 0, s.r.err
	}
	return s.r.off, nil
}

func (s *javaStream) u8() byte {
	if b := s.r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (s *javaStream) u16() int {
	if b := s.r.take(2); b != nil {
		return int(binary.BigEndian.Uint16(b))
	}
	return 0
}

func (s *javaStream) peek() byte {
	if s.r.err != nil || s.r.off >= len(s.r.b) {
		s.r.err = errJavaStream
		return 0
	}
	return s.r.b[s.r.off]
}

func (s *javaStream) newHandle(h javaHandle) error {
	if len(s.handles) >= javaMaxHandles {
		return errJavaStream
	}
	s.handles = append(s.handles, h)
	return nil
}

func (s *javaStream) reference() (javaHandle, error) {
	h := s.r.u32()
	if s.r.err != nil || h < baseWireHandle || int(h-baseWireHandle) >= len(s.handles) {
		return javaHandle{}, errJavaStream
	}
	return s.handles[h-baseWireHandle], nil
}

func (s *javaStream) enter() error {
	if s.depth++; s.depth > javaMaxDepth {
		return errJavaStream
	}
	return nil
}

// content steps over one content element.
func (s *javaStream) content() error {
	if err := s.enter(); err != nil {
		return err
	}
	defer func() { s.depth-- }()
	tc := s.u8()
	if s.r.err != nil {
		return s.r.err
	}
	switch tc {
	case tcNull:
		return nil
	case tcReference:
		_, err := s.reference()
		return err
	case tcObject:
		desc, err := s.classDesc()
		if err != nil {
			return err
		}
		if desc == nil {
			return errJavaStream
		}
		if err := s.newHandle(javaHandle{}); err != nil {
			return err
		}
		return s.classData(desc)
	case tcClass:
		if _, err := s.classDesc(); err != nil {
			return err
		}
		return s.newHandle(javaHandle{})
	case tcArray:
		desc, err := s.classDesc()
		if err != nil {
			return err
		}
		if desc == nil || len(desc.name) < 2 || desc.name[0] != '[' {
			return errJavaStream
		}
		if err := s.newHandle(javaHandle{}); err != nil {
			return err
		}
		size := s.r.u32()
		if s.r.err != nil || int64(size) > int64(len(s.r.b)-s.r.off) {
			return errJavaStream
		}
		if width := primitiveWidth(desc.name[1]); width > 0 {
			s.r.skip(int(size) * width)
			return s.r.err
		}
		for i := uint32(0); i < size; i++ {
			if err := s.content(); err != nil {
				return err
			}
		}
		return nil
	case tcString:
		s.r.skip(s.u16())
		if s.r.err != nil {
			return s.r.err
		}
		return s.newHandle(javaHandle{})
	case tcLongString:
		n := s.r.take(8)
		if n == nil {
			return errJavaStream
		}
		size := binary.BigEndian.Uint64(n)
		if size > math.MaxInt32 {
			return errJavaStream
		}
		s.r.skip(int(size))
		if s.r.err != nil {
			return s.r.err
		}
		return s.newHandle(javaHandle{})
	case tcEnum:
		if _, err := s.classDesc(); err != nil {
			return err
		}
		if err := s.newHandle(javaHandle{}); err != nil {
			return err
		}
		return s.content()
	case tcBlockData:
		s.r.skip(int(s.u8()))
		return s.r.err
	case tcBlockDataLong:
		s.r.skip(int(s.r.u32()))
		return s.r.err
	}
	return errJavaStream
}

// classDesc reads a class descriptor: inline, by reference, or null.
func (s *javaStream) classDesc() (*javaClassDesc, error) {
	if err := s.enter(); err != nil {
		return nil, err
	}
	defer func() { s.depth-- }()
	switch s.u8() {
	case tcNull:
		return nil, s.r.err
	case tcReference:
		h, err := s.reference()
		if err != nil || h.desc == nil {
			return nil, errJavaStream
		}
		return h.desc, nil
	case tcClassDesc:
		desc := &javaClassDesc{name: string(s.r.take(s.u16()))}
		s.r.skip(8) // serialVersionUID
		if s.r.err != nil {
			return nil, s.r.err
		}
		if err := s.newHandle(javaHandle{desc: desc}); err != nil {
			return nil, err
		}
		desc.flags = s.u8()
		n := s.u16()
		if s.r.err != nil || n > javaMaxFields {
			return nil, errJavaStream
		}
		for i := 0; i < n; i++ {
			code := s.u8()
			s.r.skip(s.u16()) // field name
			if s.r.err != nil {
				return nil, s.r.err
			}
			switch {
			case code == '[' || code == 'L':
				if err := s.content(); err != nil { // the field's class name
					return nil, err
				}
			case primitiveWidth(code) == 0:
				return nil, errJavaStream
			}
			desc.fields = append(desc.fields, code)
		}
		if err := s.annotation(); err != nil {
			return nil, err
		}
		super, err := s.classDesc()
		if err != nil {
			return nil, err
		}
		desc.super = super
		return desc, nil
	case tcProxyClassDesc:
		desc := &javaClassDesc{flags: scSerializable}
		if err := s.newHandle(javaHandle{desc: desc}); err != nil {
			return nil, err
		}
		n := s.r.u32()
		if s.r.err != nil || n > javaMaxFields {
			return nil, errJavaStream
		}
		for i := uint32(0); i < n; i++ {
			s.r.skip(s.u16())
		}
		if err := s.annotation(); err != nil {
			return nil, err
		}
		super, err := s.classDesc()
		if err != nil {
			return nil, err
		}
		desc.super = super
		return desc, nil
	}
	return nil, errJavaStream
}

// annotation steps over contents up to and including TC_ENDBLOCKDATA.
func (s *javaStream) annotation() error {
	for {
		if s.peek() == tcEndBlockData {
			s.r.skip(1)
			return s.r.err
		}
		if s.r.err != nil {
			return s.r.err
		}
		if err := s.content(); err != nil {
			return err
		}
	}
}

// classData steps over an object's field values, superclass first.
func (s *javaStream) classData(desc *javaClassDesc) error {
	var chain []*javaClassDesc
	for d := desc; d != nil; d = d.super {
		if len(chain) >= javaMaxDepth {
			return errJavaStream
		}
		chain = append([]*javaClassDesc{d}, chain...)
	}
	for _, d := range chain {
		switch {
		case d.flags&scExternalizable != 0:
			if d.flags&scBlockData == 0 {
				return errJavaStream // the old externalizable protocol has no framing
			}
			if err := s.annotation(); err != nil {
				return err
			}
		case d.flags&scSerializable != 0:
			for _, code := range d.fields {
				if width := primitiveWidth(code); width > 0 {
					s.r.skip(width)
					continue
				}
				if err := s.content(); err != nil {
					return err
				}
			}
			if d.flags&scWriteMethod != 0 {
				if err := s.annotation(); err != nil {
					return err
				}
			}
		}
		if s.r.err != nil {
			return s.r.err
		}
	}
	return nil
}

// primitiveWidth is a primitive type code's size; 0 for an object or array.
func primitiveWidth(code byte) int {
	switch code {
	case 'B', 'Z':
		return 1
	case 'C', 'S':
		return 2
	case 'I', 'F':
		return 4
	case 'J', 'D':
		return 8
	}
	return 0
}
