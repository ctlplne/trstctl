// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

// The BSON types the sign-in writes, and every type a reader must step over.
const (
	TypeDouble     = 0x01
	TypeString     = 0x02
	TypeDocument   = 0x03
	TypeArray      = 0x04
	TypeBinary     = 0x05
	TypeObjectID   = 0x07
	TypeBool       = 0x08
	TypeDateTime   = 0x09
	TypeNull       = 0x0a
	TypeRegex      = 0x0b
	TypeInt32      = 0x10
	TypeTimestamp  = 0x11
	TypeInt64      = 0x12
	TypeDecimal128 = 0x13
)

// maxDocument bounds a document the sign-in or the gateway's relay reads
// whole (MongoDB's own limit is 16 MiB plus headroom).
const maxDocument = 48 << 20

// E is one element of a document the sign-in writes, in order.
type E struct {
	Key   string
	Value any // int32, int64, float64, string, bool, []byte (binary), []E (document), A (array)
}

// A is an array: its elements' keys are "0", "1", ... in order.
type A []E

// Encode writes a document of elements in order.
func Encode(elems []E) []byte {
	b := make([]byte, 4, 64)
	for _, e := range elems {
		switch v := e.Value.(type) {
		case float64:
			b = appendKey(b, TypeDouble, e.Key)
			b = binary.LittleEndian.AppendUint64(b, math.Float64bits(v))
		case string:
			b = appendKey(b, TypeString, e.Key)
			b = binary.LittleEndian.AppendUint32(b, uint32(len(v)+1)) // #nosec G115 -- command strings are short (CWE-190)
			b = append(append(b, v...), 0)
		case []E:
			b = appendKey(b, TypeDocument, e.Key)
			b = append(b, Encode(v)...)
		case A:
			b = appendKey(b, TypeArray, e.Key)
			b = append(b, Encode(v)...)
		case []byte:
			b = appendKey(b, TypeBinary, e.Key)
			b = binary.LittleEndian.AppendUint32(b, uint32(len(v))) // #nosec G115 -- SASL payloads are short (CWE-190)
			b = append(append(b, 0), v...)
		case bool:
			b = appendKey(b, TypeBool, e.Key)
			if v {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case int32:
			b = appendKey(b, TypeInt32, e.Key)
			b = binary.LittleEndian.AppendUint32(b, uint32(v)) // #nosec G115 -- a BSON int32 is its two's-complement bits (CWE-190)
		case int64:
			b = appendKey(b, TypeInt64, e.Key)
			b = binary.LittleEndian.AppendUint64(b, uint64(v)) // #nosec G115 -- a BSON int64 is its two's-complement bits (CWE-190)
		}
	}
	b = append(b, 0)
	binary.LittleEndian.PutUint32(b, uint32(len(b))) // #nosec G115 -- a command document is short (CWE-190)
	return b
}

func appendKey(b []byte, t byte, key string) []byte {
	return append(append(append(b, t), key...), 0)
}

// Element is one element of a document as read: its type, key and value
// bytes, and the whole element's raw bytes.
type Element struct {
	Type  byte
	Key   string
	Value []byte
	Raw   []byte
}

// Elements reads a document's elements in order.
func Elements(doc []byte) ([]Element, error) {
	if len(doc) < 5 || int(binary.LittleEndian.Uint32(doc)) != len(doc) || doc[len(doc)-1] != 0 {
		return nil, errors.New("mongosignin: a BSON document is malformed")
	}
	var out []Element
	rest := doc[4 : len(doc)-1]
	for len(rest) > 0 {
		start := rest
		t := rest[0]
		end := bytes.IndexByte(rest[1:], 0)
		if end < 0 {
			return nil, errors.New("mongosignin: a BSON key is not terminated")
		}
		key := string(rest[1 : 1+end])
		rest = rest[2+end:]
		size, err := valueSize(t, rest)
		if err != nil {
			return nil, err
		}
		out = append(out, Element{Type: t, Key: key, Value: rest[:size], Raw: start[:len(start)-len(rest)+size]})
		rest = rest[size:]
	}
	return out, nil
}

// fixedSizes are the BSON types whose values have a fixed size (0x06
// undefined, 0x7f max key and 0xff min key are empty).
var fixedSizes = map[byte]int{TypeDouble: 8, TypeObjectID: 12, TypeBool: 1, TypeDateTime: 8, TypeNull: 0, 0x06: 0,
	TypeInt32: 4, TypeTimestamp: 8, TypeInt64: 8, TypeDecimal128: 16, 0x7f: 0, 0xff: 0}

// valueSize is the size of a value of type t at the start of b.
func valueSize(t byte, b []byte) (int, error) {
	var n int
	switch t {
	case TypeString, 0x0d, 0x0e: // string, JavaScript, symbol
		if len(b) < 4 {
			return 0, errors.New("mongosignin: a BSON string is short")
		}
		n = 4 + int(binary.LittleEndian.Uint32(b))
	case TypeDocument, TypeArray, 0x0f: // document, array, code with scope
		if len(b) < 4 {
			return 0, errors.New("mongosignin: a BSON document is short")
		}
		n = int(binary.LittleEndian.Uint32(b))
	case TypeBinary:
		if len(b) < 5 {
			return 0, errors.New("mongosignin: a BSON binary is short")
		}
		n = 5 + int(binary.LittleEndian.Uint32(b))
	case TypeRegex:
		first := bytes.IndexByte(b, 0)
		if first < 0 {
			return 0, errors.New("mongosignin: a BSON regex is not terminated")
		}
		second := bytes.IndexByte(b[first+1:], 0)
		if second < 0 {
			return 0, errors.New("mongosignin: a BSON regex is not terminated")
		}
		n = first + second + 2
	case 0x0c: // DBPointer: string and ObjectId
		if len(b) < 4 {
			return 0, errors.New("mongosignin: a BSON pointer is short")
		}
		n = 4 + int(binary.LittleEndian.Uint32(b)) + 12
	default:
		size, ok := fixedSizes[t]
		if !ok {
			return 0, errors.New("mongosignin: a BSON element has an unknown type")
		}
		n = size
	}
	if n < 0 || n > len(b) || n > maxDocument {
		return 0, errors.New("mongosignin: a BSON element runs past its document")
	}
	return n, nil
}

// Lookup finds a document's element by key.
func Lookup(doc []byte, key string) (Element, bool) {
	elems, err := Elements(doc)
	if err != nil {
		return Element{}, false
	}
	for _, e := range elems {
		if e.Key == key {
			return e, true
		}
	}
	return Element{}, false
}

// Number reads an int32, int64 or double element as a float.
func (e Element) Number() (float64, bool) {
	switch e.Type {
	case TypeInt32:
		return float64(int32(binary.LittleEndian.Uint32(e.Value))), true // #nosec G115 -- a BSON int32's two's-complement bits (CWE-190)
	case TypeInt64:
		return float64(int64(binary.LittleEndian.Uint64(e.Value))), true // #nosec G115 -- a BSON int64's two's-complement bits (CWE-190)
	case TypeDouble:
		return math.Float64frombits(binary.LittleEndian.Uint64(e.Value)), true
	}
	return 0, false
}

// Bool reads a boolean element.
func (e Element) Bool() bool { return e.Type == TypeBool && len(e.Value) == 1 && e.Value[0] == 1 }

// Text reads a string element.
func (e Element) Text() (string, bool) {
	if e.Type != TypeString || len(e.Value) < 5 {
		return "", false
	}
	return string(e.Value[4 : len(e.Value)-1]), true
}

// Binary reads a binary element's data.
func (e Element) Binary() ([]byte, bool) {
	if e.Type != TypeBinary || len(e.Value) < 5 {
		return nil, false
	}
	return e.Value[5:], true
}
