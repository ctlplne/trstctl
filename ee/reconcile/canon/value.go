// SPDX-License-Identifier: LicenseRef-trstctl-EE

package canon

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type valueKind uint8

const (
	valueInvalid valueKind = iota
	valueBool
	valueInt
	valueString
	valueBytes
	valueArray
	valueObject
)

type stringKind uint8

const (
	stringPlain stringKind = iota
	stringDN
	stringURI
	stringPath
)

// Value is a normalized, secret-free canonical attribute value. The constructors
// are intentionally narrow: XREC canonical records admit booleans, integers,
// strings, byte strings rendered as lowercase hex, arrays with spec-defined
// order, and objects with lexicographically sorted member names.
type Value struct {
	kind       valueKind
	stringKind stringKind
	boolv      bool
	intv       int64
	strv       string
	bytesv     []byte
	arrayv     []Value
	objectv    map[string]Value
}

func Bool(v bool) Value { return Value{kind: valueBool, boolv: v} }

func Int(v int64) Value { return Value{kind: valueInt, intv: v} }

func String(v string) Value { return Value{kind: valueString, stringKind: stringPlain, strv: v} }

func DN(v string) Value { return Value{kind: valueString, stringKind: stringDN, strv: v} }

func URI(v string) Value { return Value{kind: valueString, stringKind: stringURI, strv: v} }

func Path(v string) Value { return Value{kind: valueString, stringKind: stringPath, strv: v} }

func Bytes(v []byte) Value {
	cp := append([]byte(nil), v...)
	return Value{kind: valueBytes, bytesv: cp}
}

func Array(v []Value) Value {
	cp := append([]Value(nil), v...)
	return Value{kind: valueArray, arrayv: cp}
}

func Object(v map[string]Value) Value {
	cp := make(map[string]Value, len(v))
	for k, val := range v {
		cp[k] = val
	}
	return Value{kind: valueObject, objectv: cp}
}

func (v Value) jsonValue() (canonicalJSON, error) {
	switch v.kind {
	case valueBool:
		return jsonBool(v.boolv), nil
	case valueInt:
		return jsonInt(v.intv), nil
	case valueString:
		s, err := normalizeAttributeString(v.strv, v.stringKind)
		if err != nil {
			return nil, err
		}
		if hasSecretValue(s) {
			return nil, ErrSecretMaterial
		}
		return jsonString(s), nil
	case valueBytes:
		if hasSecretBytes(v.bytesv) {
			return nil, ErrSecretMaterial
		}
		return jsonString(hex.EncodeToString(v.bytesv)), nil
	case valueArray:
		arr := make(jsonArray, 0, len(v.arrayv))
		for _, item := range v.arrayv {
			jv, err := item.jsonValue()
			if err != nil {
				return nil, err
			}
			arr = append(arr, jv)
		}
		return arr, nil
	case valueObject:
		obj := make(jsonObject, len(v.objectv))
		for raw, item := range v.objectv {
			key := normalizeText(strings.TrimSpace(raw))
			if key == "" {
				return nil, fmt.Errorf("%w: empty object member", ErrInvalidCanonicalValue)
			}
			if hasSecretFieldName(key) {
				return nil, ErrSecretMaterial
			}
			if _, ok := obj[key]; ok {
				return nil, fmt.Errorf("%w: duplicate object member after NFC normalization: %s", ErrInvalidCanonicalValue, key)
			}
			jv, err := item.jsonValue()
			if err != nil {
				return nil, err
			}
			obj[key] = jv
		}
		return obj, nil
	default:
		return nil, ErrInvalidCanonicalValue
	}
}

func normalizeAttributeString(s string, kind stringKind) (string, error) {
	switch kind {
	case stringPlain:
		return normalizeText(s), nil
	case stringDN:
		return normalizeDN(s), nil
	case stringURI:
		return normalizeURI(s)
	case stringPath:
		return normalizePath(s), nil
	default:
		return "", ErrInvalidCanonicalValue
	}
}

func normalizeText(s string) string {
	return norm.NFC.String(s)
}

func normalizeToken(s string) string {
	return strings.ToLower(strings.TrimSpace(normalizeText(s)))
}

func normalizeDN(s string) string {
	parts := strings.Split(normalizeText(strings.TrimSpace(s)), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if ok {
			out = append(out, strings.ToLower(strings.TrimSpace(k))+"="+strings.TrimSpace(v))
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

func normalizeURI(s string) (string, error) {
	raw := strings.TrimSpace(normalizeText(s))
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: uri: %v", ErrInvalidCanonicalValue, err)
	}
	if u.Scheme != "" {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if u.Host != "" {
		u.Host = strings.ToLower(u.Host)
	}
	if u.Path != "" {
		cleaned := path.Clean(u.EscapedPath())
		if strings.HasSuffix(u.Path, "/") && cleaned != "/" {
			cleaned += "/"
		}
		u.Path = cleaned
		u.RawPath = ""
	}
	return u.String(), nil
}

func normalizeSPIFFEID(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(normalizeText(s)))
	if err != nil {
		return "", fmt.Errorf("%w: spiffe id: %v", ErrInvalidCanonicalValue, err)
	}
	if strings.ToLower(u.Scheme) != "spiffe" || u.Host == "" {
		return "", fmt.Errorf("%w: workload identity must be a spiffe URI", ErrInvalidCanonicalValue)
	}
	u.Scheme = "spiffe"
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""
	u.RawPath = ""
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	return u.String(), nil
}

func normalizePath(s string) string {
	p := strings.TrimSpace(normalizeText(s))
	if p == "" {
		return "/"
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func normalizeSecretRef(namespace, p string) string {
	ns := normalizeToken(namespace)
	clean := normalizePath(p)
	if ns == "" {
		return clean
	}
	return ns + ":" + clean
}

func canonicalizeAttributes(in map[string]Value) (jsonObject, error) {
	obj := make(jsonObject, len(in))
	for raw, v := range in {
		key := normalizeText(strings.TrimSpace(raw))
		if key == "" {
			return nil, fmt.Errorf("%w: empty attribute name", ErrInvalidCanonicalValue)
		}
		if hasSecretFieldName(key) {
			return nil, ErrSecretMaterial
		}
		if _, ok := obj[key]; ok {
			return nil, fmt.Errorf("%w: duplicate attribute after NFC normalization: %s", ErrInvalidCanonicalValue, key)
		}
		jv, err := v.jsonValue()
		if err != nil {
			return nil, err
		}
		obj[key] = jv
	}
	return obj, nil
}

func stableObjectKeys(obj jsonObject) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
