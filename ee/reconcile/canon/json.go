// SPDX-License-Identifier: LicenseRef-trstctl-EE

package canon

import (
	"bytes"
	"encoding/json"
	"strconv"
)

type canonicalJSON interface {
	writeCanonical(*bytes.Buffer) error
}

type jsonObject map[string]canonicalJSON
type jsonArray []canonicalJSON
type jsonString string
type jsonInt int64
type jsonBool bool

func (o jsonObject) writeCanonical(b *bytes.Buffer) error {
	b.WriteByte('{')
	keys := stableObjectKeys(o)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeJSONString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := o[k].writeCanonical(b); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func (a jsonArray) writeCanonical(b *bytes.Buffer) error {
	b.WriteByte('[')
	for i, v := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := v.writeCanonical(b); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

func (s jsonString) writeCanonical(b *bytes.Buffer) error {
	return writeJSONString(b, string(s))
}

func (i jsonInt) writeCanonical(b *bytes.Buffer) error {
	b.WriteString(strconv.FormatInt(int64(i), 10))
	return nil
}

func (v jsonBool) writeCanonical(b *bytes.Buffer) error {
	if v {
		b.WriteString("true")
		return nil
	}
	b.WriteString("false")
	return nil
}

func canonicalBytes(v canonicalJSON) ([]byte, error) {
	var b bytes.Buffer
	if err := v.writeCanonical(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeJSONString(b *bytes.Buffer, s string) error {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalizeText(s)); err != nil {
		return err
	}
	out := bytes.TrimSpace(tmp.Bytes())
	b.Write(out)
	return nil
}
