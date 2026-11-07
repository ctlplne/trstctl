// SPDX-License-Identifier: BUSL-1.1
package hostaccounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// LocalCredential keeps the existing Windows engine's credential shape. Only
// the password is private; decoding it never creates a Go string.
type LocalCredential struct {
	Host     string           `json:"host"`
	Username string           `json:"username"`
	Password secret.JSONBytes `json:"password"`
}
type RotationPreparation struct {
	Intent          RotationIntent  `json:"intent"`
	ProviderBinding string          `json:"provider_binding"`
	Role            string          `json:"role"`
	Credential      LocalCredential `json:"credential"`
}

var errPrivateCredential = errors.New("host accounts: bounded exact private credential required")

// Borrow raw value slices rather than tokenizing password strings or making
// a decoder-owned copy of the complete private JSON. The caller owns and wipes
// raw; only the decoded password buffer transfers to the caller.
func privateFields(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || len(raw) > 64<<10 || !json.Valid(raw) || raw[0] != '{' {
		return nil, errPrivateCredential
	}
	fields := map[string]json.RawMessage{}
	space := func(pos int) int {
		for pos < len(raw) && (raw[pos] == ' ' || raw[pos] == '\n' || raw[pos] == '\r' || raw[pos] == '\t') {
			pos++
		}
		return pos
	}
	for pos := space(1); pos < len(raw) && raw[pos] != '}'; {
		start := pos
		pos++
		for pos < len(raw) {
			if raw[pos] == '\\' {
				pos += 2
				continue
			}
			if raw[pos] == '"' {
				pos++
				break
			}
			pos++
		}
		key := ""
		for _, name := range names {
			if bytes.Equal(raw[start:pos], []byte("\""+name+"\"")) {
				key = name
				break
			}
		}
		if key == "" {
			return nil, errPrivateCredential
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errPrivateCredential
		}
		pos = space(pos)
		if pos >= len(raw) || raw[pos] != ':' {
			return nil, errPrivateCredential
		}
		pos = space(pos + 1)
		start = pos
		depth := 0
		quoted := false
		for pos < len(raw) {
			c := raw[pos]
			if quoted {
				if c == '\\' {
					pos += 2
					continue
				}
				if c == '"' {
					quoted = false
				}
				pos++
				continue
			}
			if c == '"' {
				quoted = true
				pos++
				continue
			}
			if depth == 0 && (c == ',' || c == '}') {
				break
			}
			if c == '{' || c == '[' {
				depth++
			}
			if c == '}' || c == ']' {
				depth--
			}
			if depth > 32 {
				return nil, errPrivateCredential
			}
			pos++
		}
		fields[key] = bytes.TrimSpace(raw[start:pos])
		if pos < len(raw) && raw[pos] == ',' {
			pos = space(pos + 1)
		}
	}
	if len(fields) != len(names) {
		return nil, errPrivateCredential
	}
	return fields, nil
}
func decodeLocalCredential(raw []byte) (LocalCredential, error) {
	var c LocalCredential
	fields, e := privateFields(raw, "host", "username", "password")
	if e != nil {
		return c, e
	}
	if json.Unmarshal(fields["host"], &c.Host) != nil || json.Unmarshal(fields["username"], &c.Username) != nil || json.Unmarshal(fields["password"], &c.Password) != nil || len(c.Password) == 0 || len(c.Password) > 1024 {
		secret.Wipe(c.Password)
		return LocalCredential{}, errPrivateCredential
	}
	return c, nil
}
func DecodeLocalCredential(raw []byte, i RotationIntent) (LocalCredential, error) {
	c, e := decodeLocalCredential(raw)
	if e != nil {
		return c, e
	}
	if i.Validate() != nil || c.Host != i.Native.Machine.Name || c.Username != i.Native.Account.Name {
		secret.Wipe(c.Password)
		return LocalCredential{}, errPrivateCredential
	}
	return c, nil
}
func DecodeRotationPreparation(raw []byte) (RotationPreparation, error) {
	var p RotationPreparation
	fields, e := privateFields(raw, "intent", "provider_binding", "role", "credential")
	if e != nil {
		return p, e
	}
	p.Intent, e = DecodeRotationIntent(fields["intent"])
	if e != nil {
		return p, errPrivateCredential
	}
	if json.Unmarshal(fields["provider_binding"], &p.ProviderBinding) != nil || json.Unmarshal(fields["role"], &p.Role) != nil || len(p.ProviderBinding) != 64 || p.Role == "" {
		return p, errPrivateCredential
	}
	p.Credential, e = DecodeLocalCredential(fields["credential"], p.Intent)
	if e != nil || len(p.Credential.Password) < 24 {
		secret.Wipe(p.Credential.Password)
		return RotationPreparation{}, errPrivateCredential
	}
	return p, nil
}

// MarshalLocalCredential encodes private bytes outside encoding/json's pooled
// encoder buffers. The returned buffer belongs to tenant custody and must be
// wiped after sealing; the public metadata encoder sees no password.
func MarshalLocalCredential(c LocalCredential) ([]byte, error) {
	if c.Host == "" || c.Username == "" || len(c.Password) == 0 || len(c.Password) > 1024 {
		return nil, errPrivateCredential
	}
	metadata, e := json.Marshal(struct {
		Host     string `json:"host"`
		Username string `json:"username"`
	}{c.Host, c.Username})
	if e != nil {
		return nil, e
	}
	password, e := c.Password.MarshalJSON()
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(password)
	out := make([]byte, 0, len(metadata)+len(password)+13)
	out = append(out, metadata[:len(metadata)-1]...)
	out = append(out, `,"password":`...)
	out = append(out, password...)
	out = append(out, '}')
	return out, nil
}
func MarshalRotationPreparation(p RotationPreparation) ([]byte, error) {
	if p.Intent.Validate() != nil || len(p.ProviderBinding) != 64 || p.Role == "" || p.Credential.Host != p.Intent.Native.Machine.Name || p.Credential.Username != p.Intent.Native.Account.Name || len(p.Credential.Password) < 24 {
		return nil, errPrivateCredential
	}
	metadata, e := json.Marshal(struct {
		Intent          RotationIntent `json:"intent"`
		ProviderBinding string         `json:"provider_binding"`
		Role            string         `json:"role"`
	}{p.Intent, p.ProviderBinding, p.Role})
	if e != nil {
		return nil, e
	}
	credential, e := MarshalLocalCredential(p.Credential)
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(credential)
	out := make([]byte, 0, len(metadata)+len(credential)+15)
	out = append(out, metadata[:len(metadata)-1]...)
	out = append(out, `,"credential":`...)
	out = append(out, credential...)
	out = append(out, '}')
	return out, nil
}
