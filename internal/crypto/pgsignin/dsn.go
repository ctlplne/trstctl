// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// ParseDSN reads a session DSN in either libpq form — a postgres:// URI or
// "key=value" keywords — into a Target. The password stays in bytes. Only
// one TCP host is supported; a Unix socket or a host list is refused.
func ParseDSN(dsn []byte) (Target, error) {
	t := Target{Port: "5432", SSLMode: "prefer"}
	var err error
	if bytes.HasPrefix(dsn, []byte("postgres://")) || bytes.HasPrefix(dsn, []byte("postgresql://")) {
		err = parseURI(dsn, &t)
	} else {
		err = parseKeywords(dsn, &t)
	}
	if err != nil {
		t.Wipe()
		return Target{}, err
	}
	if t.Host == "" || strings.ContainsAny(t.Host, ",/") {
		t.Wipe()
		return Target{}, errors.New("pgsignin: the session's DSN must name one TCP host")
	}
	if n, perr := strconv.Atoi(t.Port); perr != nil || n < 1 || n > 65535 {
		t.Wipe()
		return Target{}, errors.New("pgsignin: the session's DSN port is invalid")
	}
	return t, nil
}

func parseURI(dsn []byte, t *Target) error {
	rest := dsn[bytes.Index(dsn, []byte("://"))+3:]
	end := len(rest)
	for i, b := range rest {
		if b == '/' || b == '?' || b == '#' {
			end = i
			break
		}
	}
	authority, tail := rest[:end], rest[end:]
	if at := bytes.LastIndexByte(authority, '@'); at >= 0 {
		userinfo := authority[:at]
		authority = authority[at+1:]
		user, password, hasPassword := bytes.Cut(userinfo, []byte(":"))
		decoded, ok := percentDecode(user)
		if !ok {
			return errors.New("pgsignin: the session's DSN user is malformed")
		}
		t.User = string(decoded)
		if hasPassword {
			if t.Password, ok = percentDecode(password); !ok {
				return errors.New("pgsignin: the session's DSN password is malformed")
			}
		}
	}
	if len(authority) > 0 {
		host, port := string(authority), ""
		if h, p, err := net.SplitHostPort(string(authority)); err == nil {
			host, port = h, p
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		t.Host = host
		if port != "" {
			t.Port = port
		}
	}
	if fragment := bytes.IndexByte(tail, '#'); fragment >= 0 {
		tail = tail[:fragment]
	}
	path, query, _ := bytes.Cut(tail, []byte("?"))
	if len(path) > 1 {
		db, ok := percentDecode(path[1:])
		if !ok {
			return errors.New("pgsignin: the session's DSN database is malformed")
		}
		t.Database = string(db)
	}
	for len(query) > 0 {
		var part []byte
		part, query, _ = bytes.Cut(query, []byte("&"))
		key, value, _ := bytes.Cut(part, []byte("="))
		decoded, ok := percentDecode(value)
		if !ok {
			return errors.New("pgsignin: the session's DSN query is malformed")
		}
		setParameter(t, string(key), decoded)
	}
	return nil
}

func parseKeywords(dsn []byte, t *Target) error {
	for i := 0; i < len(dsn); {
		for i < len(dsn) && isSpace(dsn[i]) {
			i++
		}
		if i == len(dsn) {
			break
		}
		keyStart := i
		for i < len(dsn) && !isSpace(dsn[i]) && dsn[i] != '=' {
			i++
		}
		key := string(dsn[keyStart:i])
		for i < len(dsn) && isSpace(dsn[i]) {
			i++
		}
		if key == "" || i >= len(dsn) || dsn[i] != '=' {
			return errors.New("pgsignin: the session's DSN is malformed")
		}
		i++
		for i < len(dsn) && isSpace(dsn[i]) {
			i++
		}
		// Sized once, so a password is never left behind in a grown-out
		// backing array.
		value := make([]byte, 0, len(dsn)-i)
		quoted := i < len(dsn) && dsn[i] == '\''
		if quoted {
			i++
		}
		closed := !quoted
		for i < len(dsn) {
			b := dsn[i]
			if b == '\\' && i+1 < len(dsn) {
				value = append(value, dsn[i+1])
				i += 2
				continue
			}
			if quoted && b == '\'' {
				i++
				closed = true
				break
			}
			if !quoted && isSpace(b) {
				break
			}
			value = append(value, b)
			i++
		}
		if !closed {
			secret.Wipe(value)
			return errors.New("pgsignin: the session's DSN has an unterminated value")
		}
		setParameter(t, key, value)
	}
	return nil
}

// setParameter records one DSN parameter; value is owned by the caller
// unless it becomes the password.
func setParameter(t *Target, key string, value []byte) {
	switch key {
	case "password":
		secret.Wipe(t.Password)
		t.Password = value
		return
	case "host":
		t.Host = string(value)
	case "port":
		t.Port = string(value)
	case "user":
		t.User = string(value)
	case "dbname":
		t.Database = string(value)
	case "sslmode":
		t.SSLMode = string(value)
	case "sslrootcert":
		t.SSLRootCert = string(value)
	}
	secret.Wipe(value)
}

func percentDecode(value []byte) ([]byte, bool) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out = append(out, value[i])
			continue
		}
		if i+2 >= len(value) {
			secret.Wipe(out)
			return nil, false
		}
		hi, okHi := hexNibble(value[i+1])
		lo, okLo := hexNibble(value[i+2])
		if !okHi || !okLo {
			secret.Wipe(out)
			return nil, false
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, true
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
