// SPDX-License-Identifier: BUSL-1.1

// Package dbdsn parses the bounded TCP connection profiles used by database
// providers and gateways. Parsing does not open files or resolve addresses.
package dbdsn

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	MaxBytes   = 64 << 10
	MaxHosts   = 16
	MaxOptions = 64

	Postgres = "postgresql"
	MySQL    = "mysql"
	Mongo    = "mongodb"
	Oracle   = "oracle"
	MSSQL    = "mssql"
	HANA     = "hana"
)

var (
	ErrInvalid = errors.New("database connection profile is malformed or exceeds its bounds")
	ErrOption  = errors.New("database connection profile contains an unsupported or repeated option")
)

// Purpose separates the administrator's connection profile from a credential
// that will be presented to a database. Gateway is the smaller profile spoken
// by the gateway's native sign-in path.
type Purpose uint8

const (
	Admin Purpose = iota
	Credential
	Gateway
)

// Target keeps the authentication secret out of the routing and options
// fields. The caller must Wipe a successfully parsed target.
type Target struct {
	Hosts              []string
	User               string
	Password           []byte
	Database           string
	AuthSource         string
	ExplicitAuthSource bool
	Options            map[string]string
	CAFile             string
	SystemRoots        bool
	SRV                bool
	passwordBuffer     *secret.Buffer
}

func (t *Target) Wipe() {
	if t.passwordBuffer != nil {
		t.passwordBuffer.Destroy()
		t.passwordBuffer = nil
	} else {
		secret.Wipe(t.Password)
	}
	t.Password = nil
}

func IsDriver(driver string) bool {
	switch driver {
	case Postgres, MySQL, Mongo, Oracle, MSSQL, "azure-sql", HANA:
		return true
	default:
		return false
	}
}

type profile struct {
	Target
	driver  string
	purpose Purpose
	seen    map[string]bool
	host    string
	port    string
}

// Parse reads one of the provider's supported connection forms. It rejects
// duplicate effective fields even if the native parser would overwrite them.
func Parse(driver string, raw []byte, purpose Purpose) (Target, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || bytes.IndexByte(raw, 0) >= 0 || !IsDriver(driver) {
		return Target{}, ErrInvalid
	}
	raw = bytes.TrimRight(raw, "\r\n")
	if driver == "azure-sql" {
		driver = MSSQL
	}
	p := profile{driver: driver, purpose: purpose, seen: make(map[string]bool)}
	p.Options = make(map[string]string)
	var err error
	switch {
	case driver == MySQL:
		err = p.parseMySQL(raw)
	case driver == Postgres && !bytes.HasPrefix(raw, []byte("postgres://")) && !bytes.HasPrefix(raw, []byte("postgresql://")):
		err = p.parsePostgresKeywords(raw)
	default:
		err = p.parseURI(raw)
	}
	if err == nil {
		err = p.finish()
	}
	if err != nil {
		p.Wipe()
		return Target{}, err
	}
	return p.Target, nil
}

func (p *profile) parsePostgresKeywords(raw []byte) error {
	for raw = bytes.TrimLeft(raw, " \t\r\n\v\f"); len(raw) > 0; raw = bytes.TrimLeft(raw, " \t\r\n\v\f") {
		key, rest, ok := bytes.Cut(raw, []byte{'='})
		key = bytes.TrimRight(key, " \t\r\n\v\f")
		if !ok || len(key) == 0 || bytes.ContainsAny(key, " \t\r\n\v\f") {
			return ErrInvalid
		}
		rest = bytes.TrimLeft(rest, " \t\r\n\v\f")
		value, next, ok := pgValue(rest)
		if !ok {
			return ErrInvalid
		}
		err := p.set(string(key), value, false)
		secret.Wipe(value)
		if err != nil {
			return err
		}
		raw = next
	}
	return nil
}

func pgValue(raw []byte) ([]byte, []byte, bool) {
	quoted := len(raw) > 0 && raw[0] == '\''
	if quoted {
		raw = raw[1:]
	}
	// Count the encoded token before allocating so a password never grows a
	// backing array and adjacent options do not consume its capacity.
	end := 0
	for end < len(raw) {
		b := raw[end]
		if quoted && b == '\'' || !quoted && bytes.ContainsRune([]byte(" \t\r\n\v\f"), rune(b)) {
			break
		}
		if b == '\\' && end+1 < len(raw) {
			end++
		}
		end++
	}
	if quoted && end == len(raw) {
		return nil, nil, false
	}
	value := make([]byte, 0, end)
	for i := 0; i < end; i++ {
		if raw[i] == '\\' {
			i++
			if i == end {
				break // libpq drops an unquoted escape at the end of input.
			}
		}
		value = append(value, raw[i])
	}
	if quoted {
		end++
	}
	return value, raw[end:], true
}

func (p *profile) parseURI(raw []byte) error {
	scheme, rest, ok := bytes.Cut(raw, []byte("://"))
	if !ok || bytes.IndexByte(rest, '#') >= 0 {
		return ErrInvalid
	}
	switch string(scheme) {
	case "postgres", Postgres:
		ok = p.driver == Postgres
	case Mongo, "mongodb+srv":
		ok = p.driver == Mongo
		p.SRV = string(scheme) == "mongodb+srv"
	case Oracle:
		ok = p.driver == Oracle
	case "sqlserver":
		ok = p.driver == MSSQL
	case "hdb":
		ok = p.driver == HANA
	default:
		ok = false
	}
	if !ok || p.SRV && p.purpose == Gateway {
		return ErrInvalid
	}
	end := bytes.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if credentials, hosts, ok := bytes.Cut(authority, []byte{'@'}); ok {
		if bytes.IndexByte(hosts, '@') >= 0 {
			return ErrInvalid
		}
		authority = hosts
		user, password, hasPassword := bytes.Cut(credentials, []byte{':'})
		if err := p.putDecoded("user", user, false, false); err != nil {
			return err
		}
		if hasPassword {
			if err := p.putDecoded("password", password, false, false); err != nil {
				return err
			}
		}
	}
	if len(authority) != 0 {
		addresses, err := p.uriHosts(authority)
		if err != nil {
			return err
		}
		p.Hosts = addresses
		p.seen["host"] = true
	}
	path, query, hasQuery := bytes.Cut(tail, []byte{'?'})
	if len(path) > 1 {
		if p.driver == MSSQL || p.driver == HANA || bytes.IndexByte(path[1:], '/') >= 0 {
			return ErrInvalid
		}
		if err := p.putDecoded("database", path[1:], false, false); err != nil {
			return err
		}
	}
	if hasQuery {
		return p.parseQuery(query)
	}
	return nil
}

func (p *profile) uriHosts(raw []byte) ([]string, error) {
	if bytes.Count(raw, []byte{','}) >= MaxHosts {
		return nil, ErrInvalid
	}
	var hosts []string
	for len(raw) > 0 {
		var part []byte
		var more bool
		part, raw, more = bytes.Cut(raw, []byte{','})
		decoded, ok := decode(part, false)
		if !ok {
			return nil, ErrInvalid
		}
		host, port, ok := hostPort(string(decoded))
		secret.Wipe(decoded)
		if !ok || more && len(raw) == 0 {
			return nil, ErrInvalid
		}
		if port != "" {
			p.seen["port"] = true
		}
		address, err := p.address(host, port)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, address)
	}
	return hosts, nil
}

func (p *profile) parseMySQL(raw []byte) error {
	// The final slash separates the database and the final at sign before it
	// separates credentials from network. Password bytes may contain either.
	slash := bytes.LastIndexByte(raw, '/')
	if slash < 0 {
		return ErrInvalid
	}
	at := bytes.LastIndexByte(raw[:slash], '@')
	if at < 1 {
		return ErrInvalid
	}
	user, password, ok := bytes.Cut(raw[:at], []byte{':'})
	if !ok {
		return ErrInvalid
	}
	if err := p.set("user", user, false); err != nil {
		return err
	}
	if err := p.set("password", password, false); err != nil {
		return err
	}
	network := raw[at+1 : slash]
	if !bytes.HasPrefix(network, []byte("tcp(")) || !bytes.HasSuffix(network, []byte{')'}) {
		return ErrInvalid
	}
	host, port, ok := hostPort(string(network[4 : len(network)-1]))
	if !ok || p.purpose == Gateway && port == "" {
		return ErrInvalid
	}
	address, err := p.address(host, port)
	if err != nil {
		return err
	}
	p.Hosts = []string{address}
	p.seen["host"], p.seen["port"] = true, true
	database, query, hasQuery := bytes.Cut(raw[slash+1:], []byte{'?'})
	if err := p.putDecoded("database", database, false, false); err != nil {
		return err
	}
	if hasQuery {
		return p.parseQuery(query)
	}
	return nil
}

func (p *profile) parseQuery(raw []byte) error {
	for len(raw) != 0 {
		delimiter := bytes.IndexByte(raw, '&')
		if p.driver == Mongo {
			delimiter = bytes.IndexAny(raw, "&;")
		}
		part := raw
		if delimiter >= 0 {
			part, raw = raw[:delimiter], raw[delimiter+1:]
		} else {
			raw = nil
		}
		key, val, ok := bytes.Cut(part, []byte{'='})
		if !ok || len(key) == 0 || len(key) > 128 {
			return ErrInvalid
		}
		decoded, ok := decode(key, p.driver != Postgres)
		if !ok {
			return ErrInvalid
		}
		err := p.putDecoded(string(decoded), val, p.driver != Postgres, true)
		secret.Wipe(decoded)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *profile) putDecoded(key string, raw []byte, queryEscape, fromQuery bool) error {
	value, ok := decode(raw, queryEscape)
	if !ok {
		return ErrInvalid
	}
	defer secret.Wipe(value)
	return p.set(key, value, fromQuery)
}

func (p *profile) set(key string, value []byte, fromQuery bool) error {
	if len(key) > 128 || bytes.IndexByte(value, 0) >= 0 {
		return ErrInvalid
	}
	key, value, err := p.option(key, value, fromQuery)
	if err != nil {
		return err
	}
	if p.seen[key] || len(p.seen) >= MaxOptions {
		return ErrOption
	}
	p.seen[key] = true
	switch key {
	case "password":
		if len(value) != 0 {
			buf, err := secret.NewFrom(value)
			if err != nil {
				return errors.New("database password could not be held in locked memory")
			}
			p.passwordBuffer, p.Password = buf, buf.Bytes()
		}
	case "user":
		p.User = string(value)
	case "database":
		p.Database = string(value)
	case "host":
		p.host = string(value)
	case "port":
		p.port = string(value)
	case "authsource":
		p.AuthSource = string(value)
		p.ExplicitAuthSource = true
	case "ca_file":
		if p.driver == Postgres && bytes.Equal(value, []byte("system")) {
			p.SystemRoots = true
		} else {
			p.CAFile = string(value)
		}
	default:
		p.Options[key] = string(value)
	}
	return nil
}

func (p *profile) finish() error {
	if len(p.Hosts) == 0 && p.host != "" {
		hosts, ports := strings.Split(p.host, ","), strings.Split(p.port, ",")
		if len(hosts) > MaxHosts || len(ports) != 1 && len(ports) != len(hosts) {
			return ErrInvalid
		}
		for i, host := range hosts {
			port := ports[0]
			if len(ports) > 1 {
				port = ports[i]
			}
			address, err := p.address(host, port)
			if err != nil {
				return err
			}
			p.Hosts = append(p.Hosts, address)
		}
	} else if len(p.Hosts) != 0 && p.port != "" {
		if len(p.Hosts) != 1 {
			return ErrInvalid
		}
		host, _, _ := net.SplitHostPort(p.Hosts[0])
		address, err := p.address(host, p.port)
		if err != nil {
			return err
		}
		p.Hosts[0] = address
	}
	if len(p.Hosts) == 0 || p.driver != Postgres && p.driver != Mongo && len(p.Hosts) != 1 ||
		p.driver == Postgres && p.purpose == Gateway && len(p.Hosts) != 1 ||
		!identifier(p.User, 256) || p.User == "" || !identifier(p.Database, 256) ||
		p.driver != Postgres && len(p.Password) == 0 {
		return ErrInvalid
	}
	if p.driver == Oracle && p.Database == "" || p.driver == MSSQL && strings.Contains(p.User, `\`) {
		return ErrInvalid
	}
	if p.driver == Mongo {
		if p.Options["directconnection"] == "true" && (p.SRV || len(p.Hosts) != 1) {
			return ErrInvalid
		}
		if p.AuthSource == "" {
			p.AuthSource = p.Database
			if p.AuthSource == "" {
				p.AuthSource = "admin"
			}
		}
		if p.SRV {
			if len(p.Hosts) != 1 || p.seen["port"] {
				return ErrInvalid
			}
			host, _, _ := net.SplitHostPort(p.Hosts[0])
			if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
				return ErrInvalid
			}
		}
	}
	return nil
}

func (p *profile) address(host, port string) (string, error) {
	if port == "" {
		switch p.driver {
		case Postgres:
			port = "5432"
		case MySQL:
			port = "3306"
		case Mongo:
			port = "27017"
		case Oracle:
			port = "1521"
		case MSSQL:
			port = "1433"
		}
	}
	return TCPAddress(host, port)
}

func hostPort(raw string) (string, string, bool) {
	if host, port, err := net.SplitHostPort(raw); err == nil {
		return host, port, true
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return raw[1 : len(raw)-1], "", true
	}
	return raw, "", !strings.Contains(raw, ":")
}

// TCPAddress canonicalizes the endpoint understood by the dial guard.
func TCPAddress(host, port string) (string, error) {
	host, err := HostName(host)
	if err != nil {
		return "", err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", ErrInvalid
	}
	return net.JoinHostPort(host, strconv.FormatUint(number, 10)), nil
}

// HostName admits a DNS name or IP literal without path, socket or zone syntax.
func HostName(host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", ErrInvalid
			}
		}
	}
	return host, nil
}

func identifier(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func decode(raw []byte, query bool) ([]byte, bool) {
	value := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		switch {
		case b == '+' && query:
			b = ' '
		case b == '%':
			if i+2 >= len(raw) {
				secret.Wipe(value)
				return nil, false
			}
			hi, hiOK := nibble(raw[i+1])
			lo, loOK := nibble(raw[i+2])
			if !hiOK || !loOK {
				secret.Wipe(value)
				return nil, false
			}
			b = hi<<4 | lo
			i += 2
		}
		value = append(value, b)
	}
	return value, true
}

func nibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
