// SPDX-License-Identifier: BUSL-1.1

// Package pgsignin signs the access gateway in to a PostgreSQL target as one
// session's login (A254). It reads the session's DSN, connects, answers the
// server's password request (SCRAM-SHA-256, MD5 or cleartext, as libpq does)
// and returns the connection once the server is ready, for the gateway to
// relay a stock client's protocol over. It is a sign-in, not a
// driver: it never sends a query, and the agent binary links no database
// driver. TLS, whenever it is used, is verified: the database's certificate
// must chain to sslrootcert (a file on the gateway's host) or to the system
// roots and name the host — stricter than libpq's prefer, require and
// verify-ca, which accept a certificate they cannot verify.
package pgsignin

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- PostgreSQL's md5 password exchange, used only when the server demands it (CWE-327)
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/scram"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Target is a parsed session DSN. Password is byte-backed; Wipe clears it.
type Target struct {
	Host, Port, User, Database string
	Password                   []byte
	// SSLMode is libpq's sslmode ("prefer" when the DSN names none);
	// SSLRootCert a PEM file of trusted roots on the gateway's host, or
	// "system".
	SSLMode, SSLRootCert string
	// rootPEM and serverName are the target's CA and certificate name as the
	// session carries them (A256-L1); they take precedence over SSLRootCert
	// and Host.
	rootPEM    []byte
	serverName string
}

// Wipe clears the password.
func (t *Target) Wipe() { secret.Wipe(t.Password) }

// Session is a signed-in connection, ready for queries.
type Session struct {
	Conn net.Conn
	// Parameters are the server's ParameterStatus reports, in order.
	Parameters           [][2]string
	ProcessID, SecretKey uint32
	TxStatus             byte
}

// Options shape one sign-in.
type Options struct {
	// Dial reaches the target; nil uses a plain dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Database is used when the DSN names none.
	Database string
	// Runtime carries client runtime parameters (application_name,
	// client_encoding, ...) into the startup message; see RuntimeParameter.
	Runtime [][2]string
	// RootCAPEM is the target's CA as the control plane carries it with the
	// session (A256-L1): a private CA verifies the database without a root
	// file on the gateway's host, and takes precedence over the DSN's
	// sslrootcert, a path on the control plane's host. ServerName, when set,
	// is the certificate name to verify instead of the DSN's host.
	RootCAPEM  []byte
	ServerName string
}

// RuntimeParameter reports whether a client's startup parameter may be passed
// to the target. The login, database, replication and command-line options
// are the gateway's to decide, never the client's.
func RuntimeParameter(name string) bool {
	switch name {
	case "application_name", "client_encoding", "DateStyle", "TimeZone", "extra_float_digits", "IntervalStyle":
		return true
	}
	return false
}

const (
	protocolVersion3 = 196608
	sslRequestCode   = 80877103
	// maxSignInMessage bounds one server message before the session is ready.
	maxSignInMessage = 1 << 20
)

// SignIn connects and authenticates as the DSN's login. The caller owns the
// returned connection and must wipe dsn.
func SignIn(ctx context.Context, dsn []byte, opts Options) (*Session, error) {
	target, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	if target.Database == "" {
		target.Database = opts.Database
	}
	if target.User == "" || target.Database == "" {
		return nil, errors.New("pgsignin: the session's DSN names no login or database")
	}
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(target.Host, target.Port))
	if err != nil {
		return nil, errors.New("pgsignin: the database is unreachable")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	target.rootPEM, target.serverName = opts.RootCAPEM, opts.ServerName
	session, err := signIn(conn, &target, opts.Runtime)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = session.Conn.SetDeadline(time.Time{})
	return session, nil
}

func signIn(conn net.Conn, target *Target, runtime [][2]string) (*Session, error) {
	conn, err := negotiateTLS(conn, target)
	if err != nil {
		return nil, err
	}
	startup := []byte{0, 0, 0, 0}
	startup = binary.BigEndian.AppendUint32(startup, protocolVersion3)
	startup = appendCString(appendCString(startup, "user"), target.User)
	startup = appendCString(appendCString(startup, "database"), target.Database)
	for _, p := range runtime {
		if RuntimeParameter(p[0]) && !strings.ContainsRune(p[1], 0) {
			startup = appendCString(appendCString(startup, p[0]), p[1])
		}
	}
	startup = append(startup, 0)
	binary.BigEndian.PutUint32(startup, uint32(len(startup))) // #nosec G115 -- a startup message is a few hundred bytes (CWE-190)
	if _, err := conn.Write(startup); err != nil {
		return nil, errors.New("pgsignin: the database closed the connection")
	}
	if err := authenticate(conn, target); err != nil {
		return nil, err
	}
	session := &Session{Conn: conn}
	for {
		kind, body, err := readMessage(conn)
		if err != nil {
			return nil, err
		}
		switch kind {
		case 'S':
			name, rest, ok := cutCString(body)
			value, _, ok2 := cutCString(rest)
			if !ok || !ok2 {
				return nil, errors.New("pgsignin: malformed parameter status")
			}
			session.Parameters = append(session.Parameters, [2]string{name, value})
		case 'K':
			if len(body) != 8 {
				return nil, errors.New("pgsignin: malformed backend key data")
			}
			session.ProcessID, session.SecretKey = binary.BigEndian.Uint32(body), binary.BigEndian.Uint32(body[4:])
		case 'Z':
			if len(body) != 1 {
				return nil, errors.New("pgsignin: malformed ready for query")
			}
			session.TxStatus = body[0]
			return session, nil
		case 'E':
			return nil, serverError("the database refused the session", body)
		case 'N', 'v':
			// Notices, and a protocol-option negotiation the gateway does
			// not need, are not the client's to see.
		default:
			return nil, fmt.Errorf("pgsignin: unexpected message %q before the session was ready", kind)
		}
	}
}

// negotiateTLS asks for TLS unless sslmode is disable or allow, and verifies
// the certificate whenever the server agrees.
func negotiateTLS(conn net.Conn, target *Target) (net.Conn, error) {
	mode := target.SSLMode
	switch mode {
	case "disable", "allow":
		return conn, nil
	case "prefer", "require", "verify-ca", "verify-full":
	default:
		return nil, fmt.Errorf("pgsignin: sslmode %q is not supported", mode)
	}
	request := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), sslRequestCode)
	if _, err := conn.Write(request); err != nil {
		return nil, errors.New("pgsignin: the database closed the connection")
	}
	answer := make([]byte, 1)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return nil, errors.New("pgsignin: the database did not answer the TLS request")
	}
	switch answer[0] {
	case 'N':
		if mode == "prefer" {
			return conn, nil
		}
		return nil, fmt.Errorf("pgsignin: sslmode %s needs TLS and the database offers none", mode)
	case 'S':
	default:
		return nil, errors.New("pgsignin: the database answered the TLS request with something else")
	}
	config := &tls.Config{ServerName: target.Host, MinVersion: tls.VersionTLS12}
	if target.serverName != "" {
		config.ServerName = target.serverName
	}
	switch {
	case len(target.rootPEM) > 0:
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(target.rootPEM) {
			return nil, errors.New("pgsignin: the session's CA holds no certificate")
		}
		config.RootCAs = roots
	case target.SSLRootCert != "" && target.SSLRootCert != "system":
		pemBytes, err := os.ReadFile(target.SSLRootCert) // #nosec G304 -- the session's DSN names the root file on the gateway's host, as libpq's sslrootcert does (CWE-22)
		if err != nil {
			return nil, errors.New("pgsignin: sslrootcert cannot be read on the gateway's host")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("pgsignin: sslrootcert holds no certificate")
		}
		config.RootCAs = roots
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("pgsignin: the database's TLS certificate does not verify: %w", err)
	}
	return tlsConn, nil
}

// authenticate answers the server's authentication request as libpq does:
// none (trust), SCRAM-SHA-256, MD5 or a cleartext password — the server's
// pg_hba decides, and a role whose password is stored as MD5 can do nothing
// else. Kerberos, GSSAPI and SSPI are refused.
func authenticate(conn net.Conn, target *Target) error {
	for {
		kind, body, err := readMessage(conn)
		if err != nil {
			return err
		}
		if kind == 'E' {
			return serverError("the database refused the session's login", body)
		}
		if kind != 'R' || len(body) < 4 {
			return fmt.Errorf("pgsignin: expected authentication, got %q", kind)
		}
		switch code := binary.BigEndian.Uint32(body); code {
		case 0:
			return nil
		case 3:
			if err := sendPassword(conn, target.Password); err != nil {
				return err
			}
		case 5:
			if len(body) != 8 {
				return errors.New("pgsignin: malformed MD5 password request")
			}
			hashed := md5Password(target.User, target.Password, body[4:8])
			err := sendPassword(conn, hashed)
			secret.Wipe(hashed)
			if err != nil {
				return err
			}
		case 10:
			if !saslOffers(body[4:], "SCRAM-SHA-256") {
				return errors.New("pgsignin: the database offers no SCRAM-SHA-256")
			}
			if err := scramSHA256(conn, target.Password); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pgsignin: authentication method %d is not supported (SCRAM-SHA-256, MD5 and password only)", code)
		}
	}
}

// sendPassword sends a PasswordMessage; the copy is wiped after the write.
func sendPassword(conn net.Conn, password []byte) error {
	msg := make([]byte, 0, len(password)+6)
	msg = append(append(append(msg, 'p', 0, 0, 0, 0), password...), 0)
	err := writeMessage(conn, msg)
	secret.Wipe(msg)
	return err
}

// md5Password is PostgreSQL's MD5 response: "md5" and the hex of
// md5(hex(md5(password || user)) || salt).
func md5Password(user string, password, salt []byte) []byte {
	inner := md5.New() // #nosec G401 -- PostgreSQL's md5 password exchange, as the server demands it (CWE-327)
	inner.Write(password)
	inner.Write([]byte(user))
	innerHex := make([]byte, hex.EncodedLen(md5.Size))
	hex.Encode(innerHex, inner.Sum(nil))
	outer := md5.New() // #nosec G401 -- PostgreSQL's md5 password exchange, as the server demands it (CWE-327)
	outer.Write(innerHex)
	outer.Write(salt)
	secret.Wipe(innerHex)
	out := make([]byte, 3, 3+hex.EncodedLen(md5.Size))
	copy(out, "md5")
	return hex.AppendEncode(out, outer.Sum(nil))
}

func saslOffers(list []byte, mechanism string) bool {
	for len(list) > 0 {
		name, rest, ok := cutCString(list)
		if !ok || name == "" {
			return false
		}
		if name == mechanism {
			return true
		}
		list = rest
	}
	return false
}

// scramSHA256 runs the client side of SCRAM-SHA-256 (RFC 5802, RFC 7677) as
// PostgreSQL does: the user name in the exchange is empty (the startup named
// the login) and channel binding is not used.
func scramSHA256(conn net.Conn, password []byte) error {
	// PostgreSQL takes the user from the startup message; the SCRAM user
	// name is empty.
	client, err := scram.NewRandom("", password)
	if err != nil {
		return err
	}
	defer client.Wipe()
	first := client.First()
	initial := appendCString([]byte{'p', 0, 0, 0, 0}, "SCRAM-SHA-256")
	initial = binary.BigEndian.AppendUint32(initial, uint32(len(first))) // #nosec G115 -- a SCRAM client-first message is under 100 bytes (CWE-190)
	initial = append(initial, first...)
	if err := writeMessage(conn, initial); err != nil {
		return err
	}
	serverFirst, err := expectAuth(conn, 11)
	if err != nil {
		return err
	}
	final, err := client.Final(serverFirst)
	if err != nil {
		return fmt.Errorf("pgsignin: %w", err)
	}
	if err := writeMessage(conn, append([]byte{'p', 0, 0, 0, 0}, final...)); err != nil {
		return err
	}
	serverFinal, err := expectAuth(conn, 12)
	if err != nil {
		return err
	}
	if err := client.Verify(serverFinal); err != nil {
		return fmt.Errorf("pgsignin: %w", err)
	}
	return nil
}

func expectAuth(conn net.Conn, code uint32) ([]byte, error) {
	kind, body, err := readMessage(conn)
	if err != nil {
		return nil, err
	}
	if kind == 'E' {
		return nil, serverError("the database refused the session's login", body)
	}
	if kind != 'R' || len(body) < 4 || binary.BigEndian.Uint32(body) != code {
		return nil, errors.New("pgsignin: the SCRAM exchange went out of order")
	}
	return body[4:], nil
}

func readMessage(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, errors.New("pgsignin: the database closed the connection during sign-in")
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length > maxSignInMessage {
		return 0, nil, errors.New("pgsignin: a sign-in message is out of bounds")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, errors.New("pgsignin: the database closed the connection during sign-in")
	}
	return header[0], body, nil
}

// writeMessage fills in msg's length (bytes 1..4) and sends it.
func writeMessage(conn net.Conn, msg []byte) error {
	binary.BigEndian.PutUint32(msg[1:], uint32(len(msg)-1)) // #nosec G115 -- sign-in messages are bounded and small (CWE-190)
	if _, err := conn.Write(msg); err != nil {
		return errors.New("pgsignin: the database closed the connection during sign-in")
	}
	return nil
}

// serverError keeps the SQLSTATE and drops the server's text, which can name
// the login.
func serverError(what string, body []byte) error {
	code := ""
	for len(body) > 1 && body[0] != 0 {
		field := body[0]
		value, rest, ok := cutCString(body[1:])
		if !ok {
			break
		}
		if field == 'C' {
			code = value
		}
		body = rest
	}
	return fmt.Errorf("pgsignin: %s (SQLSTATE %s)", what, code)
}

func appendCString(dst []byte, s string) []byte { return append(append(dst, s...), 0) }

func cutCString(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}
