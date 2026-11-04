// SPDX-License-Identifier: BUSL-1.1

// Package mysqlsignin signs the access gateway in to a MySQL target as one
// session's account (A256). The gateway answers a stock client's handshake
// itself and signs in upstream with the session's DSN, using the client's own
// capability flags so the relayed command phase means the same to both ends.
// Authentication follows the server: caching_sha2_password (the fast path, or
// full authentication with the password encrypted to the server's RSA key, as
// a driver does without TLS) or mysql_native_password. It is a sign-in, not a
// driver: it sends no command, and the agent binary links no database driver.
package mysqlsignin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- MySQL's mysql_native_password and the RSA-OAEP padding its servers use (CWE-327)
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Capability flags the sign-in reads or sets.
const (
	ClientLongPassword               uint32 = 1 << 0
	ClientConnectWithDB              uint32 = 1 << 3
	ClientCompress                   uint32 = 1 << 5
	ClientProtocol41                 uint32 = 1 << 9
	ClientSSL                        uint32 = 1 << 11
	ClientSecureConnection           uint32 = 1 << 15
	ClientPluginAuth                 uint32 = 1 << 19
	ClientConnectAttrs               uint32 = 1 << 20
	ClientPluginAuthLenencClientData uint32 = 1 << 21
	ClientSessionTrack               uint32 = 1 << 23
	ClientDeprecateEOF               uint32 = 1 << 24
	ClientZstdCompression            uint32 = 1 << 26
	ClientQueryAttributes            uint32 = 1 << 27
	ClientSSLVerifyServerCert        uint32 = 1 << 30
	ClientRememberOptions            uint32 = 1 << 31
)

// gatewayOnly are the flags the gateway never passes on: transport choices
// (TLS, compression) belong to each hop, connect attributes and the
// database are the gateway's to send.
const gatewayOnly = ClientSSL | ClientCompress | ClientZstdCompression | ClientConnectAttrs | ClientSSLVerifyServerCert | ClientRememberOptions | ClientConnectWithDB

// required are the flags the sign-in's own encoding needs.
const required = ClientProtocol41 | ClientSecureConnection | ClientPluginAuth | ClientPluginAuthLenencClientData

// maxPacket bounds a sign-in packet the gateway reads.
const maxPacket = 1 << 16

// Target is a parsed session DSN. Password is byte-backed; Wipe clears it.
type Target struct {
	Address, User, Database string
	Password                []byte
}

// Wipe clears the password.
func (t *Target) Wipe() { secret.Wipe(t.Password) }

// ParseDSN reads a session DSN, user:password@tcp(host:port)/database, with
// optional parameters after "?" (ignored: the sign-in sets its own).
func ParseDSN(dsn []byte) (*Target, error) {
	at := bytes.LastIndex(dsn, []byte("@tcp("))
	if at <= 0 {
		return nil, errors.New("mysqlsignin: the DSN is not user:password@tcp(host:port)/database")
	}
	userinfo, rest := dsn[:at], dsn[at+len("@tcp("):]
	colon := bytes.IndexByte(userinfo, ':')
	if colon <= 0 || colon == len(userinfo)-1 {
		return nil, errors.New("mysqlsignin: the DSN has no user and password")
	}
	closing := bytes.IndexByte(rest, ')')
	if closing <= 0 || len(rest) <= closing+1 || rest[closing+1] != '/' {
		return nil, errors.New("mysqlsignin: the DSN's address is not tcp(host:port)/")
	}
	address := string(rest[:closing])
	host, port, err := net.SplitHostPort(address)
	if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
		return nil, errors.New("mysqlsignin: the DSN's address is not host:port")
	}
	database, _, _ := strings.Cut(string(rest[closing+2:]), "?")
	password := make([]byte, len(userinfo)-colon-1)
	copy(password, userinfo[colon+1:])
	return &Target{Address: address, User: string(userinfo[:colon]), Database: database, Password: password}, nil
}

// Handshake is a server's initial handshake (protocol version 10).
type Handshake struct {
	ServerVersion string
	ConnectionID  uint32
	Capabilities  uint32
	Charset       byte
	Status        uint16
	AuthPlugin    string
	// Scramble is the 20-byte nonce authentication answers.
	Scramble []byte
}

// ReadPacket reads one packet: its sequence number and payload, under
// maxPacket.
func ReadPacket(r io.Reader) (byte, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size > maxPacket {
		return 0, nil, errors.New("mysqlsignin: a sign-in packet is too large")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[3], payload, nil
}

// WritePacket writes one packet with its sequence number.
func WritePacket(w io.Writer, seq byte, payload []byte) error {
	if len(payload) > 1<<24-1 {
		return errors.New("mysqlsignin: a sign-in packet is too large")
	}
	n := len(payload)
	packet := make([]byte, 4, 4+n)
	packet[0], packet[1], packet[2], packet[3] = byte(n), byte(n>>8), byte(n>>16), seq // #nosec G115 -- the 3-byte little-endian length of a payload checked above (CWE-190)
	_, err := w.Write(append(packet, payload...))
	secret.Wipe(packet)
	return err
}

// ParseHandshake reads a protocol-10 handshake payload.
func ParseHandshake(p []byte) (*Handshake, error) {
	if len(p) < 1 || p[0] != 10 {
		if len(p) > 0 && p[0] == 0xff {
			return nil, fmt.Errorf("mysqlsignin: the server refused the connection: %s", errText(p))
		}
		return nil, errors.New("mysqlsignin: the server's handshake is not protocol 10")
	}
	version, rest, ok := cutNul(p[1:])
	if !ok || len(rest) < 4+8+1+2+1+2+2+1+10 {
		return nil, errors.New("mysqlsignin: the server's handshake is short")
	}
	h := &Handshake{ServerVersion: version, ConnectionID: binary.LittleEndian.Uint32(rest)}
	scramble := append([]byte(nil), rest[4:12]...)
	rest = rest[13:]
	h.Capabilities = uint32(binary.LittleEndian.Uint16(rest))
	h.Charset = rest[2]
	h.Status = binary.LittleEndian.Uint16(rest[3:])
	h.Capabilities |= uint32(binary.LittleEndian.Uint16(rest[5:])) << 16
	authLen := int(rest[7])
	rest = rest[18:]
	if h.Capabilities&ClientSecureConnection != 0 {
		n := max(13, authLen-8)
		if len(rest) < n {
			return nil, errors.New("mysqlsignin: the server's handshake is short")
		}
		scramble = append(scramble, bytes.TrimRight(rest[:n], "\x00")...)
		rest = rest[n:]
	}
	if h.Capabilities&ClientPluginAuth != 0 {
		h.AuthPlugin, _, _ = cutNul(rest)
	}
	if len(scramble) != 20 {
		return nil, errors.New("mysqlsignin: the server's scramble is not 20 bytes")
	}
	h.Scramble = scramble
	return h, nil
}

// ClientHandshake is the handshake the gateway sends a client: the server's
// version, connection id, character set and status, its capabilities without
// TLS or compression, the gateway's own scramble, and caching_sha2_password.
// The client's answer is never checked — the admitted tunnel authenticated it.
func ClientHandshake(server *Handshake) ([]byte, error) {
	scramble := make([]byte, 20)
	if _, err := rand.Read(scramble); err != nil {
		return nil, err
	}
	for i := range scramble {
		scramble[i] = scramble[i]%94 + 33 // printable, never NUL, as servers send
	}
	caps := (server.Capabilities | required) &^ (ClientSSL | ClientCompress | ClientZstdCompression)
	p := []byte{10}
	p = append(append(p, server.ServerVersion...), 0)
	p = binary.LittleEndian.AppendUint32(p, server.ConnectionID)
	p = append(append(p, scramble[:8]...), 0)
	p = binary.LittleEndian.AppendUint16(p, uint16(caps)) // #nosec G115 -- the capability flags' lower half (CWE-190)
	p = append(p, server.Charset)
	p = binary.LittleEndian.AppendUint16(p, server.Status)
	p = binary.LittleEndian.AppendUint16(p, uint16(caps>>16)) // #nosec G115 -- the capability flags' upper half (CWE-190)
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(append(p, scramble[8:]...), 0)
	return append(append(p, "caching_sha2_password"...), 0), nil
}

// ClientResponse is what the gateway keeps of a client's HandshakeResponse41:
// the flags and character set it speaks and the database it asked for.
type ClientResponse struct {
	Capabilities uint32
	Charset      byte
	Database     string
	// SSLRequest is set when the client asked for TLS, which the gateway's
	// handshake never offers.
	SSLRequest bool
}

// ParseClientResponse reads a client's HandshakeResponse41.
func ParseClientResponse(p []byte) (*ClientResponse, error) {
	if len(p) < 32 {
		return nil, errors.New("mysqlsignin: the client's handshake response is short")
	}
	r := &ClientResponse{Capabilities: binary.LittleEndian.Uint32(p), Charset: p[8]}
	if r.Capabilities&ClientProtocol41 == 0 {
		return nil, errors.New("mysqlsignin: the client does not speak protocol 4.1")
	}
	if len(p) == 32 && r.Capabilities&ClientSSL != 0 {
		r.SSLRequest = true
		return r, nil
	}
	_, rest, ok := cutNul(p[32:])
	if !ok {
		return nil, errors.New("mysqlsignin: the client's user is not terminated")
	}
	switch {
	case r.Capabilities&ClientPluginAuthLenencClientData != 0:
		n, used, ok := lenenc(rest)
		if !ok || len(rest)-used < n {
			return nil, errors.New("mysqlsignin: the client's auth response is short")
		}
		rest = rest[used+n:]
	case r.Capabilities&ClientSecureConnection != 0:
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return nil, errors.New("mysqlsignin: the client's auth response is short")
		}
		rest = rest[1+int(rest[0]):]
	default:
		if _, rest, ok = cutNul(rest); !ok {
			return nil, errors.New("mysqlsignin: the client's auth response is not terminated")
		}
	}
	if r.Capabilities&ClientConnectWithDB != 0 {
		r.Database, _, _ = cutNul(rest)
	}
	return r, nil
}

// SignIn answers the server's handshake as the target's account, speaking the
// client's capability flags (less what each hop chooses for itself), and
// returns the server's final OK payload.
func SignIn(conn net.Conn, server *Handshake, target *Target, client *ClientResponse) ([]byte, error) {
	caps := (client.Capabilities&server.Capabilities)&^gatewayOnly | required
	database := target.Database
	if database == "" {
		database = client.Database
	}
	if database != "" {
		caps |= ClientConnectWithDB
	}
	plugin := server.AuthPlugin
	if plugin == "" {
		plugin = "mysql_native_password"
	}
	auth, err := scramble(plugin, target.Password, server.Scramble)
	if err != nil {
		return nil, err
	}
	p := binary.LittleEndian.AppendUint32(nil, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24)
	p = append(p, client.Charset)
	p = append(p, make([]byte, 23)...)
	p = append(append(p, target.User...), 0)
	p = append(appendLenenc(p, len(auth)), auth...)
	secret.Wipe(auth)
	if caps&ClientConnectWithDB != 0 {
		p = append(append(p, database...), 0)
	}
	p = append(append(p, plugin...), 0)
	err = WritePacket(conn, 1, p)
	secret.Wipe(p)
	if err != nil {
		return nil, err
	}
	nonce := server.Scramble
	for range 4 {
		seq, reply, err := ReadPacket(conn)
		if err != nil {
			return nil, err
		}
		if len(reply) == 0 {
			return nil, errors.New("mysqlsignin: the server sent an empty sign-in reply")
		}
		switch reply[0] {
		case 0x00:
			return reply, nil
		case 0xff:
			return nil, fmt.Errorf("mysqlsignin: the server refused the session's account: %s", errText(reply))
		case 0xfe:
			// Auth switch: the server names another plugin and nonce.
			name, data, ok := cutNul(reply[1:])
			if !ok {
				return nil, errors.New("mysqlsignin: a malformed auth switch")
			}
			plugin, nonce = name, bytes.TrimRight(data, "\x00")
			answer, err := scramble(plugin, target.Password, nonce)
			if err != nil {
				return nil, err
			}
			err = WritePacket(conn, seq+1, answer)
			secret.Wipe(answer)
			if err != nil {
				return nil, err
			}
		case 0x01:
			if plugin != "caching_sha2_password" || len(reply) < 2 {
				return nil, errors.New("mysqlsignin: unexpected authentication data")
			}
			switch reply[1] {
			case 0x03: // fast authentication succeeded; the OK follows
				continue
			case 0x04: // full authentication: ask for the server's RSA key
				if err := WritePacket(conn, seq+1, []byte{0x02}); err != nil {
					return nil, err
				}
				keySeq, keyReply, err := ReadPacket(conn)
				if err != nil {
					return nil, err
				}
				if len(keyReply) < 2 || keyReply[0] != 0x01 {
					return nil, errors.New("mysqlsignin: the server sent no RSA key")
				}
				encrypted, err := encryptPassword(target.Password, nonce, keyReply[1:])
				if err != nil {
					return nil, err
				}
				if err := WritePacket(conn, keySeq+1, encrypted); err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("mysqlsignin: unexpected caching_sha2_password state")
			}
		default:
			return nil, errors.New("mysqlsignin: unexpected sign-in reply")
		}
	}
	return nil, errors.New("mysqlsignin: the sign-in did not finish")
}

// scramble answers a nonce for the named plugin.
func scramble(plugin string, password, nonce []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, nil
	}
	switch plugin {
	case "caching_sha2_password":
		first := sha256.Sum256(password)
		second := sha256.Sum256(first[:])
		third := sha256.New()
		third.Write(second[:])
		third.Write(nonce)
		mix := third.Sum(nil)
		out := make([]byte, len(first))
		for i := range out {
			out[i] = first[i] ^ mix[i]
		}
		secret.Wipe(first[:])
		return out, nil
	case "mysql_native_password":
		first := sha1.Sum(password)  // #nosec G401 -- mysql_native_password, when the server demands it (CWE-327)
		second := sha1.Sum(first[:]) // #nosec G401 -- mysql_native_password (CWE-327)
		third := sha1.New()          // #nosec G401 -- mysql_native_password (CWE-327)
		third.Write(nonce)
		third.Write(second[:])
		mix := third.Sum(nil)
		out := make([]byte, len(first))
		for i := range out {
			out[i] = first[i] ^ mix[i]
		}
		secret.Wipe(first[:])
		return out, nil
	}
	return nil, fmt.Errorf("mysqlsignin: the server asks for %q, which the gateway does not answer", plugin)
}

// encryptPassword encrypts the password (with its terminating NUL, mixed
// with the nonce) to the server's RSA key with OAEP, as a driver does for
// full authentication without TLS.
func encryptPassword(password, nonce, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("mysqlsignin: the server's RSA key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mysqlsignin: the server's RSA key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("mysqlsignin: the server's key is not RSA")
	}
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		plain[i] ^= nonce[i%len(nonce)]
	}
	defer secret.Wipe(plain)
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, plain, nil) // #nosec G401 -- the OAEP hash MySQL servers use (CWE-327)
}

func errText(p []byte) string {
	if len(p) < 3 {
		return "unknown error"
	}
	code := binary.LittleEndian.Uint16(p[1:])
	msg := p[3:]
	if len(msg) > 6 && msg[0] == '#' {
		msg = msg[6:]
	}
	return fmt.Sprintf("%d %s", code, strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, string(msg)))
}

func cutNul(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// lenenc reads a length-encoded integer: its value and the bytes it took.
// A value past maxLenenc is refused: no handshake field is that long.
func lenenc(b []byte) (int, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return int(binary.LittleEndian.Uint16(b[1:])), 3, true
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return int(b[1]) | int(b[2])<<8 | int(b[3])<<16, 4, true
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		v := binary.LittleEndian.Uint64(b[1:])
		if v > maxLenenc {
			return 0, 0, false
		}
		return int(v), 9, true // #nosec G115 -- bounded by maxLenenc just above (CWE-190)
	case 0xfb, 0xff:
		return 0, 0, false
	}
	return int(b[0]), 1, true
}

// maxLenenc bounds a length-encoded value the sign-in accepts.
const maxLenenc = 1 << 24

func appendLenenc(b []byte, n int) []byte {
	switch {
	case n < 251:
		return append(b, byte(n)) // #nosec G115 -- a one-byte length below 251 (CWE-190)
	case n < 1<<16:
		return binary.LittleEndian.AppendUint16(append(b, 0xfc), uint16(n)) // #nosec G115 -- a two-byte length below 1<<16 (CWE-190)
	case n < 1<<24:
		return append(b, 0xfd, byte(n), byte(n>>8), byte(n>>16)) // #nosec G115 -- the three bytes of a value under 1<<24 (CWE-190)
	}
	return binary.LittleEndian.AppendUint64(append(b, 0xfe), uint64(n)) // #nosec G115 -- a length, never negative (CWE-190)
}
