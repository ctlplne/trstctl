// SPDX-License-Identifier: BUSL-1.1

// Package mongosignin signs the access gateway in to a MongoDB target as one
// session's user (A256). It reads the session's credential URI, connects to
// its primary (or its only host), authenticates with SCRAM-SHA-256 through
// saslStart and saslContinue, and returns the connection for the gateway to
// relay a stock client's messages over. It is a sign-in, not a driver: the
// session's connection carries only the SASL exchange (a hello that finds the
// primary of several hosts goes over a connection of its own), and the agent
// binary links no MongoDB driver. Every connection uses verified TLS against
// the session's CA or system roots, for the host's name.
package mongosignin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/scram"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/trust"
)

// Wire protocol operation codes.
const (
	OpReply      = 1
	OpQuery      = 2004
	OpCompressed = 2012
	OpMsg        = 2013
)

// OP_MSG flag bits.
const (
	FlagChecksumPresent = 1 << 0
	FlagMoreToCome      = 1 << 1
)

// maxSignInMessage bounds a reply the sign-in reads.
const maxSignInMessage = 1 << 20

// Target is a parsed session URI. Password is byte-backed; Wipe clears it.
type Target struct {
	Hosts      []string
	User       string
	Password   []byte
	AuthSource string
	TLS        bool
	// rootPEM and serverName are public trust from the session (A256-L1).
	rootPEM       []byte
	serverName    string
	passwordOwner *dbdsn.Target
}

// Wipe clears the password.
func (t *Target) Wipe() {
	if t.passwordOwner != nil {
		t.passwordOwner.Wipe()
		t.passwordOwner = nil
	} else {
		secret.Wipe(t.Password)
	}
	t.Password = nil
}

// ParseURI admits an explicit, bounded TCP host list and requires verified
// TLS. The job supplies private CA material by value.
func ParseURI(credential []byte) (*Target, error) {
	profile, err := dbdsn.Parse(dbdsn.Mongo, credential, dbdsn.Gateway)
	if err != nil {
		return nil, err
	}
	if profile.Options["tls"] == "false" {
		profile.Wipe()
		return nil, errors.New("mongosignin: the session requires verified TLS")
	}
	return &Target{Hosts: profile.Hosts, User: profile.User, Password: profile.Password,
		AuthSource: profile.AuthSource, TLS: true, passwordOwner: &profile}, nil
}

// Options shape one sign-in.
type Options struct {
	// Dial reaches the target; nil uses a plain dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// RootCAPEM is the target's CA as the control plane carries it with the
	// session (A256-L1): a private CA verifies the server without a CA file
	// on the gateway's host.
	// ServerName, when set, is the certificate name to verify instead of the
	// host's.
	RootCAPEM  []byte
	ServerName string
	AuthSource string
}

// SignIn connects to the credential's primary and authenticates as its
// user. The session's connection sends no hello: a server takes a client's
// metadata only in a connection's first hello, which is the stock client's
// own. With several hosts, each is asked on a connection of its own whether
// it is the writable primary (else the first that answers is used). A
// refused sign-in closes the connection.
func SignIn(ctx context.Context, credential []byte, opts Options) (net.Conn, error) {
	target, err := ParseURI(credential)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	if opts.AuthSource != "" && opts.AuthSource != target.AuthSource {
		return nil, dbdsn.ErrGatewayRoute
	}
	target.rootPEM, target.serverName = opts.RootCAPEM, opts.ServerName
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	host := target.Hosts[0]
	if len(target.Hosts) > 1 {
		host = primaryHost(ctx, dial, target)
	}
	conn, err := connect(ctx, dial, host, target)
	if err != nil {
		return nil, fmt.Errorf("mongosignin: no host of the credential answered: %w", err)
	}
	if err := authenticate(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// primaryHost probes each host on a connection of its own and returns the
// writable primary, else the first host that answered, else the first host.
func primaryHost(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), target *Target) string {
	answered := ""
	for _, host := range target.Hosts {
		conn, err := connect(ctx, dial, host, target)
		if err != nil {
			continue
		}
		primary, err := isWritablePrimary(conn)
		_ = conn.Close()
		if err != nil {
			continue
		}
		if primary {
			return host
		}
		if answered == "" {
			answered = host
		}
	}
	if answered == "" {
		return target.Hosts[0]
	}
	return answered
}

func connect(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), host string, target *Target) (net.Conn, error) {
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	name, _, _ := net.SplitHostPort(host)
	if target.serverName != "" {
		name = target.serverName
	}
	config := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	if len(target.rootPEM) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(target.rootPEM) {
			_ = conn.Close()
			return nil, errors.New("mongosignin: the session's CA holds no certificate")
		}
		config.RootCAs = roots

	}
	tlsConn := trust.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mongosignin: the server's TLS certificate does not verify: %w", err)
	}
	return tlsConn, nil
}

func isWritablePrimary(conn net.Conn) (bool, error) {
	reply, err := command(conn, []E{{"hello", int32(1)}, {"$db", "admin"}})
	if err != nil {
		return false, err
	}
	e, ok := Lookup(reply, "isWritablePrimary")
	return ok && e.Bool(), nil
}

// authenticate runs SCRAM-SHA-256 through saslStart and saslContinue.
func authenticate(conn net.Conn, target *Target) error {
	client, err := scram.NewRandom(target.User, target.Password)
	if err != nil {
		return err
	}
	defer client.Wipe()
	reply, err := command(conn, []E{{"saslStart", int32(1)}, {"mechanism", "SCRAM-SHA-256"}, {"payload", client.First()},
		{"options", []E{{"skipEmptyExchange", true}}}, {"$db", target.AuthSource}})
	if err != nil {
		return err
	}
	conversation, _ := Lookup(reply, "conversationId")
	serverFirst, ok := lookupBinary(reply, "payload")
	if !ok {
		return errors.New("mongosignin: saslStart answered without a payload")
	}
	final, err := client.Final(serverFirst)
	if err != nil {
		return fmt.Errorf("mongosignin: %w", err)
	}
	id := conversationID(conversation)
	for range 3 {
		reply, err = command(conn, []E{{"saslContinue", int32(1)}, {"conversationId", id}, {"payload", final}, {"$db", target.AuthSource}})
		if err != nil {
			return err
		}
		if serverFinal, ok := lookupBinary(reply, "payload"); ok && len(serverFinal) > 0 {
			if err := client.Verify(serverFinal); err != nil {
				return fmt.Errorf("mongosignin: %w", err)
			}
		}
		if done, ok := Lookup(reply, "done"); ok && done.Bool() {
			return nil
		}
		final = []byte{}
	}
	return errors.New("mongosignin: the SASL conversation did not finish")
}

func conversationID(e Element) any {
	if n, ok := e.Number(); ok && e.Type == TypeInt64 {
		return int64(n)
	}
	if n, ok := e.Number(); ok {
		return int32(n)
	}
	return int32(1)
}

func lookupBinary(doc []byte, key string) ([]byte, bool) {
	e, ok := Lookup(doc, key)
	if !ok {
		return nil, false
	}
	return e.Binary()
}

var requestIDs atomic.Int32

// command sends one OP_MSG command and returns its reply document, or the
// server's refusal.
func command(conn net.Conn, doc []E) ([]byte, error) {
	body := Encode(doc)
	defer secret.Wipe(body)
	msg := MessageHeader(16+4+1+len(body), requestIDs.Add(1), 0, OpMsg)
	msg = append(msg, 0, 0, 0, 0, 0)
	msg = append(msg, body...)
	_, err := conn.Write(msg)
	secret.Wipe(msg)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint32(header))
	if length < 16+5 || length > maxSignInMessage || binary.LittleEndian.Uint32(header[12:]) != OpMsg {
		return nil, errors.New("mongosignin: the server answered with something other than a message")
	}
	payload := make([]byte, length-16)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	if payload[4] != 0 {
		return nil, errors.New("mongosignin: the server's reply has no body section")
	}
	reply := payload[5:]
	if binary.LittleEndian.Uint32(payload)&FlagChecksumPresent != 0 {
		if len(reply) < 4 {
			return nil, errors.New("mongosignin: the server's reply checksum is incomplete")
		}
		reply = reply[:len(reply)-4]
	}
	if len(reply) < 5 {
		return nil, errors.New("mongosignin: the server's reply document is incomplete")
	}
	n := int(binary.LittleEndian.Uint32(reply))
	if n < 5 || n > len(reply) {
		return nil, errors.New("mongosignin: the server's reply document length is invalid")
	}
	reply = reply[:n]
	if _, err := Elements(reply); err != nil {
		return nil, fmt.Errorf("mongosignin: the server's reply document is invalid: %w", err)
	}
	if ok, found := Lookup(reply, "ok"); found {
		if v, _ := ok.Number(); v != 1 {
			msg := "refused"
			if e, ok := Lookup(reply, "errmsg"); ok {
				msg, _ = e.Text()
			}
			return nil, fmt.Errorf("mongosignin: the server refused the command: %s", msg)
		}
	}
	return reply, nil
}

// MessageHeader is a wire message's 16-byte header.
func MessageHeader(length int, requestID, responseTo int32, opCode int32) []byte {
	h := binary.LittleEndian.AppendUint32(nil, uint32(length))  // #nosec G115 -- a message length is bounded by its reader (CWE-190)
	h = binary.LittleEndian.AppendUint32(h, uint32(requestID))  // #nosec G115 -- a request id is its two's-complement bits (CWE-190)
	h = binary.LittleEndian.AppendUint32(h, uint32(responseTo)) // #nosec G115 -- a request id is its two's-complement bits (CWE-190)
	return binary.LittleEndian.AppendUint32(h, uint32(opCode))  // #nosec G115 -- an op code is a small constant (CWE-190)
}
