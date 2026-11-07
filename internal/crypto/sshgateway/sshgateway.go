// SPDX-License-Identifier: BUSL-1.1

// Package sshgateway is the SSH half of the credential-hidden access gateway
// (A254), kept inside the crypto boundary (AN-3). It holds one session's
// per-session key in locked memory with the user certificate the tenant's SSH
// CA issued for it, serves stock SSH clients that reached the gateway through
// its ticketed, TLS-verified tunnel, and signs in upstream as the session's
// principal, relaying session channels (shell, exec, sftp) and nothing else.
// The client never holds a key, a certificate or a password for the target.
package sshgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto"
)

// HostKey is the gateway's own host key for the client side of its SSH
// sessions. A client verifies it through the known_hosts entry the trstctl
// CLI writes from the gateway's TLS-verified admission answer.
type HostKey struct {
	key    *crypto.LockedSigner
	signer ssh.Signer
	line   string
}

// NewHostKey generates a host key in locked memory.
func NewHostKey() (*HostKey, error) {
	key, signer, err := newLockedSSHKey()
	if err != nil {
		return nil, err
	}
	return &HostKey{key: key, signer: signer, line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}, nil
}

// AuthorizedKey is the host key in authorized_keys form ("ecdsa-sha2-nistp256 AAAA...").
func (h *HostKey) AuthorizedKey() string { return h.line }

// Destroy wipes the host key.
func (h *HostKey) Destroy() { h.key.Destroy() }

// SessionKey is one session's upstream identity: a key generated for the
// session and destroyed with it, and the certificate issued for it.
type SessionKey struct {
	key    *crypto.LockedSigner
	signer ssh.Signer
	mu     sync.Mutex
	cert   ssh.Signer
}

// NewSessionKey generates a session key in locked memory.
func NewSessionKey() (*SessionKey, error) {
	key, signer, err := newLockedSSHKey()
	if err != nil {
		return nil, err
	}
	return &SessionKey{key: key, signer: signer}, nil
}

// PublicKey is the session key in authorized_keys form, for certification.
func (k *SessionKey) PublicKey() []byte { return ssh.MarshalAuthorizedKey(k.signer.PublicKey()) }

// Certify adopts the user certificate issued for this key and returns when it
// stops working. A certificate for any other key, or a host certificate, is
// refused.
func (k *SessionKey) Certify(certificate []byte) (time.Time, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certificate)
	if err != nil {
		return time.Time{}, errors.New("sshgateway: the session certificate does not parse")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return time.Time{}, errors.New("sshgateway: the session credential is not a user certificate")
	}
	if !bytes.Equal(cert.Key.Marshal(), k.signer.PublicKey().Marshal()) {
		return time.Time{}, errors.New("sshgateway: the session certificate is for another key")
	}
	signer, err := ssh.NewCertSigner(cert, k.signer)
	if err != nil {
		return time.Time{}, fmt.Errorf("sshgateway: adopt the session certificate: %w", err)
	}
	k.mu.Lock()
	k.cert = signer
	k.mu.Unlock()
	return time.Unix(int64(cert.ValidBefore), 0), nil // #nosec G115 -- an OpenSSH certificate's valid-before is a Unix time (CWE-190)
}

// Destroy wipes the session key; a sign-in that has not finished fails.
func (k *SessionKey) Destroy() { k.key.Destroy() }

func (k *SessionKey) certified() ssh.Signer {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.cert
}

func newLockedSSHKey() (*crypto.LockedSigner, ssh.Signer, error) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, nil, err
	}
	signer, err := crypto.SSHSigner(key)
	if err != nil {
		key.Destroy()
		return nil, nil, err
	}
	return key, signer, nil
}

// Upstream is where and as whom a session signs in.
type Upstream struct {
	// Address is the target's host:port; User the session's principal.
	Address, User string
	// HostKeyFingerprints pin the target's host keys (SHA256:...). A host
	// certificate is accepted when it, or the key it certifies, is pinned.
	HostKeyFingerprints []string
	// Dial reaches the target; nil uses a plain dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Recorder sees one connection's session traffic inside the gateway, before
// any of it leaves (A255). A call that blocks holds that stream's traffic:
// a recorder that cannot keep up slows the session, it never loses data.
type Recorder interface {
	// Data is bytes on session channel ch: stream "in" from the client,
	// "out" and "err" from the target.
	Data(ch int, stream string, p []byte)
	// Request is a session request relayed on channel ch: from the client
	// (pty-req, env, shell, exec, subsystem, window-change, signal, ...) or
	// from the target (exit-status, exit-signal, ...).
	Request(ch int, from, kind string, payload []byte)
}

// clientRequests are the session requests a client may make through the
// gateway; agent and X11 forwarding are refused.
var clientRequests = []string{"pty-req", "env", "shell", "exec", "subsystem", "window-change", "signal", "break", "keepalive@openssh.com"}

// Serve speaks SSH to one admitted client connection and relays its session
// channels to the upstream target, signed in with the session's certificate.
// rec, when set, sees every relayed byte and request. It returns when the
// client or the target goes away; the caller closes the client connection to
// end it early (revocation, deadline).
func Serve(ctx context.Context, client net.Conn, host *HostKey, key *SessionKey, up Upstream, rec Recorder) error {
	return ServeGuarded(ctx, client, host, key, up, rec, nil)
}

// RequestGuard evaluates a post-authentication session request. Its payload is
// borrowed for this call only. A false answer refuses it before target forwarding.
type RequestGuard struct {
	Inspect func(context.Context, string, []byte) bool
	Reserve func(int) (func(), bool)
}

// ServeGuarded adds a separate guard per channel. Nil preserves ordinary SSH.
func ServeGuarded(ctx context.Context, client net.Conn, host *HostKey, key *SessionKey, up Upstream, rec Recorder, guards func() *RequestGuard) error {
	signer := key.certified()
	if signer == nil {
		return errors.New("sshgateway: the session key is not certified")
	}
	return serve(ctx, client, host, []ssh.AuthMethod{ssh.PublicKeys(signer)}, up, rec, guards)
}

// ServeGuardedPassword is ServeGuarded for a target whose vaulted account
// signs in with a password (A270, network devices): the gateway signs in
// upstream as up.User with password, by password or keyboard-interactive
// authentication as the device asks. The client never holds the password;
// the caller keeps and wipes it.
func ServeGuardedPassword(ctx context.Context, client net.Conn, host *HostKey, password []byte, up Upstream, rec Recorder, guards func() *RequestGuard) error {
	if len(password) == 0 {
		return errors.New("sshgateway: the session has no vaulted password")
	}
	return serve(ctx, client, host, passwordAuth(password), up, rec, guards)
}

// passwordAuth answers a password or keyboard-interactive sign-in with
// password. x/crypto/ssh takes it as a string, built per attempt from the
// caller's bytes and not kept.
func passwordAuth(password []byte) []ssh.AuthMethod {
	answer := func() (string, error) { return string(password), nil }
	interactive := func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = string(password)
		}
		return answers, nil
	}
	return []ssh.AuthMethod{ssh.PasswordCallback(answer), ssh.KeyboardInteractive(interactive)}
}

func serve(ctx context.Context, client net.Conn, host *HostKey, auth []ssh.AuthMethod, up Upstream, rec Recorder, guards func() *RequestGuard) error {
	// The ticketed, TLS-verified tunnel is the client's authentication; the
	// client side asks for none.
	serverConfig := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-trstctl-access-gateway"}
	serverConfig.AddHostKey(host.signer)
	sconn, channels, requests, err := ssh.NewServerConn(client, serverConfig)
	if err != nil {
		return fmt.Errorf("sshgateway: client handshake: %w", err)
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(requests) // global requests: no forwarding of any kind
	upstream, err := dialUpstream(ctx, up, auth)
	if err != nil {
		for nc := range channels {
			_ = nc.Reject(ssh.ConnectionFailed, "the access gateway could not sign in to the target")
		}
		return err
	}
	// The target ending the connection ends the client's too.
	go func() {
		_ = upstream.Wait()
		_ = sconn.Close()
	}()
	var relays sync.WaitGroup
	next := 0
	slots := make(chan struct{}, 32)
	for nc := range channels {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "the access gateway relays sessions only")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = nc.Reject(ssh.ResourceShortage, "the access gateway channel capacity is full")
			continue
		}
		relays.Add(1)
		next++
		go func(ch int) {
			defer relays.Done()
			defer func() { <-slots }()
			var guard *RequestGuard
			if guards != nil {
				guard = guards()
			}
			relaySession(ctx, nc, upstream, ch, rec, guard)
		}(next)
	}
	// The client is gone: end the target connection, then the relays.
	_ = upstream.Close()
	relays.Wait()
	return nil
}

func dialUpstream(ctx context.Context, up Upstream, auth []ssh.AuthMethod) (*ssh.Client, error) {
	if up.Address == "" || up.User == "" || len(up.HostKeyFingerprints) == 0 {
		return nil, errors.New("sshgateway: a target address, principal and host key pin are required")
	}
	dial := up.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := dial(dialCtx, "tcp", up.Address)
	if err != nil {
		return nil, errors.New("sshgateway: the target is unreachable")
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	config := &ssh.ClientConfig{
		User:            up.User,
		Auth:            auth,
		HostKeyCallback: pinnedHostKey(up.HostKeyFingerprints),
		Timeout:         15 * time.Second,
	}
	c, channels, requests, err := ssh.NewClientConn(conn, up.Address, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshgateway: sign in to the target: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, channels, requests), nil
}

// pinnedHostKey accepts only a pinned host key, or a host certificate that is
// pinned itself or certifies a pinned key.
func pinnedHostKey(fingerprints []string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		offered := key
		if cert, ok := key.(*ssh.Certificate); ok {
			if cert.CertType != ssh.HostCert {
				return errors.New("sshgateway: the target presented no host identity")
			}
			if !slices.Contains(fingerprints, ssh.FingerprintSHA256(cert)) {
				offered = cert.Key
			}
		}
		if !slices.Contains(fingerprints, ssh.FingerprintSHA256(offered)) {
			return errors.New("sshgateway: the target's host key is not one its pins name")
		}
		return nil
	}
}

// relaySession bridges one client session channel to a new upstream one: the
// data both ways, the client's allowed requests up and the target's requests
// (exit-status, exit-signal) down, then the close. rec sees all of it.
func relaySession(ctx context.Context, nc ssh.NewChannel, upstream *ssh.Client, ch int, rec Recorder, guard *RequestGuard) {
	up, upRequests, err := upstream.OpenChannel("session", nc.ExtraData())
	if err != nil {
		var refused *ssh.OpenChannelError
		if errors.As(err, &refused) {
			_ = nc.Reject(refused.Reason, refused.Message)
		} else {
			_ = nc.Reject(ssh.ConnectionFailed, "the target refused the session")
		}
		return
	}
	down, downRequests, err := nc.Accept()
	if err != nil {
		_ = up.Close()
		return
	}
	// replying is held across each relayed client request, so the channel is
	// not closed between the target's answer and the client receiving it.
	var replying sync.Mutex
	go func() {
		if guard == nil {
			forwardRequests(downRequests, up, &replying, func(kind string) bool { return slices.Contains(clientRequests, kind) }, recordRequest(rec, ch, "client"))
		} else {
			forwardGuardedRequests(ctx, downRequests, up, down, &replying, guard, recordRequest(rec, ch, "client"))
		}
		// The client closed its channel: close the target's, so a process
		// that outlives its input does not hold the relay open.
		_ = up.Close()
	}()
	targetRequestsDone := make(chan struct{})
	go func() {
		defer close(targetRequestsDone)
		forwardRequests(upRequests, down, nil, func(string) bool { return true }, recordRequest(rec, ch, "target"))
	}()
	go func() {
		_, _ = io.Copy(up, recorded(down, rec, ch, "in"))
		_ = up.CloseWrite()
	}()
	var output sync.WaitGroup
	output.Add(2)
	go func() {
		defer output.Done()
		_, _ = io.Copy(down, recorded(up, rec, ch, "out"))
	}()
	go func() {
		defer output.Done()
		_, _ = io.Copy(down.Stderr(), recorded(up.Stderr(), rec, ch, "err"))
	}()
	output.Wait()
	_ = down.CloseWrite()
	// The target's exit-status reaches the client before the channel closes.
	<-targetRequestsDone
	replying.Lock()
	_ = down.Close()
	replying.Unlock()
	_ = up.Close()
}

func forwardRequests(in <-chan *ssh.Request, out ssh.Channel, replying *sync.Mutex, allowed func(string) bool, seen func(*ssh.Request)) {
	for req := range in {
		if !allowed(req.Type) {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		seen(req)
		if replying != nil {
			replying.Lock()
		}
		ok, err := out.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(ok && err == nil, nil)
		}
		if replying != nil {
			replying.Unlock()
		}
	}
}

// recordedReader passes reads through to the recorder before returning them,
// so a blocked recorder holds the stream.
type recordedReader struct {
	r      io.Reader
	rec    Recorder
	ch     int
	stream string
}

func recorded(r io.Reader, rec Recorder, ch int, stream string) io.Reader {
	if rec == nil {
		return r
	}
	return &recordedReader{r: r, rec: rec, ch: ch, stream: stream}
}

func (r *recordedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.rec.Data(r.ch, r.stream, p[:n])
	}
	return n, err
}

func recordRequest(rec Recorder, ch int, from string) func(*ssh.Request) {
	if rec == nil {
		return func(*ssh.Request) {}
	}
	return func(req *ssh.Request) { rec.Request(ch, from, req.Type, req.Payload) }
}
