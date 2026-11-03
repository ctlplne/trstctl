// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// accountHost is an in-process SSH host for the rotation profile: the
// administrator's key may run only chpasswd (or sudo -n chpasswd), which sets
// passwords from stdin; local accounts log in with their password.
type accountHost struct {
	mu        sync.Mutex
	passwords map[string]string
	commands  []string
}

// startAccountHost serves with one ECDSA host key; startAccountHostKeys with
// several, as a real host does, returning each key's fingerprint.
func startAccountHost(t *testing.T, admin ssh.PublicKey) (string, string, *accountHost) {
	address, fingerprints, host := startAccountHostKeys(t, admin, ECDSAP256)
	return address, fingerprints[0], host
}

func startAccountHostKeys(t *testing.T, admin ssh.PublicKey, algorithms ...Algorithm) (string, []string, *accountHost) {
	t.Helper()
	var signers []ssh.Signer
	var fingerprints []string
	for _, algorithm := range algorithms {
		hostKey, err := GenerateLockedKey(algorithm)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(hostKey.Destroy)
		hostSigner, err := sshSignerFromDigestSigner(hostKey)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, hostSigner)
		fingerprints = append(fingerprints, ssh.FingerprintSHA256(hostSigner.PublicKey()))
	}
	host := &accountHost{passwords: map[string]string{"orders-svc": "initial"}}
	server := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != "root" || !bytes.Equal(key.Marshal(), admin.Marshal()) {
				return nil, net.ErrClosed
			}
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			host.mu.Lock()
			defer host.mu.Unlock()
			if current, ok := host.passwords[c.User()]; !ok || current != string(password) {
				return nil, net.ErrClosed
			}
			return &ssh.Permissions{}, nil
		},
	}
	for _, hostSigner := range signers {
		server.AddHostKey(hostSigner)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go host.serve(conn, server)
		}
	}()
	return listener.Addr().String(), fingerprints, host
}

func (h *accountHost) serve(conn net.Conn, server *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	connection, channels, requests, err := ssh.NewServerConn(conn, server)
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		session, requests, err := channel.Accept()
		if err != nil {
			return
		}
		for req := range requests {
			var command struct{ Command string }
			if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			h.mu.Lock()
			h.commands = append(h.commands, command.Command)
			h.mu.Unlock()
			status := uint32(1)
			if command.Command == sshChpasswdCommand || command.Command == sshChpasswdSudoCommand {
				line, _ := bufio.NewReader(io.LimitReader(session, 4096)).ReadString('\n')
				if account, password, ok := strings.Cut(strings.TrimSuffix(line, "\n"), ":"); ok {
					h.mu.Lock()
					h.passwords[account] = password
					h.mu.Unlock()
					status = 0
				}
			}
			_, _ = session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			_ = session.Close()
		}
	}
}

// A240: the local-account profile changes a password only through chpasswd
// on stdin, as the pinned host's administrator; the new password logs in and
// the old one does not; a different host key, an unsafe account name or a
// separator in the password is refused before anything runs.
func TestSSHAccountPasswordRunsOnlyChpasswdOnAPinnedHost(t *testing.T) {
	adminKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	admin, _, _, _, err := ssh.ParseAuthorizedKey(adminPublic)
	if err != nil {
		t.Fatal(err)
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(private)
	address, fingerprint, host := startAccountHost(t, admin)
	target := SSHAccountTarget{Address: address, AdminUser: "root", HostKeyFingerprint: fingerprint}
	ctx := t.Context()

	if err := VerifySSHAccountPassword(ctx, target, "orders-svc", []byte("initial")); err != nil {
		t.Fatalf("the current password: %v", err)
	}
	if err := SetSSHAccountPassword(ctx, target, private, "orders-svc", []byte("rotated-0001")); err != nil {
		t.Fatal(err)
	}
	if err := VerifySSHAccountPassword(ctx, target, "orders-svc", []byte("rotated-0001")); err != nil {
		t.Fatalf("the new password: %v", err)
	}
	if err := VerifySSHAccountPassword(ctx, target, "orders-svc", []byte("initial")); err == nil {
		t.Fatal("the old password still logs in")
	}
	sudo := target
	sudo.Sudo = true
	if err := SetSSHAccountPassword(ctx, sudo, private, "orders-svc", []byte("rotated-0002")); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	commands := strings.Join(host.commands, ";")
	host.mu.Unlock()
	if commands != sshChpasswdCommand+";"+sshChpasswdSudoCommand {
		t.Fatalf("commands run = %q", commands)
	}
	wrongPin := target
	wrongPin.HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
	for name, attempt := range map[string]func() error{
		"another host key":    func() error { return SetSSHAccountPassword(ctx, wrongPin, private, "orders-svc", []byte("x1")) },
		"unsafe account name": func() error { return SetSSHAccountPassword(ctx, target, private, "root:0:0", []byte("x2")) },
		"separator":           func() error { return SetSSHAccountPassword(ctx, target, private, "orders-svc", []byte("a:b")) },
		"newline":             func() error { return SetSSHAccountPassword(ctx, target, private, "orders-svc", []byte("a\nroot:x")) },
		"no pin": func() error {
			return VerifySSHAccountPassword(ctx, SSHAccountTarget{Address: address}, "orders-svc", []byte("x"))
		},
	} {
		if err := attempt(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.commands) != 2 || host.passwords["orders-svc"] != "rotated-0002" {
		t.Fatalf("a refused attempt reached the host: commands=%v", host.commands)
	}
}

// A240: a host holds several keys and offers the one the client prefers
// (ECDSA P-256, for Go's client). A pin of its other key still connects: the
// client tries one host-key algorithm at a time until the pinned key is
// presented, checking each before any credential is sent.
func TestSSHAccountPinOfAnyHostKeyConnects(t *testing.T) {
	adminKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	admin, _, _, _, err := ssh.ParseAuthorizedKey(adminPublic)
	if err != nil {
		t.Fatal(err)
	}
	address, fingerprints, _ := startAccountHostKeys(t, admin, ECDSAP256, ECDSAP384)
	for i, fingerprint := range fingerprints {
		target := SSHAccountTarget{Address: address, HostKeyFingerprint: fingerprint}
		if err := VerifySSHAccountPassword(t.Context(), target, "orders-svc", []byte("initial")); err != nil {
			t.Fatalf("pin of host key %d: %v", i, err)
		}
	}
	other := SSHAccountTarget{Address: address, HostKeyFingerprint: "SHA256:" + strings.Repeat("B", 43)}
	if err := VerifySSHAccountPassword(t.Context(), other, "orders-svc", []byte("initial")); err == nil {
		t.Fatal("a pin of no host key connected")
	}
}
