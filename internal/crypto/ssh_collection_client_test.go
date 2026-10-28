// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestSSHCollectionPinsHostAndExecutesOnlyFixedReadOnlyHelper(t *testing.T) {
	hostKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer hostKey.Destroy()
	hostSigner, err := sshSignerFromDigestSigner(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer clientKey.Destroy()
	clientPublic, err := SSHPublicKeyFromSigner(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _, _, _, err := ssh.ParseAuthorizedKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	der, err := clientKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(private)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var auths, commands, authenticationFinished atomic.Int32
	server := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auths.Add(1)
		if c.User() != "trstctl_observe" || !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, net.ErrClosed
		}
		return &ssh.Permissions{}, nil
	}}
	server.AddHostKey(hostSigner)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				connection, channels, requests, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				defer func() { _ = connection.Close() }()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "only fixed read-only sessions")
						continue
					}
					session, requests, err := channel.Accept()
					if err != nil {
						return
					}
					for req := range requests {
						var command struct{ Command string }
						if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != sshCollectionFixedCommand {
							_ = req.Reply(false, nil)
							continue
						}
						commands.Add(1)
						if authenticationFinished.Load() != 1 {
							t.Error("authentication credential was retained until public readback")
						}
						_ = req.Reply(true, nil)
						_, _ = session.Write([]byte(`{"version":1,"profile":"owned-public-fixture"}`))
						_, _ = session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = session.Close()
						break
					}
				}
			}()
		}
	}()
	validPin := ssh.FingerprintSHA256(hostSigner.PublicKey())
	badHash, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(validPin, "SHA256:"))
	if err != nil {
		t.Fatal(err)
	}
	badHash[0] ^= 1
	cfg := SSHCollectionConnection{Address: listener.Addr().String(), Username: "trstctl_observe", HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(badHash), DialControl: func(_, address string, _ syscall.RawConn) error {
		if address != listener.Addr().String() {
			return errors.New("outside owned test endpoint")
		}
		return nil
	}}
	if body, err := ReadSSHCollection(t.Context(), cfg, private); err == nil || len(body) != 0 || auths.Load() != 0 {
		t.Fatalf("wrong host pin reached authentication: auth=%d err=%v", auths.Load(), err)
	}
	cfg.HostKeyFingerprint = validPin
	cfg.AuthenticationDone = func() { secret.Wipe(private); authenticationFinished.Add(1) }
	body, err := ReadSSHCollection(t.Context(), cfg, private)
	if err != nil || !bytes.Contains(body, []byte("owned-public-fixture")) || commands.Load() != 1 {
		t.Fatalf("fixed collector execution: body=%s count=%d err=%v", body, commands.Load(), err)
	}
	if authenticationFinished.Load() != 1 || !bytes.Equal(private, make([]byte, len(private))) {
		t.Fatal("authentication callback did not erase borrowed bytes before public readback")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	before := auths.Load()
	if _, err := ReadSSHCollection(canceled, cfg, private); err == nil || auths.Load() != before {
		t.Fatal("canceled collection contacted the server")
	}
	_ = listener.Close()
	<-finished
}
