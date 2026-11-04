// SPDX-License-Identifier: BUSL-1.1

package sshgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// upstreamSSH is a target that trusts one user CA for one principal and
// answers exec with what it ran, as a stock sshd configured with
// TrustedUserCAKeys would admit the gateway's session certificate.
type upstreamSSH struct {
	addr        string
	fingerprint string
	ca          ssh.Signer
}

func startUpstream(t *testing.T, principal string) upstreamSSH {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{IsUserAuthority: func(auth ssh.PublicKey) bool {
		return bytes.Equal(auth.Marshal(), ca.PublicKey().Marshal())
	}}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if _, ok := key.(*ssh.Certificate); !ok {
			return nil, errors.New("certificates only")
		}
		return checker.Authenticate(meta, key)
	}}
	config.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(requests)
				for nc := range channels {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.Prohibited, "sessions only")
						continue
					}
					ch, reqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer func() { _ = ch.Close() }()
						for req := range reqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							command := string(req.Payload[4:])
							_, _ = ch.Write([]byte(sconn.User() + " ran " + command + "\n"))
							status := make([]byte, 4)
							binary.BigEndian.PutUint32(status, 0)
							_, _ = ch.SendRequest("exit-status", false, status)
							return
						}
					}()
				}
			}()
		}
	}()
	return upstreamSSH{addr: ln.Addr().String(), fingerprint: ssh.FingerprintSHA256(hostSigner.PublicKey()), ca: ca}
}

func certify(t *testing.T, key *SessionKey, ca ssh.Signer, principal string, certType uint32) []byte {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: pub, CertType: certType, KeyId: "pam:session-1", ValidPrincipals: []string{principal},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()), // #nosec G115 -- present-day Unix times are positive (CWE-190)
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(cert)
}

// gatewayFor serves one client connection through the gateway and returns a
// stock-style SSH client (no key, no password) connected through it.
func gatewayFor(t *testing.T, host *HostKey, key *SessionKey, up Upstream) *ssh.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = Serve(context.Background(), conn, host, key, up, nil)
		_ = conn.Close()
	}()
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(host.AuthorizedKey()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "anyone", HostKeyCallback: ssh.FixedHostKey(hostPub), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("client through the gateway: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGatewaySignsInAsThePrincipalForAClientWithNoCredentialA254(t *testing.T) {
	target := startUpstream(t, "alice")
	host, err := NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Destroy()
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	validBefore, err := key.Certify(certify(t, key, target.ca, "alice", ssh.UserCert))
	if err != nil || time.Until(validBefore) < 50*time.Minute {
		t.Fatalf("certify = %v, %v", validBefore, err)
	}
	client := gatewayFor(t, host, key, Upstream{Address: target.addr, User: "alice", HostKeyFingerprints: []string{target.fingerprint}})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.Output("id -un")
	if err != nil || strings.TrimSpace(string(out)) != "alice ran id -un" {
		t.Fatalf("exec through the gateway = %q, %v", out, err)
	}
	// Forwarding of any kind is refused: a port forward channel and agent
	// forwarding on a session.
	if _, err := client.Dial("tcp", target.addr); err == nil || !strings.Contains(err.Error(), "relays sessions only") {
		t.Fatalf("port forward through the gateway = %v, want refused", err)
	}
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil); ok || err != nil {
		t.Fatalf("agent forwarding through the gateway = %v, %v", ok, err)
	}
}

func TestGatewayRefusesAnUnpinnedTargetA254(t *testing.T) {
	target := startUpstream(t, "alice")
	impostor := startUpstream(t, "alice")
	host, err := NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Destroy()
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if _, err := key.Certify(certify(t, key, impostor.ca, "alice", ssh.UserCert)); err != nil {
		t.Fatal(err)
	}
	// The address answers with a host key the target does not pin.
	client := gatewayFor(t, host, key, Upstream{Address: impostor.addr, User: "alice", HostKeyFingerprints: []string{target.fingerprint}})
	if _, err := client.NewSession(); err == nil || !strings.Contains(err.Error(), "could not sign in") {
		t.Fatalf("session to an unpinned host = %v, want refused", err)
	}
}

func TestSessionKeyAdoptsOnlyItsOwnUserCertificateA254(t *testing.T) {
	target := startUpstream(t, "alice")
	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	other, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	if _, err := key.Certify(certify(t, other, target.ca, "alice", ssh.UserCert)); err == nil {
		t.Fatal("a certificate for another key was adopted")
	}
	if _, err := key.Certify(certify(t, key, target.ca, "alice", ssh.HostCert)); err == nil {
		t.Fatal("a host certificate was adopted as the session's")
	}
	host, err := NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Destroy()
	if err := Serve(context.Background(), nil, host, key, Upstream{}, nil); err == nil {
		t.Fatal("an uncertified session key served")
	}
}
