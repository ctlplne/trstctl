// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHCollectionConnection contains only routing and public host-identity facts.
// The caller enforces its exact relay/source egress grant at dial time.
type SSHCollectionConnection struct {
	Address            string
	Username           string
	HostKeyFingerprint string
	DialControl        func(network, address string, c syscall.RawConn) error
	// AuthenticationDone lets the owner erase a shared credential as soon as
	// all bounded authentication attempts finish, before public reads complete.
	AuthenticationDone func()
}

// SSHCollectionCommand is the sole remotely callable read-only profile.
const SSHCollectionCommand = "/usr/local/libexec/trstctl-ssh-collect-v1"
const sshCollectionFixedCommand = SSHCollectionCommand
const sshCollectionOutputLimit = 2 << 20

// ReadSSHCollection authenticates with a byte-backed locked PKCS#8 key. Only
// the fixed helper is callable: a source/job cannot choose commands or paths.
// The caller owns and must wipe privatePKCS8; this method owns and destroys the
// locked signing identity and every parser-owned temporary key buffer.
func ReadSSHCollection(ctx context.Context, cfg SSHCollectionConnection, privatePKCS8 []byte) ([]byte, error) {
	done := cfg.AuthenticationDone
	defer func() {
		if done != nil {
			done()
		}
	}()

	if cfg.Address == "" || cfg.Username == "" || cfg.DialControl == nil || !strings.HasPrefix(cfg.HostKeyFingerprint, "SHA256:") {
		return nil, errors.New("SSH collection requires a pinned target, collection account and scoped dial control")
	}
	key, err := LockedKeyFromPKCS8PEM(privatePKCS8)
	if err != nil {
		return nil, errors.New("SSH collection requires a supported PKCS#8 credential")
	}
	defer key.Destroy()
	signer, err := sshSignerFromDigestSigner(key)
	if err != nil {
		return nil, errors.New("SSH collection credential cannot authenticate")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: cfg.DialControl}
	conn, err := dialer.DialContext(bounded, "tcp", cfg.Address)
	if err != nil {
		return nil, errors.New("SSH collection target is unreachable")
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := bounded.Deadline()
	_ = conn.SetDeadline(deadline)
	// Closing the socket interrupts handshake/session I/O immediately on cancel.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-bounded.Done():
			_ = conn.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)
	clientCfg := &ssh.ClientConfig{User: cfg.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		// A raw host-key pin remains stable when the same key acquires a
		// host certificate. The SSH exchange still proves possession of that key;
		// this is key pinning, not a claim of CA/principal validation.
		offered := ssh.FingerprintSHA256(key)
		if certificate, ok := key.(*ssh.Certificate); ok {
			if certificate.CertType != ssh.HostCert {
				return errors.New("SSH collection requires a host identity")
			}
			if offered != cfg.HostKeyFingerprint {
				key = certificate.Key
			}
		}
		if ssh.FingerprintSHA256(key) != cfg.HostKeyFingerprint {
			return errors.New("SSH collection host identity differs from its pin")
		}
		return nil
	}, Timeout: 5 * time.Second}
	connection, channels, requests, err := ssh.NewClientConn(conn, cfg.Address, clientCfg)
	if err != nil {
		return nil, errors.New("SSH collection host identity or authentication failed")
	}
	// Authentication is complete. No later session operation needs the
	// credential signer; erase its locked private copy before reading public data.
	key.Destroy()
	if done != nil {
		done()
		done = nil
	}
	client := ssh.NewClient(connection, channels, requests)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("SSH collection could not open its bounded read-only session")
	}
	defer func() { _ = session.Close() }()
	output := &sshCollectionOutput{limit: sshCollectionOutputLimit}
	session.Stdout = output
	session.Stderr = io.Discard
	runErr := session.Run(sshCollectionFixedCommand)
	if output.exceeded {
		return nil, errors.New("SSH collection report exceeds its output bound")
	}
	if runErr != nil {
		return nil, errors.New("SSH collection helper failed; inspect local read-only account and helper permissions")
	}
	return output.data, nil
}

type sshCollectionOutput struct {
	data     []byte
	limit    int
	exceeded bool
}

func (w *sshCollectionOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.data) {
		w.exceeded = true
		return 0, errors.New("SSH collection report limit")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
