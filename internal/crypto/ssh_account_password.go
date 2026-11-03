// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// SSHAccountTarget is a host whose local accounts a rotator manages (A240).
type SSHAccountTarget struct {
	Address            string
	AdminUser          string
	HostKeyFingerprint string
	// Sudo runs the profile as `sudo -n /usr/sbin/chpasswd`, for an
	// administrator that is not root but may run chpasswd.
	Sudo bool
	// Windows runs the Windows profile instead (A240): Windows PowerShell's
	// Set-LocalUser, for a member of Administrators on a host serving
	// OpenSSH.
	Windows bool
	// DialControl, when set, is applied to the connection's socket.
	DialControl func(network, address string, c syscall.RawConn) error
}

// The only command a local-account rotator runs: chpasswd, reading
// "account:password" from stdin. Nothing a target or job supplies becomes
// argv.
const (
	sshChpasswdCommand     = "/usr/sbin/chpasswd"         // #nosec G101 -- a command path the profile runs, not a credential (CWE-798)
	sshChpasswdSudoCommand = "sudo -n /usr/sbin/chpasswd" // #nosec G101 -- a command path the profile runs, not a credential (CWE-798)
)

// sshWindowsSetLocalUser is the Windows profile's script. The account is a
// validated name (no quote can occur in it) and is the only value in the
// script, which travels as -EncodedCommand; the password arrives on stdin and
// never reaches a command line.
const sshWindowsSetLocalUser = "$ErrorActionPreference = 'Stop'\n" +
	"$password = ConvertTo-SecureString -String ([Console]::In.ReadToEnd()) -AsPlainText -Force\n" +
	"Set-LocalUser -Name '%s' -Password $password\n"

// sshWindowsCommand is the Windows profile's command line for account.
func sshWindowsCommand(account string) string {
	script := fmt.Sprintf(sshWindowsSetLocalUser, account)
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		raw = binary.LittleEndian.AppendUint16(raw, unit)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
}

// ValidSSHAccountName reports whether name is a portable local user name
// ([a-z_][a-z0-9_-]{0,31}); it can never carry the chpasswd separator or a
// newline.
func ValidSSHAccountName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i, c := range name {
		switch {
		case c == '_' || (c >= 'a' && c <= 'z'):
		case i > 0 && (c == '-' || (c >= '0' && c <= '9')):
		default:
			return false
		}
	}
	return true
}

// SetSSHAccountPassword authenticates as the target's administrator with a
// byte-backed locked PKCS#8 key and runs the fixed chpasswd profile with
// "account:password" on stdin, or on a Windows target the Set-LocalUser
// profile with the password alone on stdin. The caller owns and must wipe
// adminPKCS8 and password.
func SetSSHAccountPassword(ctx context.Context, target SSHAccountTarget, adminPKCS8 []byte, account string, password []byte) error {
	if !ValidSSHAccountName(account) || len(password) == 0 || bytes.ContainsAny(password, ":\n\r") {
		return errors.New("SSH account rotation requires a local account name and a password without separators")
	}
	if target.Windows && len(account) > 20 {
		return errors.New("SSH account rotation: a Windows local account name has at most 20 characters")
	}
	key, err := LockedKeyFromPKCS8PEM(adminPKCS8)
	if err != nil {
		return errors.New("SSH account rotation requires a supported PKCS#8 administrator key")
	}
	defer key.Destroy()
	signer, err := sshSignerFromDigestSigner(key)
	if err != nil {
		return errors.New("SSH account rotation administrator key cannot authenticate")
	}
	client, closeClient, err := dialPinnedSSH(ctx, target, target.AdminUser, ssh.PublicKeys(signer))
	if err != nil {
		return err
	}
	defer closeClient()
	key.Destroy()
	session, err := client.NewSession()
	if err != nil {
		return errors.New("SSH account rotation could not open its session")
	}
	defer func() { _ = session.Close() }()
	if target.Windows {
		stdin := append([]byte(nil), password...)
		defer secret.Wipe(stdin)
		session.Stdin = bytes.NewReader(stdin)
		if err := session.Run(sshWindowsCommand(account)); err != nil {
			return errors.New("SSH account rotation: Set-LocalUser refused the change; check the administrator's rights, the account and the host's password policy")
		}
		return nil
	}
	line := append(append(append([]byte(account), ':'), password...), '\n')
	defer secret.Wipe(line)
	session.Stdin = bytes.NewReader(line)
	command := sshChpasswdCommand
	if target.Sudo {
		command = sshChpasswdSudoCommand
	}
	if err := session.Run(command); err != nil {
		return errors.New("SSH account rotation: chpasswd refused the change; check the administrator's rights and the account")
	}
	return nil
}

// VerifySSHAccountPassword proves account's password authenticates at the
// target: password (or keyboard-interactive) authentication completes, and
// no command runs.
func VerifySSHAccountPassword(ctx context.Context, target SSHAccountTarget, account string, password []byte) error {
	if !ValidSSHAccountName(account) || len(password) == 0 {
		return errors.New("SSH account verification requires a local account name and a password")
	}
	// x/crypto/ssh takes the password as a string; it is built per attempt
	// from the caller's bytes and not kept.
	answer := func() (string, error) { return string(password), nil }
	interactive := func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = string(password)
		}
		return answers, nil
	}
	_, closeClient, err := dialPinnedSSH(ctx, target, account,
		ssh.PasswordCallback(answer), ssh.KeyboardInteractive(interactive))
	if err != nil {
		return err
	}
	closeClient()
	return nil
}

// sshHostKeyAlgorithmGroups are tried in turn until the host presents the
// pinned key: a host holds several keys and offers the one the client prefers,
// so a pin of its Ed25519 (or second ECDSA) key must not fail because another
// was preferred. One algorithm per attempt; the host key is checked before any
// credential is sent.
var sshHostKeyAlgorithmGroups = [][]string{
	nil, // the client's own preference
	{ssh.KeyAlgoED25519},
	{ssh.KeyAlgoECDSA256}, {ssh.KeyAlgoECDSA384}, {ssh.KeyAlgoECDSA521},
	{ssh.KeyAlgoRSASHA512}, {ssh.KeyAlgoRSASHA256},
}

// dialPinnedSSH connects to the target, pins its host key and authenticates
// as user; the returned func closes the client and its socket.
func dialPinnedSSH(ctx context.Context, target SSHAccountTarget, user string, auth ...ssh.AuthMethod) (*ssh.Client, func(), error) {
	if target.Address == "" || user == "" || len(target.HostKeyFingerprint) < len("SHA256:")+1 || target.HostKeyFingerprint[:7] != "SHA256:" {
		return nil, nil, errors.New("SSH account rotation requires a pinned target and an account")
	}
	for _, algorithms := range sshHostKeyAlgorithmGroups {
		client, closeClient, offeredOther, err := dialPinnedSSHWith(ctx, target, user, algorithms, auth)
		if err == nil {
			return client, closeClient, nil
		}
		if !offeredOther {
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("SSH account rotation host identity differs from its pin")
}

// dialPinnedSSHWith is one attempt restricted to algorithms (nil: the client's
// preference); offeredOther reports that the host presented a key other than
// the pinned one, or none of the algorithms, before any credential was sent.
func dialPinnedSSHWith(ctx context.Context, target SSHAccountTarget, user string, algorithms []string, auth []ssh.AuthMethod) (*ssh.Client, func(), bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: target.DialControl}
	conn, err := dialer.DialContext(bounded, "tcp", target.Address)
	if err != nil {
		cancel()
		return nil, nil, false, errors.New("SSH account rotation target is unreachable")
	}
	deadline, _ := bounded.Deadline()
	_ = conn.SetDeadline(deadline)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-bounded.Done():
			_ = conn.Close()
		case <-stopped:
		}
	}()
	release := func() {
		close(stopped)
		cancel()
		_ = conn.Close()
	}
	verified, mismatched := false, false
	clientCfg := &ssh.ClientConfig{User: user, Auth: auth, Timeout: 5 * time.Second, HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			// A raw host-key pin stays stable when the same key acquires a host
			// certificate; the exchange still proves possession of that key.
			if certificate, ok := key.(*ssh.Certificate); ok {
				if certificate.CertType != ssh.HostCert {
					return errors.New("SSH account rotation requires a host identity")
				}
				if ssh.FingerprintSHA256(key) != target.HostKeyFingerprint {
					key = certificate.Key
				}
			}
			if ssh.FingerprintSHA256(key) != target.HostKeyFingerprint {
				mismatched = true
				return errors.New("SSH account rotation host identity differs from its pin")
			}
			verified = true
			return nil
		}}
	connection, channels, requests, err := ssh.NewClientConn(conn, target.Address, clientCfg)
	if err != nil {
		release()
		// Without a verified host key nothing was authenticated: another key
		// was offered, or none of these algorithms is the host's.
		return nil, nil, mismatched || !verified, errors.New("SSH account rotation host identity or authentication failed")
	}
	client := ssh.NewClient(connection, channels, requests)
	return client, func() { _ = client.Close(); release() }, false, nil
}
