// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// A260: privileged account discovery reads a host's accounts over SSH with
// the local-account rotator's administrator (A240), its host key pinned. The
// only command is sshAccountInventoryScript, fixed here: it reads the account
// and group databases, the sudoers files and each account's authorized_keys,
// and changes nothing. Authorized keys leave this package as their type and
// SHA-256 fingerprint only.

// sshAccountInventoryScript prints framed sections; a file it cannot read is
// named as unreadable rather than skipped.
const sshAccountInventoryScript = `LC_ALL=C; export LC_ALL
echo '=== passwd'; getent passwd
echo '=== group'; getent group
echo '=== sudoers'
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  if [ -r "$f" ]; then echo "--- $f"; cat "$f"; echo; else echo "--- $f unreadable"; fi
done
echo '=== keys'
getent passwd | while IFS=: read -r name _ _ _ _ home _; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -e "$f" ] || continue
    if [ -r "$f" ]; then echo "--- $name"; cat "$f"; echo; else echo "--- $name unreadable"; fi
  done
done
echo '=== end'
`

// sshAccountInventoryLimit bounds what a host may return.
const sshAccountInventoryLimit = 4 << 20

// SSHSudoersFile is one sudoers file the inventory read, or could not.
type SSHSudoersFile struct {
	Path     string
	Readable bool
	Lines    []string
}

// SSHAuthorizedKey is one authorized key, reduced to what identifies it.
type SSHAuthorizedKey struct {
	Type        string
	Fingerprint string
	// Restricted is set when the key carries options (command=, from=, ...).
	Restricted bool
}

// SSHAccountKeys is an account's authorized keys, or that they could not be
// read.
type SSHAccountKeys struct {
	Account  string
	Readable bool
	Keys     []SSHAuthorizedKey
}

// SSHAccountInventory is what a host's read-only inventory returned.
type SSHAccountInventory struct {
	Passwd  []string
	Group   []string
	Sudoers []SSHSudoersFile
	Keys    []SSHAccountKeys
}

// ReadSSHAccountInventory runs the fixed read-only inventory on target as
// its administrator.
func ReadSSHAccountInventory(ctx context.Context, target SSHAccountTarget, adminPKCS8 []byte) (SSHAccountInventory, error) {
	if target.Windows {
		return SSHAccountInventory{}, errors.New("account inventory reads Linux and Unix hosts")
	}
	key, err := LockedKeyFromPKCS8PEM(adminPKCS8)
	if err != nil {
		return SSHAccountInventory{}, errors.New("account inventory requires a supported PKCS#8 administrator key")
	}
	defer key.Destroy()
	signer, err := sshSignerFromDigestSigner(key)
	if err != nil {
		return SSHAccountInventory{}, errors.New("account inventory administrator key cannot authenticate")
	}
	client, closeClient, err := dialPinnedSSH(ctx, target, target.AdminUser, ssh.PublicKeys(signer))
	if err != nil {
		return SSHAccountInventory{}, err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return SSHAccountInventory{}, err
	}
	defer func() { _ = session.Close() }()
	var out bytes.Buffer
	session.Stdout = &limitedBuffer{buf: &out, limit: sshAccountInventoryLimit}
	session.Stdin = strings.NewReader(sshAccountInventoryScript)
	// A non-root administrator reads what it can; root-only files are
	// reported unreadable.
	if err := session.Run("sh -s"); err != nil {
		return SSHAccountInventory{}, errors.New("account inventory failed on the host")
	}
	return parseSSHAccountInventory(out.Bytes())
}

type limitedBuffer struct {
	buf   *bytes.Buffer
	limit int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.limit {
		return 0, errors.New("account inventory exceeds its bound")
	}
	return l.buf.Write(p)
}

// parseSSHAccountInventory reads the framed sections; authorized keys are
// reduced to type and fingerprint here and their bytes dropped.
func parseSSHAccountInventory(raw []byte) (SSHAccountInventory, error) {
	var inv SSHAccountInventory
	section, ended := "", false
	var sudoers *SSHSudoersFile
	var keys *SSHAccountKeys
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if name, ok := strings.CutPrefix(line, "=== "); ok {
			section, sudoers, keys = name, nil, nil
			if name == "end" {
				ended = true
			}
			continue
		}
		switch section {
		case "passwd":
			if line != "" {
				inv.Passwd = append(inv.Passwd, line)
			}
		case "group":
			if line != "" {
				inv.Group = append(inv.Group, line)
			}
		case "sudoers":
			if path, ok := strings.CutPrefix(line, "--- "); ok {
				readable := !strings.HasSuffix(path, " unreadable")
				inv.Sudoers = append(inv.Sudoers, SSHSudoersFile{Path: strings.TrimSuffix(path, " unreadable"), Readable: readable})
				sudoers = &inv.Sudoers[len(inv.Sudoers)-1]
				continue
			}
			if sudoers != nil && line != "" {
				sudoers.Lines = append(sudoers.Lines, line)
			}
		case "keys":
			if account, ok := strings.CutPrefix(line, "--- "); ok {
				readable := !strings.HasSuffix(account, " unreadable")
				inv.Keys = append(inv.Keys, SSHAccountKeys{Account: strings.TrimSuffix(account, " unreadable"), Readable: readable})
				keys = &inv.Keys[len(inv.Keys)-1]
				continue
			}
			if keys == nil || strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			public, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			keys.Keys = append(keys.Keys, SSHAuthorizedKey{Type: public.Type(), Fingerprint: ssh.FingerprintSHA256(public), Restricted: len(options) > 0})
		}
	}
	if err := scanner.Err(); err != nil {
		return SSHAccountInventory{}, errors.New("account inventory output is malformed")
	}
	if !ended {
		return SSHAccountInventory{}, errors.New("account inventory output is incomplete")
	}
	return inv, nil
}
