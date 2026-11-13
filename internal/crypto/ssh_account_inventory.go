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
// and group databases, the sudoers files and each account's authorized keys
// files, and changes nothing. Authorized keys leave this package as their
// type and SHA-256 fingerprint only.
//
// A260-L2: the authorized keys files are the ones sshd reads. The script
// takes AuthorizedKeysFile from the host's sshd_config, with its Include
// files read in place, outside any Match block; the first one set wins, as in
// sshd. With none set, they are sshd's defaults (.ssh/authorized_keys and
// .ssh/authorized_keys2); set to none, no file is read. Each pattern is expanded per account (%u, %h, %U,
// %%, a leading ~; a relative path is under the home directory) by awk, from
// the account's fields in its environment, so a passwd field is never code.
// An AuthorizedKeysCommand is named too: the keys it returns cannot be read
// from a file.
//
// A260-L3: a sudoers file a non-root administrator cannot read hides who may
// run what. When one is unreadable and sudo lets the administrator list other
// users' rights (sudoers' list pseudo-command, run as any user: `admin ALL =
// (ALL) NOPASSWD: list`), the script asks sudo itself, `sudo -n -l -U
// <account>`, for every account with a login shell. A listing sudo refuses
// (it exits non-zero) is marked unlisted: that account's rights stay unknown,
// never read as none. Every sudo call reads /dev/null: the script arrives on
// stdin, and nothing it runs may read the rest of it.

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
sshd_config_lines() {
  [ -r /etc/ssh/sshd_config ] || return 0
  while IFS= read -r line; do
    case "$line" in
      [Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]=]*)
        set -f
        for pattern in ${line#*[[:space:]=]}; do
          set +f
          case "$pattern" in /*) ;; *) pattern="/etc/ssh/$pattern" ;; esac
          for f in $pattern; do
            [ -r "$f" ] && cat "$f"
            echo '#trstctl-include-end'
          done
          set -f
        done
        set +f ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < /etc/ssh/sshd_config
}
keys_config=$(sshd_config_lines | awk '
  $0 == "#trstctl-include-end" { inmatch = 0; next }
  { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") }
  $0 == "" || substr($0, 1, 1) == "#" { next }
  {
    if (match($0, /^[A-Za-z]+[ \t]*=[ \t]*/)) { key = substr($0, 1, RLENGTH); sub(/[ \t]*=[ \t]*$/, "", key); value = substr($0, RLENGTH + 1) }
    else { key = $1; value = substr($0, length($1) + 1); sub(/^[ \t]+/, "", value) }
    key = tolower(key)
  }
  key == "match" { inmatch = 1; next }
  inmatch { next }
  key == "authorizedkeysfile" && files == "" { files = value }
  key == "authorizedkeyscommand" && command == "" { command = value }
  END {
    gsub(/"/, "", files)
    if (tolower(files) == "none") files = "none"
    else if (files == "") files = ".ssh/authorized_keys .ssh/authorized_keys2"
    print "files " files
    if (command != "" && tolower(command) != "none") print "command"
  }')
echo '=== sshd'
printf '%s\n' "$keys_config"
keys_files=$(printf '%s\n' "$keys_config" | sed -n 's/^files //p')
echo '=== keys'
[ "$keys_files" = none ] || getent passwd | while IFS=: read -r name _ uid _ _ home _; do
  printf '%s\n' "$keys_files" | name="$name" home="$home" uid="$uid" awk '
    function expand(p,    out, i, c, n) {
      if (p == "~") p = "%h"
      else if (substr(p, 1, 2) == "~/") p = "%h/" substr(p, 3)
      out = ""
      for (i = 1; i <= length(p); i++) {
        c = substr(p, i, 1)
        if (c == "%" && i < length(p)) {
          n = substr(p, i + 1, 1)
          if (n == "%") { out = out "%"; i++; continue }
          if (n == "u") { out = out ENVIRON["name"]; i++; continue }
          if (n == "h") { out = out ENVIRON["home"]; i++; continue }
          if (n == "U") { out = out ENVIRON["uid"]; i++; continue }
        }
        out = out c
      }
      if (substr(out, 1, 1) != "/") out = ENVIRON["home"] "/" out
      return out
    }
    { for (i = 1; i <= NF; i++) { f = expand($i); if (!(f in seen)) { seen[f] = 1; print f } } }' |
  while IFS= read -r f; do
    [ -e "$f" ] || continue
    if [ -r "$f" ]; then echo "--- $name"; cat "$f"; echo; else echo "--- $name unreadable"; fi
  done
done
echo '=== sudo-list'
sudoers_hidden=''
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  [ -r "$f" ] || sudoers_hidden=1
done
if [ -n "$sudoers_hidden" ] && command -v sudo >/dev/null 2>&1 && sudo -n -l -U root </dev/null >/dev/null 2>&1; then
  getent passwd | while IFS=: read -r name _ _ _ _ _ shell; do
    case "$shell" in */nologin|*/false) continue ;; esac
    if listing=$(sudo -n -l -U "$name" </dev/null 2>/dev/null); then
      echo "--- $name"
      printf '%s\n' "$listing" | head -n 200
    else
      echo "--- $name unlisted"
    fi
  done
fi
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
	// KeyFiles are the AuthorizedKeysFile patterns the keys were read from
	// (A260-L2): the host's sshd_config, or sshd's defaults.
	KeyFiles []string
	// KeysCommand reports an AuthorizedKeysCommand: keys it returns are
	// not in any file the inventory read.
	KeysCommand bool
	// SudoList is sudo's own listing of each login account's rights, read
	// when a sudoers file was unreadable and the administrator may list
	// other users' rights (A260-L3); nil when it was not read. An account
	// whose listing sudo refused is absent.
	SudoList map[string][]string
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
	section, ended, listed := "", false, ""
	var sudoers *SSHSudoersFile
	var keys *SSHAccountKeys
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if name, ok := strings.CutPrefix(line, "=== "); ok {
			section, sudoers, keys, listed = name, nil, nil, ""
			if name == "end" {
				ended = true
			}
			continue
		}
		switch section {
		case "sudo-list":
			if account, ok := strings.CutPrefix(line, "--- "); ok {
				if inv.SudoList == nil {
					inv.SudoList = map[string][]string{}
				}
				listed = ""
				if !strings.HasSuffix(account, " unlisted") {
					listed = account
					inv.SudoList[account] = []string{}
				}
				continue
			}
			if listed != "" && strings.TrimSpace(line) != "" {
				inv.SudoList[listed] = append(inv.SudoList[listed], line)
			}
		case "sshd":
			if files, ok := strings.CutPrefix(line, "files "); ok {
				inv.KeyFiles = strings.Fields(files)
			} else if line == "command" {
				inv.KeysCommand = true
			}
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
