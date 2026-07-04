// SPDX-License-Identifier: MPL-2.0

// Package sshkeys parses SSH public-key material — authorized_keys lines,
// known_hosts entries, and .pub files — into crypto-free inventory metadata for
// SSH credential discovery (F42, S6.3). It is part of the AN-3 crypto boundary
// (a subpackage of internal/crypto, so it alone may use the SSH crypto library),
// and callers outside the boundary consume only the KeyInfo struct. SSH routes
// through this one boundary exactly as X.509 does — there is no parallel crypto
// stack.
package sshkeys

import (
	"bytes"

	"golang.org/x/crypto/ssh"
)

const (
	maxKnownHostsFileBytes = 1 << 20
	maxKnownHostsLineBytes = 64 << 10
)

// KeyInfo is the inventory metadata of an SSH public key.
type KeyInfo struct {
	// Type is the SSH key type, e.g. "ssh-ed25519", "ssh-rsa",
	// "ecdsa-sha2-nistp256".
	Type string
	// FingerprintSHA256 is the standard OpenSSH fingerprint ("SHA256:<base64>"),
	// the stable identity used to deduplicate a key across discovery sources.
	FingerprintSHA256 string
	// Comment is the trailing comment on the key (often an owner label), or empty.
	Comment string
}

// AuthorizedKey is one entry in an authorized_keys file: a public key, its
// options (for example command="...", from="..."), and its comment.
type AuthorizedKey struct {
	KeyInfo
	Options []string
}

// KnownHostKey is one entry in a known_hosts file: a host key and the host
// patterns it is trusted for.
type KnownHostKey struct {
	KeyInfo
	Hosts []string
}

// infoOf builds KeyInfo from a parsed public key and comment.
func infoOf(pub ssh.PublicKey, comment string) KeyInfo {
	return KeyInfo{
		Type:              pub.Type(),
		FingerprintSHA256: ssh.FingerprintSHA256(pub),
		Comment:           comment,
	}
}

// ParsePublicKey parses a single SSH public key in authorized_keys form (the
// content of a .pub file or a host key file) and returns its metadata.
func ParsePublicKey(data []byte) (KeyInfo, error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return KeyInfo{}, err
	}
	return infoOf(pub, comment), nil
}

// ParseAuthorizedKeys parses every entry in an authorized_keys file. Malformed
// or comment/blank lines are skipped; a file with no valid keys yields an empty
// slice.
func ParseAuthorizedKeys(data []byte) []AuthorizedKey {
	var out []AuthorizedKey
	rest := data
	for len(rest) > 0 {
		pub, comment, options, remaining, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		out = append(out, AuthorizedKey{KeyInfo: infoOf(pub, comment), Options: options})
		rest = remaining
	}
	return out
}

// ParseKnownHosts parses every entry in a known_hosts file, returning each host
// key and the host patterns it is trusted for.
func ParseKnownHosts(data []byte) []KnownHostKey {
	var out []KnownHostKey
	if len(data) > maxKnownHostsFileBytes {
		data = data[:maxKnownHostsFileBytes]
	}
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line = data[:i+1]
			data = data[i+1:]
		} else {
			data = nil
		}
		if len(line) == 0 || len(line) > maxKnownHostsLineBytes {
			continue
		}
		_, hosts, pub, comment, _, err := ssh.ParseKnownHosts(line)
		if err != nil {
			continue
		}
		out = append(out, KnownHostKey{KeyInfo: infoOf(pub, comment), Hosts: hosts})
	}
	return out
}
