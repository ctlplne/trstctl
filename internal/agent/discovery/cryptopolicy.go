// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The system crypto policy (X2-L6). On Fedora, RHEL and their relatives,
// /etc/crypto-policies/config names the policy every TLS library on the host
// starts from (DEFAULT, LEGACY, FUTURE, FIPS, with sub-policies such as
// DEFAULT:PQ), and the back-end files it generates set each library's
// defaults: for OpenSSL, the TLS groups it offers. A library able to
// negotiate X25519MLKEM768 still offers it only if the policy keeps the
// ML-KEM groups. The policy is reported as one more crypto_library finding,
// library "crypto-policies", with its own post-quantum answer.

// DefaultCryptoPolicyRoot is where the policy tooling keeps the policy.
const DefaultCryptoPolicyRoot = "/etc/crypto-policies"

// CryptoPolicyLibrary is the library name a policy finding carries.
const CryptoPolicyLibrary = "crypto-policies"

const maxCryptoPolicyFileSize = 256 << 10

var (
	cryptoPolicyName = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]*(:[A-Z0-9_-]+)*$`)
	openSSLGroups    = regexp.MustCompile(`^\s*Groups\s*=\s*(.+?)\s*$`)
)

// ReadCryptoPolicy reads the policy under root. It reports nothing when the
// host has no policy file, and a policy it cannot read as a name is skipped,
// never reported as a policy with no name.
func ReadCryptoPolicy(root string) (LibraryFound, bool) {
	location := filepath.Join(root, "config")
	name, ok := readPolicyName(location)
	if !ok {
		return LibraryFound{}, false
	}
	found := LibraryFound{Location: location, Library: CryptoPolicyLibrary, Version: name}
	groups, ok := readOpenSSLGroups(filepath.Join(root, "back-ends", "opensslcnf.config"))
	switch {
	case !ok:
		found.PQHybrid = PQHybridUnknown
		found.Basis = "the " + name + " policy's OpenSSL back-end sets no TLS groups, so each library's own defaults decide"
	case hasMLKEMGroup(groups):
		found.PQHybrid = PQHybridYes
		found.Basis = "the " + name + " policy keeps the ML-KEM hybrid groups in OpenSSL's TLS defaults"
	default:
		found.PQHybrid = PQHybridNo
		found.Basis = "the " + name + " policy leaves the ML-KEM hybrid groups out of OpenSSL's TLS defaults, so OpenSSL 3.5 does not offer X25519MLKEM768 unless an application sets its own groups"
	}
	if CryptoPolicyIsLegacy(name) {
		found.Basis += "; LEGACY also allows SHA-1 signatures, 1024-bit DH and DSA and TLS 1.0"
	}
	return found, true
}

// CryptoPolicyIsLegacy reports whether the policy is built on LEGACY.
func CryptoPolicyIsLegacy(name string) bool {
	base, _, _ := strings.Cut(name, ":")
	return base == "LEGACY"
}

func readPolicyName(path string) (string, bool) {
	data, ok := readSmallFile(path)
	if !ok {
		return "", false
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !cryptoPolicyName.MatchString(line) {
			return "", false
		}
		return line, true
	}
	return "", false
}

func readOpenSSLGroups(path string) ([]string, bool) {
	data, ok := readSmallFile(path)
	if !ok {
		return nil, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if m := openSSLGroups.FindStringSubmatch(scanner.Text()); m != nil {
			var groups []string
			for _, g := range strings.Split(m[1], ":") {
				if g = strings.TrimSpace(strings.TrimLeft(g, "*?")); g != "" {
					groups = append(groups, g)
				}
			}
			return groups, len(groups) > 0
		}
	}
	return nil, false
}

func hasMLKEMGroup(groups []string) bool {
	for _, g := range groups {
		if strings.Contains(strings.ToUpper(g), "MLKEM") {
			return true
		}
	}
	return false
}

func readSmallFile(path string) ([]byte, bool) {
	f, err := os.Open(path) // #nosec G304 -- the host's own crypto policy files under a fixed root (CWE-22)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCryptoPolicyFileSize))
	return data, err == nil
}
