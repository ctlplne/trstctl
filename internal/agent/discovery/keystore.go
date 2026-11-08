// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// SourceKeystore is the agent inventory source for Java keystores and PKCS#12
// files (X2). Each key entry is reported as private-key metadata: its alias,
// the key type and size read from the entry's certificate, and the public-key
// fingerprint. No key material leaves the host, and a JKS key is never
// decrypted.
const SourceKeystore = "keystore"

// SourceNetworkObserver is the source passive observers report under (X1);
// the agent's observe package collects it.
const SourceNetworkObserver = "network-observer"

// SourceTLSSessionObserver is the source host session observers report under
// (X5); the agent's sessionobserve package collects it.
const SourceTLSSessionObserver = "tls-session-observer"

const maxKeystoreFileSize = 8 << 20

// keystoreExtensions name the files a directory walk reads as keystores; a
// path named directly is always read.
var keystoreExtensions = map[string]bool{".jks": true, ".keystore": true, ".ks": true, ".p12": true, ".pfx": true}

// defaultKeystorePasswords are the published defaults tried after the
// operator's passwords: Java's "changeit" and the empty password.
var defaultKeystorePasswords = []string{"changeit"} // #nosec G101 -- the published Java keystore default, tried as a default; not a credential of this deployment (CWE-798)

// KeystoreSource reads keystores at the given files, directories or globs.
type KeystoreSource struct {
	paths     []string
	passwords [][]byte
	maxSize   int64
}

// NewKeystoreSource reads keystores under paths, trying passwords in order.
// The caller keeps ownership of passwords and wipes them after Discover.
func NewKeystoreSource(passwords [][]byte, paths ...string) *KeystoreSource {
	candidates := append([][]byte(nil), passwords...)
	for _, p := range defaultKeystorePasswords {
		candidates = append(candidates, []byte(p))
	}
	return &KeystoreSource{paths: paths, passwords: candidates, maxSize: maxKeystoreFileSize}
}

// Kind names the source.
func (s *KeystoreSource) Kind() string { return SourceKeystore }

// Discover reads every keystore it finds and returns one metadata-only finding
// per key entry. A PKCS#12 file that no password opens is reported as locked,
// with nothing listed; a file that is not a keystore is skipped.
func (s *KeystoreSource) Discover(ctx context.Context) ([]PrivateKeyFound, error) {
	var out []PrivateKeyFound
	seen := map[string]bool{}
	err := walkPaths(ctx, s.paths, func(path string, direct bool) {
		if seen[path] || (!direct && !keystoreExtensions[strings.ToLower(filepath.Ext(path))]) {
			return
		}
		seen[path] = true
		out = append(out, s.keystore(path)...)
	})
	return out, err
}

func (s *KeystoreSource) keystore(path string) []PrivateKeyFound {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > s.maxSize {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the agent inventories operator-configured keystore paths; reading them is the product function (CWE-22)
	if err != nil {
		return nil
	}
	report, err := cryptoboundary.InspectKeystore(data, s.passwords)
	secret.Wipe(data)
	restricted, metadata := privateKeyPermissionState(path, fi)
	if errors.Is(err, cryptoboundary.ErrKeystoreLocked) {
		meta := keystoreMetadata(metadata)
		meta["keystore_format"] = "PKCS12"
		meta["keystore_state"] = "locked"
		return []PrivateKeyFound{{
			Source: SourceKeystore, Location: path, Format: "PKCS12", Algorithm: "unknown",
			Encrypted: true, Restricted: restricted, Metadata: meta,
		}}
	}
	if err != nil {
		return nil
	}
	var out []PrivateKeyFound
	for _, key := range report.Keys {
		meta := keystoreMetadata(metadata)
		meta["keystore_format"] = report.Format
		meta["keystore_state"] = "read"
		meta["integrity_verified"] = strconv.FormatBool(report.IntegrityVerified)
		meta["keystore_trusted_certificates"] = strconv.Itoa(report.TrustedCerts)
		meta["key_type"] = key.KeyType
		meta["key_size_bits"] = strconv.Itoa(key.KeyBits)
		meta["certificate_sha256"] = key.CertificateSHA256
		meta["chain_length"] = strconv.Itoa(key.ChainLength)
		location := path
		if key.Alias != "" {
			meta["keystore_alias"] = key.Alias
			location = path + "#" + key.Alias
		}
		out = append(out, PrivateKeyFound{
			Source: SourceKeystore, Location: location, Format: report.Format, Algorithm: key.Algorithm,
			Fingerprint: key.FingerprintSHA256, FingerprintBasis: key.FingerprintBasis,
			Encrypted: true, Restricted: restricted, WeakReasons: key.WeakReasons, Metadata: meta,
		})
	}
	return out
}

// keystoreMetadata copies the file's permission facts into a finding's own map.
func keystoreMetadata(base map[string]string) map[string]string {
	out := make(map[string]string, len(base)+8)
	for k, v := range base {
		out[k] = v
	}
	return out
}
