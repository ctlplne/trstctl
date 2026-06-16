// Package sshdiscovery inventories the SSH key material on a host (F42, S6.3):
// host keys, user public keys, authorized_keys grants, known_hosts trust, and
// the trusted user CA configured in sshd. It is the agent half of SSH discovery,
// alongside the network host-key probe (internal/discovery/sshscan).
//
// Every authorized_keys entry is flagged as standing access (it confers
// persistent login); a grant with no owner comment is additionally flagged as
// orphaned — an unattributable standing-access grant nobody can account for,
// which is the canonical unmanaged-SSH problem. Keys are parsed through the
// crypto boundary (internal/crypto/sshkeys); this package imports no crypto.
package sshdiscovery

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/sshinv"
)

// Config locates the SSH material to inventory. All fields are optional; paths
// and globs that match nothing are skipped. Defaulting to system locations is
// the caller's responsibility, so the source is testable against temp dirs.
type Config struct {
	HostKeyGlobs        []string // e.g. /etc/ssh/ssh_host_*_key.pub
	UserKeyGlobs        []string // e.g. /home/*/.ssh/*.pub, ~/.ssh/id_*.pub
	AuthorizedKeysPaths []string // e.g. /home/*/.ssh/authorized_keys
	KnownHostsPaths     []string // e.g. ~/.ssh/known_hosts, /etc/ssh/ssh_known_hosts
	SSHDConfigPaths     []string // e.g. /etc/ssh/sshd_config (for TrustedUserCAKeys)
}

// Source discovers on-host SSH material.
type Source struct {
	cfg Config
}

// New returns an SSH discovery source for the configured locations.
func New(cfg Config) *Source { return &Source{cfg: cfg} }

// Discover inventories every SSH key the source can read. It is best-effort: a
// missing or unparseable file is skipped, never fatal.
func (s *Source) Discover(_ context.Context) ([]sshinv.Found, error) {
	var out []sshinv.Found

	// Host keys and user keys: one public key per .pub file.
	out = append(out, s.collectPubFiles(s.cfg.HostKeyGlobs, sshinv.SourceHostKey)...)
	out = append(out, s.collectPubFiles(s.cfg.UserKeyGlobs, sshinv.SourceUserKey)...)

	// authorized_keys: each entry is a standing-access grant.
	for _, path := range expandGlobs(s.cfg.AuthorizedKeysPaths) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, ak := range sshkeys.ParseAuthorizedKeys(data) {
			out = append(out, sshinv.Found{
				Source:         sshinv.SourceAuthorizedKeys,
				Location:       path,
				KeyType:        ak.Type,
				Fingerprint:    ak.FingerprintSHA256,
				Comment:        ak.Comment,
				StandingAccess: true,
				Orphaned:       strings.TrimSpace(ak.Comment) == "", // no owner annotation
			})
		}
	}

	// known_hosts: trusted host keys.
	for _, path := range expandGlobs(s.cfg.KnownHostsPaths) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, kh := range sshkeys.ParseKnownHosts(data) {
			out = append(out, sshinv.Found{
				Source:      sshinv.SourceKnownHosts,
				Location:    path,
				KeyType:     kh.Type,
				Fingerprint: kh.FingerprintSHA256,
				Comment:     strings.Join(kh.Hosts, ","),
			})
		}
	}

	// sshd TrustedUserCAKeys: the CA whose user certificates the host trusts.
	for _, caPath := range s.trustedCAPaths() {
		data, err := os.ReadFile(caPath)
		if err != nil {
			continue
		}
		for _, ca := range sshkeys.ParseAuthorizedKeys(data) {
			out = append(out, sshinv.Found{
				Source:      sshinv.SourceTrustedCA,
				Location:    caPath,
				KeyType:     ca.Type,
				Fingerprint: ca.FingerprintSHA256,
				Comment:     ca.Comment,
			})
		}
	}

	return out, nil
}

// collectPubFiles reads each .pub file matched by the globs as a single public
// key.
func (s *Source) collectPubFiles(globs []string, source string) []sshinv.Found {
	var out []sshinv.Found
	for _, path := range expandGlobs(globs) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		info, err := sshkeys.ParsePublicKey(data)
		if err != nil {
			continue
		}
		out = append(out, sshinv.Found{
			Source:      source,
			Location:    path,
			KeyType:     info.Type,
			Fingerprint: info.FingerprintSHA256,
			Comment:     info.Comment,
		})
	}
	return out
}

// trustedCAPaths reads each sshd_config and returns the TrustedUserCAKeys paths
// it configures.
func (s *Source) trustedCAPaths() []string {
	var paths []string
	for _, cfgPath := range expandGlobs(s.cfg.SSHDConfigPaths) {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "TrustedUserCAKeys") {
				paths = append(paths, fields[1])
			}
		}
	}
	return paths
}

// expandGlobs resolves glob patterns to file paths, skipping patterns that match
// nothing or fail to parse.
func expandGlobs(globs []string) []string {
	var out []string
	for _, g := range globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		out = append(out, matches...)
	}
	return out
}
