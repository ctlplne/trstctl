// SPDX-License-Identifier: BUSL-1.1

package sshdiscovery

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/sshcollection"
)

// A115: whether a host is under an SSH CA is a property of its sshd
// configuration, not of the keys found on it. TrustedUserCAKeys names the CAs
// whose user certificates sshd accepts, RevokedKeys the revocation list it
// enforces, HostCertificate the certificates it presents to clients, and
// AuthorizedKeysFile whether standing keys still log in. TrustPosture reads the
// file the way sshd does for its global section: the first value of a keyword
// wins, HostCertificate accumulates, Include files are read in place (relative
// names under /etc/ssh, globs in lexical order, at most sixteen deep), and a
// Match block, which applies only to matching connections, is counted but not
// read. It reads only public material; no private key is opened.

// TrustFindingKind is the inventory finding kind of one sshd configuration's
// trust posture.
const TrustFindingKind = "ssh_trust"

// Values a trust posture reports for a path it could not use.
const (
	StateRead        = "read"
	StateNone        = "none"
	StateMissing     = "missing"
	StateUnreadable  = "unreadable"
	StateRelative    = "relative_path"
	StateKRL         = "krl"
	StateKeyList     = "key_list"
	StateInvalid     = "invalid"
	StateCertificate = "certificate"
)

const (
	maxSSHDConfigBytes  = 1 << 20
	maxTrustFileBytes   = 4 << 20 // a RevokedKeys list; sshkrl bounds an installed KRL the same way
	maxSSHDIncludeDepth = 16      // sshd's READCONF_MAX_DEPTH
	sshdIncludeBase     = "/etc/ssh"
	maxHostCertificates = 64
)

// SSHDTrust is the trust posture one sshd configuration declares.
type SSHDTrust struct {
	ConfigPath  string
	ConfigState string
	// TrustedUserCAKeys is the configured CA file, or "none".
	TrustedUserCAKeys string
	TrustedCAState    string
	TrustedCAs        []sshkeys.KeyInfo
	// RevokedKeys is the configured revocation file, or "none". sshd reads it
	// as an OpenSSH KRL or as a list of public keys; a configured file that is
	// missing makes sshd refuse every key.
	RevokedKeys       string
	RevocationState   string
	KRLVersion        uint64
	RevokedKeysSHA256 string
	RevokedKeyCount   int
	HostCertificates  []HostCertificate
	// AuthorizedKeysFile is the effective list ("none" alone when standing
	// keys are switched off); unset means OpenSSH's default pair.
	AuthorizedKeysFile       []string
	AuthorizedPrincipalsFile string
	MatchBlocks              int
	IncludedFiles            int
}

// HostCertificate is one HostCertificate the configuration presents.
type HostCertificate struct {
	Path        string
	State       string
	Certificate sshkeys.CertificateInfo
}

// sshdSettings is the global section as sshd resolves it.
type sshdSettings struct {
	trustedUserCAKeys, revokedKeys, authorizedPrincipalsFile string
	authorizedKeysFile                                       []string
	hostCertificates                                         []string
	matchBlocks, included                                    int
}

// TrustPosture reads each configured sshd configuration's trust posture.
// A configuration that cannot be read is reported with its state rather than
// dropped, so a host whose posture is unknown does not look unconfigured.
func (s *Source) TrustPosture() []SSHDTrust {
	var out []SSHDTrust
	for _, path := range expandGlobs(s.cfg.SSHDConfigPaths) {
		out = append(out, readSSHDTrust(path))
	}
	return out
}

func readSSHDTrust(configPath string) SSHDTrust {
	trust := SSHDTrust{ConfigPath: configPath, ConfigState: StateRead}
	var settings sshdSettings
	if err := settings.read(configPath, 0); err != nil {
		trust.ConfigState = fileState(err)
		return trust
	}
	return interpretTrust(configPath, settings, readTrustFile)
}

// TrustFromSnapshot interprets the fixed helper output without reading relay files.
// sshd -T has resolved global includes/defaults; connection-specific Match contexts
// are deliberately not assessed.
func TrustFromSnapshot(snapshot sshcollection.Snapshot) (SSHDTrust, error) {
	if err := snapshot.Validate(); err != nil {
		return SSHDTrust{}, err
	}
	scalar := func(key string) string { return snapshot.Settings[key][0] }
	settings := sshdSettings{trustedUserCAKeys: scalar("trustedusercakeys"), revokedKeys: scalar("revokedkeys"), authorizedPrincipalsFile: scalar("authorizedprincipalsfile"), authorizedKeysFile: snapshot.Settings["authorizedkeysfile"]}
	for _, name := range snapshot.Settings["hostcertificate"] {
		if name != "none" {
			settings.hostCertificates = append(settings.hostCertificates, name)
		}
	}
	return interpretTrust(snapshot.ConfigPath, settings, snapshot.ReadPublicFile), nil
}

func interpretTrust(configPath string, settings sshdSettings, readPublic func(string) ([]byte, string)) SSHDTrust {
	trust := SSHDTrust{ConfigPath: configPath, ConfigState: StateRead}
	trust.MatchBlocks, trust.IncludedFiles = settings.matchBlocks, settings.included
	trust.AuthorizedKeysFile = settings.authorizedKeysFile
	if len(trust.AuthorizedKeysFile) == 0 {
		trust.AuthorizedKeysFile = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	}
	trust.AuthorizedPrincipalsFile = orNone(settings.authorizedPrincipalsFile)

	trust.TrustedUserCAKeys = orNone(settings.trustedUserCAKeys)
	trust.TrustedCAState = StateNone
	if trust.TrustedUserCAKeys != StateNone {
		data, state := readPublic(trust.TrustedUserCAKeys)
		trust.TrustedCAState = state
		if state == StateRead {
			for _, ca := range sshkeys.ParseAuthorizedKeys(data) {
				trust.TrustedCAs = append(trust.TrustedCAs, ca.KeyInfo)
			}
		}
	}

	trust.RevokedKeys = orNone(settings.revokedKeys)
	trust.RevocationState = StateNone
	if trust.RevokedKeys != StateNone {
		data, state := readPublic(trust.RevokedKeys)
		trust.RevocationState = state
		if state == StateRead {
			trust.RevokedKeysSHA256 = crypto.SHA256Hex(data)
			switch revocations, err := sshkrl.ParseRevocations(data); {
			case err == nil:
				trust.RevocationState, trust.KRLVersion = StateKRL, revocations.Version
			case bytes.HasPrefix(data, []byte("SSHKRL\n\x00")):
				trust.RevocationState = StateInvalid
			default:
				trust.RevocationState = StateKeyList
				trust.RevokedKeyCount = len(sshkeys.ParseAuthorizedKeys(data))
			}
		}
	}

	for i, path := range settings.hostCertificates {
		if i == maxHostCertificates {
			break
		}
		certificate := HostCertificate{Path: path}
		data, state := readPublic(path)
		certificate.State = state
		if state == StateRead {
			info, err := sshkeys.ParseCertificate(data)
			if err != nil {
				certificate.State = StateInvalid
			} else {
				certificate.State, certificate.Certificate = StateCertificate, info
			}
		}
		trust.HostCertificates = append(trust.HostCertificates, certificate)
	}
	return trust
}

// read applies one configuration file's global keywords to s, first value
// first, following Include in place.
func (s *sshdSettings) read(path string, depth int) error {
	if depth > maxSSHDIncludeDepth {
		return errors.New("sshd configuration includes nest too deeply")
	}
	data, err := readBounded(path, maxSSHDConfigBytes)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), maxSSHDConfigBytes)
	inMatch := false
	for scanner.Scan() {
		keyword, args := sshdLine(scanner.Text())
		if keyword == "" {
			continue
		}
		if keyword == "match" {
			// A Match block lasts to the next Match or the end of this file;
			// its settings apply only to connections it matches.
			s.matchBlocks++
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}
		switch keyword {
		case "include":
			for _, pattern := range args {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(sshdIncludeBase, pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					continue
				}
				sort.Strings(matches)
				for _, included := range matches {
					s.included++
					if err := s.read(included, depth+1); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				}
			}
		case "trustedusercakeys":
			if s.trustedUserCAKeys == "" && len(args) > 0 {
				s.trustedUserCAKeys = args[0]
			}
		case "revokedkeys":
			if s.revokedKeys == "" && len(args) > 0 {
				s.revokedKeys = args[0]
			}
		case "authorizedprincipalsfile":
			if s.authorizedPrincipalsFile == "" && len(args) > 0 {
				s.authorizedPrincipalsFile = args[0]
			}
		case "authorizedkeysfile":
			if len(s.authorizedKeysFile) == 0 && len(args) > 0 {
				s.authorizedKeysFile = append([]string(nil), args...)
			}
		case "hostcertificate":
			if len(args) > 0 {
				s.hostCertificates = append(s.hostCertificates, args[0])
			}
		}
	}
	return scanner.Err()
}

// sshdLine splits one configuration line into its lower-cased keyword and its
// arguments: "Keyword value", "Keyword=value", double-quoted arguments, and
// comments the way sshd tokenizes them.
func sshdLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return strings.ToLower(line), nil
	}
	keyword := strings.ToLower(line[:end])
	rest := strings.TrimLeft(line[end:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var args []string
	for rest != "" {
		if strings.HasPrefix(rest, "#") {
			break
		}
		var arg string
		if strings.HasPrefix(rest, `"`) {
			closing := strings.IndexByte(rest[1:], '"')
			if closing < 0 {
				return keyword, nil // sshd rejects an unterminated quote
			}
			arg, rest = rest[1:closing+1], rest[closing+2:]
		} else if space := strings.IndexAny(rest, " \t"); space >= 0 {
			arg, rest = rest[:space], rest[space:]
		} else {
			arg, rest = rest, ""
		}
		args = append(args, arg)
		rest = strings.TrimLeft(rest, " \t")
	}
	return keyword, args
}

// readTrustFile reads one public file the configuration names.
func readTrustFile(path string) ([]byte, string) {
	if !filepath.IsAbs(path) {
		return nil, StateRelative
	}
	data, err := readBounded(path, maxTrustFileBytes)
	if err != nil {
		return nil, fileState(err)
	}
	return data, StateRead
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("not a bounded regular file")
	}
	return os.ReadFile(path) // #nosec G304 -- the agent inventories operator-configured sshd configuration and the public files it names (CWE-22)
}

func fileState(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return StateMissing
	}
	return StateUnreadable
}

func orNone(value string) string {
	if value == "" || strings.EqualFold(value, "none") {
		return StateNone
	}
	return value
}

// ValidBeforeText renders a certificate's end for a report: RFC 3339, or
// "forever".
func (c HostCertificate) ValidBeforeText() string {
	if c.Certificate.Forever {
		return "forever"
	}
	if c.Certificate.ValidBefore.IsZero() {
		return ""
	}
	return c.Certificate.ValidBefore.UTC().Format(time.RFC3339)
}
