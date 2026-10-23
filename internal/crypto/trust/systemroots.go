// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Go's Linux system-root loading rule (crypto/x509 root_linux.go and
// root_unix.go in Go 1.26), applied to an exported image filesystem so an
// audit can say exactly which certificates a Go program in that image trusts:
//   - SSL_CERT_FILE, else the first READABLE file of certFiles (a missing or
//     unreadable entry moves on to the next; the first readable one ends the
//     list even when it holds no certificate);
//   - SSL_CERT_DIR (colon-separated), else certDirectories;
//   - in a directory, every entry Go can read, except a symlink whose target
//     has no slash (an alias of a file in the same directory);
//   - a PEM block is a root only if it is a CERTIFICATE block without headers
//     that parses; anything else is skipped, as AppendCertsFromPEM skips it.
//
// Every path is resolved inside the exported root the way the image's own
// kernel would resolve it: an absolute symlink target is re-rooted and ".."
// stops at the root, so a link in the image never reads a file of the machine
// running the audit.
var (
	goLinuxCertFiles = []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
	goLinuxCertDirectories = []string{"/etc/ssl/certs", "/etc/pki/tls/certs"}
)

// maxSymlinkHops bounds symlink resolution inside an exported image (Linux
// itself gives up after 40).
const maxSymlinkHops = 40

// resolveInRoot resolves name (an absolute path inside the image) to the
// image path it finally names, following symlinks component by component
// with root standing in for "/". The result is image-absolute and never
// leaves root.
func resolveInRoot(root, name string) (string, error) {
	pending := strings.Split(strings.TrimPrefix(path.Clean("/"+name), "/"), "/")
	resolved := "/"
	hops := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, part)
		host := filepath.Join(root, filepath.FromSlash(next))
		info, err := os.Lstat(host)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if hops++; hops > maxSymlinkHops {
			return "", fmt.Errorf("trust: too many symlinks resolving %s", name)
		}
		target, err := os.Readlink(host)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return resolved, nil
}

// readInRoot reads an image file, following its symlinks inside root only.
func readInRoot(root, name string) ([]byte, error) {
	resolved, err := resolveInRoot(root, name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(resolved))) // #nosec G304 -- audit input: a path resolved inside an exported image filesystem (CWE-22)
}

// SystemRoot is one certificate Go would load, with where it came from.
type SystemRoot struct {
	Subject    string `json:"subject"`
	SPKISHA256 string `json:"spki_sha256"`
	CertSHA256 string `json:"cert_sha256"`
	Source     string `json:"source"`
}

// SystemRootsReport is what SystemRootsLike found.
type SystemRootsReport struct {
	Roots   []SystemRoot `json:"roots"`
	Sources []string     `json:"sources"`
	// Skipped counts PEM blocks Go would ignore: other block types, blocks
	// with headers, certificates that do not parse.
	Skipped int `json:"skipped"`
	// EnvFile and EnvDir are the SSL_CERT_FILE / SSL_CERT_DIR values the image
	// sets, if any; an audit refuses an image that redirects the store.
	EnvFile string `json:"ssl_cert_file,omitempty"`
	EnvDir  string `json:"ssl_cert_dir,omitempty"`
}

// SystemRootsLike applies Go's Linux rule under root (an exported image
// filesystem) with the image's environment. Paths in the report are
// image-absolute.
func SystemRootsLike(root string, env map[string]string) (SystemRootsReport, error) {
	rep := SystemRootsReport{EnvFile: env["SSL_CERT_FILE"], EnvDir: env["SSL_CERT_DIR"]}
	seen := map[string]bool{}
	// Go reads the bundle twice when it also sits in a certificate directory
	// (Debian's /etc/ssl/certs/ca-certificates.crt); a skipped block counts once.
	skipped := map[[32]byte]bool{}
	skip := func(block *pem.Block) {
		skipped[sha256.Sum256(pem.EncodeToMemory(block))] = true
		rep.Skipped = len(skipped)
	}
	add := func(source string, data []byte) {
		before := len(rep.Roots)
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				skip(block)
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				skip(block)
				continue
			}
			id := CertSHA256(c)
			if seen[id] {
				continue
			}
			seen[id] = true
			rep.Roots = append(rep.Roots, SystemRoot{Subject: c.Subject.String(), SPKISHA256: SPKISHA256(c), CertSHA256: id, Source: source})
		}
		if len(rep.Roots) > before {
			rep.Sources = append(rep.Sources, source)
		}
	}
	files := goLinuxCertFiles
	if rep.EnvFile != "" {
		files = []string{rep.EnvFile}
	}
	for _, f := range files {
		data, err := readInRoot(root, f)
		if err != nil {
			continue
		}
		add(f, data)
		break
	}
	dirs := goLinuxCertDirectories
	if rep.EnvDir != "" {
		dirs = strings.Split(rep.EnvDir, ":")
	}
	for _, d := range dirs {
		resolvedDir, err := resolveInRoot(root, d)
		if err != nil {
			continue
		}
		hostDir := filepath.Join(root, filepath.FromSlash(resolvedDir))
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Type()&os.ModeSymlink != 0 {
				target, err := os.Readlink(filepath.Join(hostDir, e.Name()))
				if err == nil && !strings.Contains(target, "/") {
					continue // an alias of a file in this directory, skipped as Go skips it
				}
			}
			entry := path.Join(resolvedDir, e.Name())
			data, err := readInRoot(root, entry)
			if err != nil {
				continue
			}
			add(path.Join(d, e.Name()), data)
		}
	}
	if len(rep.Roots) == 0 {
		return rep, errors.New("trust: no system roots found under " + root)
	}
	return rep, nil
}

// AuditFinding is one failure or warning of an image trust audit.
type AuditFinding struct {
	Level   string `json:"level"` // "fail" or "warn"
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// Audit compares an image's roots with Mozilla's websites list (PEM) and the
// distrust list: a root Mozilla does not trust for websites fails, a distrusted
// certificate fails, a Mozilla root the image lacks warns, and an SSL_CERT_*
// redirection fails unless SSL_CERT_FILE names the shipped bundle.
func Audit(rep SystemRootsReport, mozillaPEM []byte, list *List) ([]AuditFinding, error) {
	var findings []AuditFinding
	moz := map[string]string{}
	rest := mozillaPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust: Mozilla list certificate does not parse: %w", err)
		}
		moz[SPKISHA256(c)] = c.Subject.String()
	}
	if len(moz) == 0 {
		return nil, errors.New("trust: Mozilla list holds no certificates")
	}
	if rep.EnvDir != "" {
		findings = append(findings, AuditFinding{Level: "fail", Subject: "SSL_CERT_DIR=" + rep.EnvDir, Reason: "the image redirects the trust store"})
	}
	if rep.EnvFile != "" && rep.EnvFile != "/etc/ssl/certs/ca-certificates.crt" {
		findings = append(findings, AuditFinding{Level: "fail", Subject: "SSL_CERT_FILE=" + rep.EnvFile, Reason: "the image redirects the trust store"})
	}
	present := map[string]bool{}
	for _, r := range rep.Roots {
		present[r.SPKISHA256] = true
		if e, ok := list.MatchHashes(r.SPKISHA256, r.CertSHA256); ok {
			findings = append(findings, AuditFinding{Level: "fail", Subject: r.Subject, Reason: "distrusted: " + e.Name + " (" + r.Source + ")"})
			continue
		}
		if _, ok := moz[r.SPKISHA256]; !ok {
			findings = append(findings, AuditFinding{Level: "fail", Subject: r.Subject, Reason: "not in Mozilla's websites trust list (" + r.Source + ")"})
		}
	}
	for spki, subject := range moz {
		if !present[spki] {
			findings = append(findings, AuditFinding{Level: "warn", Subject: subject, Reason: "Mozilla trusts it for websites; the image lacks it"})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Level != findings[j].Level {
			return findings[i].Level < findings[j].Level
		}
		return findings[i].Subject < findings[j].Subject
	})
	return findings, nil
}
