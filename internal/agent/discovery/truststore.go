// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jks"
)

const (
	trustStoreKindOS      = "os"
	trustStoreKindJava    = "java"
	trustStoreKindNSS     = "nss"
	trustStoreKindBrowser = "browser"
	trustStoreKindWindows = "windows"

	maxTrustStoreFileSize = 16 << 20
)

type trustStoreFileSource struct {
	kind     string
	platform string
	browser  string
	profile  string
	roots    []string
	maxSize  int64
}

var _ Source = (*trustStoreFileSource)(nil)

// NewOSTrustStoreSource discovers public CA certificates in OS trust-store files or
// directories. On Linux this covers locations such as /etc/ssl/certs and
// /etc/pki/ca-trust/source/anchors; tests pass fixture directories.
func NewOSTrustStoreSource(platform string, roots ...string) Source {
	return &trustStoreFileSource{kind: trustStoreKindOS, platform: platform, roots: roots, maxSize: maxTrustStoreFileSize}
}

// NewNSSTrustStoreSource discovers public certificates exported from an NSS profile
// or kept in a profile-adjacent PEM/DER trust bundle.
func NewNSSTrustStoreSource(profile string, roots ...string) Source {
	return &trustStoreFileSource{kind: trustStoreKindNSS, profile: profile, roots: roots, maxSize: maxTrustStoreFileSize}
}

// NewBrowserTrustStoreSource discovers browser-managed public trust anchors from a
// browser profile export directory.
func NewBrowserTrustStoreSource(browser, profile string, roots ...string) Source {
	return &trustStoreFileSource{kind: trustStoreKindBrowser, browser: browser, profile: profile, roots: roots, maxSize: maxTrustStoreFileSize}
}

func (s *trustStoreFileSource) Kind() string { return SourceTrustStore }

func (s *trustStoreFileSource) Discover(ctx context.Context) ([]Found, error) {
	var out []Found
	for _, root := range s.roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				return nil
			}
			if fi, ierr := d.Info(); ierr != nil || fi.Size() > s.maxSize {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, der := range certBlocks(data) {
				info, perr := certinfo.Inspect(der)
				if perr != nil {
					continue
				}
				out = append(out, Found{
					Source:   SourceTrustStore,
					Location: trustStoreLocation(s.kind, path),
					Cert:     info,
					Metadata: s.metadata(),
				})
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *trustStoreFileSource) metadata() map[string]string {
	meta := trustStoreMetadata(s.kind)
	if s.platform != "" {
		meta["platform"] = s.platform
	}
	if s.browser != "" {
		meta["browser"] = s.browser
	}
	if s.profile != "" {
		meta["profile"] = s.profile
	}
	return meta
}

type javaTrustStoreSource struct {
	path     string
	password string
	maxSize  int64
}

var _ Source = (*javaTrustStoreSource)(nil)

// NewJavaTrustStoreSource discovers public trusted-certificate entries from a Java
// JKS/cacerts trust store. Empty password means Java's conventional "changeit".
func NewJavaTrustStoreSource(path, password string) Source {
	if password == "" {
		password = "changeit"
	}
	return &javaTrustStoreSource{path: path, password: password, maxSize: maxTrustStoreFileSize}
}

func (s *javaTrustStoreSource) Kind() string { return SourceTrustStore }

func (s *javaTrustStoreSource) Discover(ctx context.Context) ([]Found, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data, err := readTrustStoreFile(s.path, s.maxSize)
	if err != nil {
		return nil, err
	}
	certs, err := jks.DecodeTrustedCertificates(data, s.password)
	if err != nil {
		return nil, err
	}
	out := make([]Found, 0, len(certs))
	for alias, pemBytes := range certs {
		info, perr := certinfo.Inspect(pemBytes)
		if perr != nil {
			continue
		}
		meta := trustStoreMetadata(trustStoreKindJava)
		meta["alias"] = alias
		out = append(out, Found{
			Source:   SourceTrustStore,
			Location: trustStoreLocation(trustStoreKindJava, location(s.path, alias)),
			Cert:     info,
			Metadata: meta,
		})
	}
	return out, nil
}

// NewWindowsTrustStoreSource discovers public certificates from a Windows trust
// store enumerator. The real Windows backend can supply a CryptoAPI enumerator; tests
// use the in-memory store fixture.
func NewWindowsTrustStoreSource(storeName string, enum CertEnumerator) Source {
	return NewTrustStoreEnumSource("windows/"+storeName, enum, map[string]string{
		"trust_store_kind":    trustStoreKindWindows,
		"platform":            "windows",
		"store":               storeName,
		"private_key_present": "false",
	})
}

func readTrustStoreFile(path string, maxSize int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("trust store %s is a directory", path)
	}
	if fi.Size() > maxSize {
		return nil, fmt.Errorf("trust store %s is %d bytes; maximum is %d", path, fi.Size(), maxSize)
	}
	return os.ReadFile(path)
}

func trustStoreMetadata(kind string) map[string]string {
	return map[string]string{
		"trust_store_kind":    kind,
		"private_key_present": "false",
	}
}

func trustStoreLocation(kind, ref string) string {
	if ref == "" {
		return kind
	}
	return kind + "/" + ref
}
