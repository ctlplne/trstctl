// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

type servedSSCEPGetCACertFiles struct {
	IssuerPath string
	RAPath     string
	AllPaths   []string
}

// servedDiscoverSSCEPGetCACertFiles understands both stock sscep output forms:
// one unsuffixed certificate, or a numbered CA/RA family. File order is not a
// trust signal. The exact public CA owned by the assembled server identifies the
// issuer; the remaining certificate must be usable to verify SCEP RA signatures.
func servedDiscoverSSCEPGetCACertFiles(basePath string, servedIssuerDER []byte) (servedSSCEPGetCACertFiles, error) {
	expected, err := certinfo.Inspect(servedIssuerDER)
	if err != nil {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("inspect served SCEP issuer: %w", err)
	}
	if !expected.IsCA || (expected.KeyUsageSet && !expected.KeyUsageCertSign) {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("served SCEP issuer is not a certificate-signing CA")
	}

	numbered, err := filepath.Glob(basePath + "-*")
	if err != nil {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("discover numbered sscep CA files: %w", err)
	}
	der, info, singleErr := servedInspectSSCEPCertificateFile(basePath)
	if singleErr == nil {
		if len(numbered) != 0 {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep wrote both unsuffixed and numbered CA files")
		}
		if info.SHA256Fingerprint != expected.SHA256Fingerprint {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("single sscep CA file is not the exact served issuer")
		}
		if info.KeyUsageSet && !info.KeyUsageDigitalSig {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("single sscep CA file cannot verify SCEP signatures")
		}
		if err := crypto.VerifyLeafSignedByCA(der, servedIssuerDER); err != nil {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("single sscep CA file is not bound to the served issuer: %w", err)
		}
		return servedSSCEPGetCACertFiles{IssuerPath: basePath, RAPath: basePath, AllPaths: []string{basePath}}, nil
	} else if !errors.Is(singleErr, os.ErrNotExist) {
		return servedSSCEPGetCACertFiles{}, singleErr
	}

	if len(numbered) == 0 {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep wrote no CA certificate files for %s", basePath)
	}
	if len(numbered) != 2 {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep wrote %d numbered CA files, want exactly CA plus RA", len(numbered))
	}
	byIndex := make(map[int]string, len(numbered))
	for _, path := range numbered {
		suffix := strings.TrimPrefix(path, basePath+"-")
		index, parseErr := strconv.Atoi(suffix)
		if parseErr != nil || index < 0 || strconv.Itoa(index) != suffix {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA file has invalid numeric suffix: %s", path)
		}
		if _, duplicate := byIndex[index]; duplicate {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA file index %d is duplicated", index)
		}
		byIndex[index] = path
	}
	paths := make([]string, len(numbered))
	for index := range paths {
		path, ok := byIndex[index]
		if !ok {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA file sequence is missing index %d", index)
		}
		paths[index] = path
	}

	var roles servedSSCEPGetCACertFiles
	roles.AllPaths = append([]string(nil), paths...)
	for _, path := range paths {
		der, info, readErr := servedInspectSSCEPCertificateFile(path)
		if readErr != nil {
			return servedSSCEPGetCACertFiles{}, readErr
		}
		if info.SHA256Fingerprint == expected.SHA256Fingerprint {
			if roles.IssuerPath != "" {
				return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA family contains the served issuer more than once")
			}
			roles.IssuerPath = path
			continue
		}
		if roles.RAPath != "" {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA family contains more than one non-issuer certificate")
		}
		if info.KeyUsageSet && !info.KeyUsageDigitalSig {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep RA certificate %s cannot verify digital signatures", path)
		}
		issuedByCA := crypto.VerifyLeafSignedByCA(der, servedIssuerDER) == nil
		selfSigned := info.Subject == info.Issuer && crypto.VerifyLeafSignedByCA(der, der) == nil
		if !issuedByCA && !selfSigned {
			return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep RA certificate %s is neither served-issuer-bound nor self-signed", path)
		}
		roles.RAPath = path
	}
	if roles.IssuerPath == "" || roles.RAPath == "" {
		return servedSSCEPGetCACertFiles{}, fmt.Errorf("sscep CA family does not contain one exact issuer and one signing RA")
	}
	return roles, nil
}

func servedInspectSSCEPCertificateFile(path string) ([]byte, certinfo.Info, error) {
	const maxSSCEPCertificateBytes = 1 << 20
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("open sscep output directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("open sscep certificate %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("stat open sscep certificate %s: %w", path, err)
	}
	if !stat.Mode().IsRegular() || stat.Size() == 0 {
		return nil, certinfo.Info{}, fmt.Errorf("sscep certificate %s is not a non-empty regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxSSCEPCertificateBytes+1))
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("read sscep certificate %s: %w", path, err)
	}
	if len(raw) > maxSSCEPCertificateBytes {
		return nil, certinfo.Info{}, fmt.Errorf("sscep certificate %s exceeds %d bytes", path, maxSSCEPCertificateBytes)
	}
	der, err := certinfo.LeafDER(raw)
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("parse sscep certificate %s: %w", path, err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("inspect sscep certificate %s: %w", path, err)
	}
	return der, info, nil
}

func TestDiscoverSSCEPGetCACertFilesAUD74(t *testing.T) {
	issuerSigner, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerSigner.Destroy)
	issuerDER, err := crypto.SelfSignedCACert(issuerSigner, "AUD-74 issuing CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raSigner, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raSigner.Destroy)
	raDER, err := crypto.SelfSignedCACert(raSigner, "AUD-74 protocol RA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("one certificate is both issuer and RA", func(t *testing.T) {
		dir := t.TempDir()
		base := servedWritePEMFile(t, dir, "sscep-ca.crt", "CERTIFICATE", issuerDER)
		got, err := servedDiscoverSSCEPGetCACertFiles(base, issuerDER)
		if err != nil {
			t.Fatal(err)
		}
		if got.IssuerPath != base || got.RAPath != base || len(got.AllPaths) != 1 {
			t.Fatalf("one-certificate roles = %+v, want %s as issuer and RA", got, base)
		}
	})

	for _, tc := range []struct {
		name        string
		issuerIndex int
	}{
		{name: "RA then issuer", issuerIndex: 1},
		{name: "issuer then RA", issuerIndex: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "sscep-ca.crt")
			issuerPath := base + "-" + strconv.Itoa(tc.issuerIndex)
			raPath := base + "-" + strconv.Itoa(1-tc.issuerIndex)
			servedWritePEMFile(t, dir, filepath.Base(issuerPath), "CERTIFICATE", issuerDER)
			servedWritePEMFile(t, dir, filepath.Base(raPath), "CERTIFICATE", raDER)

			got, err := servedDiscoverSSCEPGetCACertFiles(base, issuerDER)
			if err != nil {
				t.Fatal(err)
			}
			if got.IssuerPath != issuerPath || got.RAPath != raPath || len(got.AllPaths) != 2 {
				t.Fatalf("numbered certificate roles = %+v, want issuer=%s RA=%s", got, issuerPath, raPath)
			}
		})
	}
}

func TestDiscoverSSCEPGetCACertFilesRejectsAmbiguousOutputAUD74(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	issuerDER, err := crypto.SelfSignedCACert(signer, "AUD-74 issuing CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		seed func(t *testing.T, dir, base string)
	}{
		{name: "missing", seed: func(*testing.T, string, string) {}},
		{name: "mixed families", seed: func(t *testing.T, dir, base string) {
			servedWritePEMFile(t, dir, filepath.Base(base), "CERTIFICATE", issuerDER)
			servedWritePEMFile(t, dir, filepath.Base(base)+"-0", "CERTIFICATE", issuerDER)
		}},
		{name: "duplicate issuer", seed: func(t *testing.T, dir, base string) {
			servedWritePEMFile(t, dir, filepath.Base(base)+"-0", "CERTIFICATE", issuerDER)
			servedWritePEMFile(t, dir, filepath.Base(base)+"-1", "CERTIFICATE", issuerDER)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "sscep-ca.crt")
			tc.seed(t, dir, base)
			if got, err := servedDiscoverSSCEPGetCACertFiles(base, issuerDER); err == nil {
				t.Fatalf("ambiguous sscep output accepted: %+v", got)
			}
		})
	}
}
