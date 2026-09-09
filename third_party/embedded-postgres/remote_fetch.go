// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

// RemoteFetchStrategy fetches an archive to its designated acquisition path.
type RemoteFetchStrategy func() error

func defaultRemoteFetchStrategy(host string, versionStrategy VersionStrategy, cacheLocator CacheLocator, client *http.Client, expectedName ...string) RemoteFetchStrategy {
	return func() error {
		operatingSystem, architecture, version := versionStrategy()
		jarURL := fmt.Sprintf("%s/io/zonky/test/postgres/embedded-postgres-binaries-%s-%s/%s/embedded-postgres-binaries-%s-%s-%s.jar", host, operatingSystem, architecture, version, operatingSystem, architecture, version)
		if client == nil {
			return errors.New("download client is required")
		}
		if err := netsec.ValidatePublicHTTPSURL(jarURL); err != nil {
			return fmt.Errorf("validate PostgreSQL download URL: %w", err)
		}
		jar, err := fetchBoundedResponse(client, jarURL, maxPostgresArchiveBytes)
		if err != nil {
			return err
		}
		sidecar, err := fetchBoundedResponse(client, jarURL+".sha256", 4096)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(sidecar)) != boundarycrypto.SHA256Hex(jar) {
			return errors.New("downloaded checksums do not match")
		}
		return decompressResponse(jar, int64(len(jar)), cacheLocator, jarURL, expectedName...)
	}
}

func fetchBoundedResponse(client *http.Client, url string, maximum int64) (data []byte, err error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download postgres archive: %w", err)
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, errors.New("postgres response exceeds byte limit")
	}
	return readBounded(response.Body, maximum)
}

func decompressResponse(body []byte, _ int64, cacheLocator CacheLocator, downloadURL string, expectedName ...string) error {
	if int64(len(body)) > maxPostgresArchiveBytes {
		return errors.New("postgres JAR exceeds byte limit")
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return errorFetchingPostgres(err)
	}
	if len(reader.File) > maxPostgresEntries {
		return errors.New("postgres JAR exceeds entry limit")
	}
	var selected *zip.File
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".txz") {
			if selected != nil || !file.Mode().IsRegular() {
				return errors.New("postgres JAR must contain exactly one regular TXZ")
			}
			name, err := archiveEntryName(file.Name)
			if err != nil || strings.Contains(name, "/") || name != file.Name {
				return errors.New("unsafe postgres JAR TXZ name")
			}
			if len(expectedName) > 0 && file.Name != expectedName[0] {
				return errors.New("postgres JAR contains an unexpected platform TXZ")
			}
			selected = file
		}
	}
	if selected == nil {
		return fmt.Errorf("error fetching postgres: cannot find binary in archive retrieved from %s", downloadURL)
	}
	location, _ := cacheLocator()
	return decompressSingleFile(selected, location)
}

func decompressSingleFile(file *zip.File, location string) (err error) {
	if file.UncompressedSize64 > uint64(maxPostgresArchiveBytes) {
		return errors.New("postgres TXZ exceeds byte limit")
	}
	reader, err := file.Open()
	if err != nil {
		return errorExtractingPostgres(err)
	}
	archive, readErr := readBounded(reader, maxPostgresArchiveBytes)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return errorExtractingPostgres(err)
	}
	// Served acquisition points here at a new private directory. The immutable
	// shared cache is published separately, only after its independent pin passes.
	return publishVerifiedArchive(filepath.Dir(location), filepath.Base(location), archive, true)
}

func errorExtractingPostgres(err error) error {
	return fmt.Errorf("unable to extract postgres archive: %w", err)
}
func errorFetchingPostgres(err error) error { return fmt.Errorf("error fetching postgres: %w", err) }
