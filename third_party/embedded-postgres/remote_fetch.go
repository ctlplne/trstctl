// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

// fetchRetryDelays bounds how a rate-limited or failing mirror is retried: one
// attempt per delay after the first, each waiting the server's Retry-After
// (capped at maxRetryAfter) or the delay. Many hosts starting at once (a CI run's
// parallel jobs) otherwise turn one HTTP 429 into a failed start.
var (
	fetchRetryDelays = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	maxRetryAfter    = time.Minute
	fetchSleep       = time.Sleep
)

func fetchBoundedResponse(client *http.Client, url string, maximum int64) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, retryAfter, err := fetchBoundedOnce(client, url, maximum)
		if err == nil || retryAfter < 0 || attempt >= len(fetchRetryDelays) {
			return data, err
		}
		delay := fetchRetryDelays[attempt]
		if retryAfter > 0 {
			delay = min(retryAfter, maxRetryAfter)
		}
		fetchSleep(delay)
	}
}

// fetchBoundedOnce makes one attempt. retryAfter is -1 when the failure is not
// worth retrying, 0 to use the backoff, and the server's Retry-After otherwise.
func fetchBoundedOnce(client *http.Client, url string, maximum int64) (data []byte, retryAfter time.Duration, err error) {
	response, err := client.Get(url)
	if err != nil {
		// A refused or unreachable network is not retried: an offline host fails fast.
		return nil, -1, fmt.Errorf("download postgres archive: %w", err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			err, retryAfter = errors.Join(err, closeErr), -1
		}
	}()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		retryAfter = 0
		if seconds, convErr := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After"))); convErr == nil && seconds > 0 {
			retryAfter = time.Duration(seconds) * time.Second
		}
		return nil, retryAfter, fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	default:
		return nil, -1, fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, -1, errors.New("postgres response exceeds byte limit")
	}
	data, err = readBounded(response.Body, maximum)
	if err != nil {
		return nil, -1, err
	}
	return data, 0, nil
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
