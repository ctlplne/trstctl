// SPDX-License-Identifier: BUSL-1.1

// Package reportarchive retains exact signed compliance report bytes outside
// the replay log. An operator must back up and apply archive-erasure policy to
// this directory, just as with exported audit bundles.
package reportarchive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Dir is an operator-controlled private archive root. It may be mounted on
// shared durable storage, but must be writable only by the control-plane user.
type Dir struct{ Root string }

// Reference binds a report to canonical tenant/run UUIDs and its exact digest.
// It is always relative to the configured archive root.
func Reference(tenantID, runID, digest string) (string, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant.String() != tenantID {
		return "", errors.New("reportarchive: tenant id must be a canonical UUID")
	}
	run, err := uuid.Parse(runID)
	if err != nil || run.String() != runID {
		return "", errors.New("reportarchive: run id must be a canonical UUID")
	}
	if !digestPattern.MatchString(digest) {
		return "", errors.New("reportarchive: digest must be lowercase SHA-256 hex")
	}
	return path.Join("reports", tenantID, runID, digest+".json"), nil
}

// Put stores exact JSON wire bytes once. It fsyncs the file and directory
// before returning a reference suitable for the immutable completion event.
// Retrying the same write is safe; different bytes can never replace the file.
func (d Dir) Put(tenantID, runID string, artifact []byte) (ref, digest string, err error) {
	if !json.Valid(artifact) {
		return "", "", errors.New("reportarchive: signed report is not JSON")
	}
	digest = crypto.SHA256Hex(artifact)
	ref, err = Reference(tenantID, runID, digest)
	if err != nil {
		return "", "", err
	}
	if d.Root == "" {
		return "", "", errors.New("reportarchive: archive root is required")
	}
	root, err := filepath.Abs(d.Root)
	if err != nil {
		return "", "", err
	}
	reports := filepath.Join(root, "reports")
	tenantDir := filepath.Join(reports, tenantID)
	dir := filepath.Join(tenantDir, runID)
	for _, path := range []string{root, reports, tenantDir, dir} {
		if err := ensurePrivateDirectory(path); err != nil {
			return "", "", err
		}
	}
	final := filepath.Join(root, filepath.FromSlash(ref))
	if existing, readErr := readExact(final, digest); readErr == nil {
		if !bytes.Equal(existing, artifact) {
			return "", "", errors.New("reportarchive: digest collision")
		}
		return ref, digest, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", readErr
	}
	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return "", "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		return "", "", errors.Join(err, tmp.Close())
	}
	if _, err := io.Copy(tmp, bytes.NewReader(artifact)); err != nil {
		return "", "", errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return "", "", errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	// Link is atomic and refuses to replace an existing signed artifact.
	if err := os.Link(tmpName, final); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", "", err
		}
		existing, readErr := readExact(final, digest)
		if readErr != nil || !bytes.Equal(existing, artifact) {
			return "", "", errors.New("reportarchive: existing artifact differs from signed bytes")
		}
	}
	if err := syncDirectory(dir); err != nil {
		return "", "", err
	}
	return ref, digest, nil
}

// Read verifies path identity and bytes before returning an archive artifact.
func (d Dir) Read(tenantID, runID, digest string) ([]byte, error) {
	ref, err := Reference(tenantID, runID, digest)
	if err != nil {
		return nil, err
	}
	if d.Root == "" {
		return nil, errors.New("reportarchive: archive root is required")
	}
	root, err := filepath.Abs(d.Root)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{root, filepath.Join(root, "reports"), filepath.Join(root, "reports", tenantID), filepath.Join(root, "reports", tenantID, runID)} {
		if err := checkPrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	return readExact(filepath.Join(root, filepath.FromSlash(ref)), digest)
}

// FindRun recovers an archived candidate after a crash between durable Put and
// the completion event. More than one digest for the same run is ambiguous and
// must be resolved by an operator; recovery never chooses one arbitrarily.
func (d Dir) FindRun(tenantID, runID string) (ref, digest string, artifact []byte, err error) {
	if _, err = Reference(tenantID, runID, strings.Repeat("0", 64)); err != nil {
		return "", "", nil, err
	}
	if d.Root == "" {
		return "", "", nil, errors.New("reportarchive: archive root is required")
	}
	root, err := filepath.Abs(d.Root)
	if err != nil {
		return "", "", nil, err
	}
	tenantDir := filepath.Join(root, "reports", tenantID)
	dir := filepath.Join(tenantDir, runID)
	for _, path := range []string{root, filepath.Join(root, "reports"), tenantDir, dir} {
		if err := checkPrivateDirectory(path); err != nil {
			return "", "", nil, err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		candidateDigest := strings.TrimSuffix(name, ".json")
		if !digestPattern.MatchString(candidateDigest) {
			return "", "", nil, errors.New("reportarchive: malformed artifact for run")
		}
		if ref != "" {
			return "", "", nil, errors.New("reportarchive: multiple signed artifacts for one run")
		}
		ref, err = Reference(tenantID, runID, candidateDigest)
		if err != nil {
			return "", "", nil, err
		}
		digest = candidateDigest
	}
	if ref == "" {
		return "", "", nil, os.ErrNotExist
	}
	artifact, err = d.Read(tenantID, runID, digest)
	if err != nil {
		return "", "", nil, err
	}
	return ref, digest, artifact, nil
}

func ensurePrivateDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := checkPrivateDirectory(path); err != nil {
		return err
	}
	if err == nil {
		return syncDirectory(filepath.Dir(path))
	}
	return nil
}

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("reportarchive: directory is not private: %s", path)
	}
	return nil
}

func readExact(path, digest string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("reportarchive: artifact is not a private regular file")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed reports path under operator archive root; both path IDs and digest are validated UUID/SHA-256 components.
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) || !strings.EqualFold(crypto.SHA256Hex(data), digest) {
		return nil, errors.New("reportarchive: artifact failed digest or JSON validation")
	}
	return data, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- directory is constructed under the operator archive root and checked as a private real directory.
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	return errors.Join(syncErr, dir.Close())
}
