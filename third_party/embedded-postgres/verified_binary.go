// SPDX-License-Identifier: MIT

package embeddedpostgres

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/xi2/xz"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	maxPostgresArchiveBytes    int64  = 256 << 20
	maxPostgresExtractBytes    int64  = 2 << 30
	maxPostgresFileBytes       int64  = 256 << 20
	maxPostgresEntries                = 20000
	maxPostgresDictionaryBytes uint32 = 64 << 20
)

// ArchiveIdentity is a caller-owned trust decision, independent of a download
// server's checksum sidecar. All fields are mandatory and match the exact build.
type ArchiveIdentity struct {
	OS      string
	Arch    string
	Version PostgresVersion
	SHA256  string
}

// expectedTXZName follows the committed served manifest's inner archive names.
func expectedTXZName(strategy VersionStrategy) string {
	goos, arch, _ := strategy()
	names := map[string]string{"amd64": "x86_64", "arm64v8": "arm_64"}
	return "postgres-" + goos + "-" + names[arch] + ".txz"
}

// NewVerifiedDatabase requires authenticated archive bytes and derives a fresh
// private executable tree on every Start. It never trusts BinariesPath contents.
// NewDatabase retains the separately scoped legacy integration-fixture API;
// served callers must use this constructor with their committed identity.
func NewVerifiedDatabase(config Config, identity ArchiveIdentity) (*EmbeddedPostgres, error) {
	if err := validateArchiveIdentity(config, identity); err != nil {
		return nil, err
	}
	ep := newDatabaseWithConfig(config)
	ep.archiveIdentity = &identity
	ep.verifiedConfig = config
	return ep, nil
}

func validateArchiveIdentity(config Config, identity ArchiveIdentity) error {
	supported := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	supported = supported || runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
	if !supported {
		return errors.New("verified postgres platform ownership is unsupported")
	}
	if config.dataPath == "" {
		return errors.New("verified postgres requires an explicit persistent data path")
	}
	goos, arch, version := defaultVersionStrategy(config, runtime.GOOS, runtime.GOARCH,
		linuxMachineName, shouldUseAlpineLinuxBuild)()
	if !regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`).MatchString(string(version)) {
		return errors.New("invalid postgres archive version")
	}
	if identity.OS != goos || identity.Arch != arch || identity.Version != version || version == "" {
		return errors.New("postgres archive identity does not match configured version and platform")
	}
	if len(identity.SHA256) != 64 || strings.Trim(identity.SHA256, "0123456789abcdef") != "" {
		return errors.New("postgres archive identity requires a committed lowercase SHA-256")
	}
	return nil
}

// AcquireArchive authenticates and publishes the configured archive without
// extracting or executing it. Start repeats authentication on its exact bytes.
func (ep *EmbeddedPostgres) AcquireArchive() error {
	if ep.archiveIdentity == nil {
		return errors.New("archive acquisition requires NewVerifiedDatabase")
	}
	_, err := ep.acquireVerifiedArchive()
	return err
}

func (ep *EmbeddedPostgres) acquireVerifiedArchive() ([]byte, error) {
	if err := validateArchiveIdentity(ep.verifiedConfig, *ep.archiveIdentity); err != nil {
		return nil, err
	}
	cacheLocation, _ := ep.cacheLocator()
	cacheDir := filepath.Dir(cacheLocation)
	if err := ensurePrivateCache(cacheDir); err != nil {
		return nil, err
	}
	var archive []byte
	info, err := os.Lstat(cacheLocation)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("postgres archive must be a regular file, not a link")
		}
		archive, err = readBoundedArchive(cacheDir, filepath.Base(cacheLocation))
	} else if errors.Is(err, os.ErrNotExist) {
		archive, err = ep.acquirePrivateArchive()
	} else {
		return nil, fmt.Errorf("inspect postgres archive: %w", err)
	}
	if err != nil {
		return nil, err
	}
	if boundarycrypto.SHA256Hex(archive) != ep.archiveIdentity.SHA256 {
		return nil, errors.New("postgres archive provenance check FAILED: committed SHA-256 mismatch")
	}
	if err := publishVerifiedArchive(cacheDir, filepath.Base(cacheLocation), archive); err != nil {
		return nil, err
	}
	return archive, nil
}

func (ep *EmbeddedPostgres) acquirePrivateArchive() (archive []byte, err error) {
	source := ep.verifiedConfig.archiveSourcePath
	if source != "" {
		if _, err := os.Lstat(source); err == nil {
			return readBoundedArchive(filepath.Dir(source), filepath.Base(source))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	owned, err := os.MkdirTemp("", "trstctl-pg-acquire-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(owned)) }()
	destination := filepath.Join(owned, "download.txz")
	if err := ep.fetchVerifiedArchive(destination); err != nil {
		return nil, err
	}
	return readBoundedArchive(owned, "download.txz")
}

// Link is an atomic create-if-absent publication. Every contender validates the
// winning destination; a different preexisting file is never overwritten.
func publishVerifiedArchive(dir, name string, archive []byte, legacy ...bool) (err error) {
	requireOwner := len(legacy) == 0 || !legacy[0]
	if err := ensureCacheDirectory(dir, requireOwner); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	nonce, err := boundarycrypto.RandomBytes(16)
	if err != nil {
		return err
	}
	tempName := fmt.Sprintf(".verified-archive-%x", nonce)
	temp, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Remove(tempName)) }()
	_, writeErr := temp.Write(archive)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := root.Link(tempName, name); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	winning, err := readBoundedArchive(dir, name)
	if err != nil {
		return err
	}
	if !bytes.Equal(winning, archive) {
		return errors.New("postgres archive publication collision: winning bytes differ")
	}
	return nil
}

func (ep *EmbeddedPostgres) prepareVerifiedBinary() error {
	if ep.verifiedRunPath != "" {
		return errors.New("previous verified postgres tree still requires cleanup")
	}
	ep.config = ep.verifiedConfig
	archive, err := ep.acquireVerifiedArchive()
	if err != nil {
		return err
	}
	// Only these authenticated in-memory bytes feed rooted extraction.
	owned, err := os.MkdirTemp("", "trstctl-pg-verified-")
	if err != nil {
		return err
	}
	ep.verifiedRunPath = owned
	root, err := os.OpenRoot(owned)
	if err != nil {
		return errors.Join(err, ep.cleanupVerifiedBinary())
	}
	defer root.Close()
	if err := root.Mkdir(".unpublished-binaries", 0700); err != nil {
		return errors.Join(err, ep.cleanupVerifiedBinary())
	}
	binaries, err := root.OpenRoot(".unpublished-binaries")
	if err != nil {
		return errors.Join(err, ep.cleanupVerifiedBinary())
	}
	err = extractVerifiedArchive(archive, binaries)
	closeErr := binaries.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr, ep.cleanupVerifiedBinary())
	}
	if err := root.Rename(".unpublished-binaries", "binaries"); err != nil {
		return errors.Join(err, ep.cleanupVerifiedBinary())
	}
	ep.config.binariesPath = filepath.Join(owned, "binaries")
	ep.config.runtimePath = filepath.Join(owned, "runtime")
	return nil
}

// An existing legacy cache is read without chmod, deletion, or migration. New
// cache directories are private. Group/world-writable or symlink roots fail.
func ensurePrivateCache(dir string) error { return ensureCacheDirectory(dir, true) }

func ensureCacheDirectory(dir string, requireOwner bool) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) || (requireOwner && !ownedByCurrentUser(info)) {
		return errors.New("postgres cache must be a real directory not writable by group or other users")
	}
	return nil
}

// VerifyArchiveFile is read-only. Only an actually absent path returns false,
// nil. Symlinks, nonregular files, oversized bytes and mismatches are errors.
func VerifyArchiveFile(archivePath, digest string) (bool, error) {
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return false, errors.New("invalid postgres archive digest")
	}
	if _, err := os.Lstat(archivePath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	data, err := readBoundedArchive(filepath.Dir(archivePath), filepath.Base(archivePath))
	if err != nil {
		return false, err
	}
	if boundarycrypto.SHA256Hex(data) != digest {
		return false, errors.New("postgres archive provenance check FAILED: committed SHA-256 mismatch")
	}
	return true, nil
}

func readBoundedArchive(dir, name string) ([]byte, error) {
	return readBoundedRegularFile(dir, name, maxPostgresArchiveBytes)
}

func readBoundedRegularFile(dir, name string, maximum int64) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, errors.New("postgres archive missing, linked, non-regular, or too large")
	}
	file, err := openRegularFile(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("postgres archive changed while opening")
	}
	data, err := readBounded(file, maximum)
	if err != nil {
		return nil, err
	}
	after, err := root.Lstat(name)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || int64(len(data)) != opened.Size() {
		return nil, errors.New("postgres archive changed while reading")
	}
	return data, nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("postgres archive exceeds byte limit")
	}
	return data, nil
}

func archiveEntryName(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimSuffix(name, "/")
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\:\x00") {
		return "", errors.New("unsafe postgres archive entry name")
	}
	return name, nil
}

// Extraction is into a fresh private root. Links are installed only after all
// regular files; a rooted Stat rejects dangling, cyclic and escaping links.
func extractVerifiedArchive(archive []byte, root *os.Root) error {
	xzReader, err := xz.NewReader(bytes.NewReader(archive), maxPostgresDictionaryBytes)
	if err != nil {
		return err
	}
	// Count raw decompressed headers, padding and PAX/GNU metadata, which
	// archive/tar may consume internally without returning a visible entry.
	return extractVerifiedTar(tar.NewReader(&boundedArchiveReader{reader: xzReader, remaining: maxPostgresExtractBytes}), root)
}

type boundedArchiveReader struct {
	reader    io.Reader
	remaining int64
}

func (r *boundedArchiveReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("postgres decompressed stream exceeds byte limit")
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func extractVerifiedTar(reader *tar.Reader, root *os.Root) error {
	return extractBoundedTar(reader, root, archiveLimits{maxPostgresFileBytes, maxPostgresExtractBytes, maxPostgresEntries})
}

type archiveLimits struct {
	fileBytes, expandedBytes int64
	entries                  int
}

func extractBoundedTar(reader *tar.Reader, root *os.Root, limits archiveLimits) error {
	if limits.fileBytes <= 0 || limits.expandedBytes <= 0 || limits.entries <= 0 {
		return errors.New("invalid postgres extraction limits")
	}
	seen := make(map[string]byte)
	links := make(map[string]string)
	var expanded int64
	for count := 0; ; count++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if count >= limits.entries || header.Size < 0 || header.Size > limits.fileBytes || header.Size > limits.expandedBytes-expanded {
			return errors.New("postgres archive exceeds extraction limits")
		}
		expanded += header.Size
		name, err := archiveEntryName(header.Name)
		if err != nil {
			return err
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate postgres archive entry")
		}
		seen[name] = header.Typeflag
		if err := root.MkdirAll(path.Dir(name), 0700); err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0700); err != nil {
				return err
			}
		case tar.TypeReg:
			if header.Mode&07000 != 0 {
				return errors.New("privileged mode in postgres archive")
			}
			// Discard group/other write access from supplied archive modes.
			mode := os.FileMode(header.Mode & 0755)
			file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
		case tar.TypeSymlink:
			if header.Linkname == "" || strings.ContainsAny(header.Linkname, "\\:\x00") || path.IsAbs(header.Linkname) {
				return errors.New("unsafe postgres archive link")
			}
			target := path.Clean(path.Join(path.Dir(name), header.Linkname))
			if !fs.ValidPath(target) || target == "." {
				return errors.New("escaping postgres archive link")
			}
			links[name] = header.Linkname
		default:
			return errors.New("unsupported postgres archive entry type")
		}
	}
	for name, target := range links {
		if err := root.Symlink(target, name); err != nil {
			return err
		}
	}
	for name := range links {
		if _, err := root.Stat(name); err != nil {
			return fmt.Errorf("invalid postgres archive link: %w", err)
		}
	}
	for _, binary := range []string{"initdb", "pg_ctl", "postgres"} {
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		info, err := root.Lstat("bin/" + binary)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0100 == 0 {
			return errors.New("authenticated postgres archive lacks a regular executable")
		}
	}
	return nil
}

func (ep *EmbeddedPostgres) cleanupVerifiedBinary() error {
	if ep.verifiedRunPath == "" {
		return nil
	}
	var closeErr error
	if ep.syncedLogger != nil {
		closeErr = ep.syncedLogger.file.Close()
		ep.syncedLogger = nil
	}
	err := os.RemoveAll(ep.verifiedRunPath)
	if err == nil {
		ep.verifiedRunPath = ""
	}
	return errors.Join(closeErr, err)
}

func (ep *EmbeddedPostgres) initVerifiedDataDirectory() error {
	info, err := os.Lstat(ep.config.dataPath)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !ownedByCurrentUser(info) {
			return errors.New("postgres data path must be a real directory")
		}
		entries, err := os.ReadDir(ep.config.dataPath)
		if err != nil || len(entries) != 0 {
			return errors.New("refusing to remove existing unrecognized postgres data")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return ep.initDatabase(ep.config.binariesPath, ep.config.runtimePath, ep.config.dataPath,
		ep.config.username, ep.config.password, ep.config.locale, ep.config.encoding, ep.syncedLogger.file)
}

func (ep *EmbeddedPostgres) verifiedDataReady() (bool, error) {
	info, err := os.Lstat(ep.config.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !ownedByCurrentUser(info) {
		return false, errors.New("postgres data path must be an owned real directory")
	}
	root, err := os.OpenRoot(ep.config.dataPath)
	if err != nil {
		return false, err
	}
	defer root.Close()
	versionInfo, err := root.Lstat("PG_VERSION")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // initVerifiedDataDirectory preserves any nonempty directory.
	}
	if err != nil || !versionInfo.Mode().IsRegular() || versionInfo.Size() > 16 {
		return false, errors.New("postgres data version must be a regular bounded file")
	}
	version, err := readBoundedRegularFile(ep.config.dataPath, "PG_VERSION", 16)
	if err != nil {
		return false, err
	}
	major, _, _ := strings.Cut(string(ep.config.version), ".")
	if strings.TrimSuffix(string(version), "\n") != major {
		return false, errors.New("refusing to overwrite postgres data from an incompatible version")
	}
	return true, nil
}
