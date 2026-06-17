package backup

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	FullManifestName = "manifest.json"
	fullFormatTag    = "trstctl-full-backup"
	fullVersion      = 1
)

// Artifact describes one file or directory covered by a full DR backup manifest.
type Artifact struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Path       string `json:"path"`
	SourcePath string `json:"source_path,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	Exists     bool   `json:"exists"`
	Captured   bool   `json:"captured"`
	Sensitive  bool   `json:"sensitive"`
	Required   bool   `json:"required"`
}

// FullManifest is the buyer/auditor-facing inventory of a full DR artifact.
type FullManifest struct {
	Format          string              `json:"format"`
	Version         int                 `json:"version"`
	CreatedAt       time.Time           `json:"created_at"`
	Artifacts       []Artifact          `json:"artifacts"`
	RecoveryClasses map[string][]string `json:"recovery_classes"`
}

func NewFullManifest(artifacts []Artifact) FullManifest {
	return FullManifest{
		Format:    fullFormatTag,
		Version:   fullVersion,
		CreatedAt: time.Now().UTC(),
		Artifacts: artifacts,
		RecoveryClasses: map[string][]string{
			string(ClassLogRebuild):     append([]string(nil), RecoveredByLogRebuild...),
			string(ClassPostgresBackup): append([]string(nil), RecoveredFromPostgresBackup...),
			string(ClassEphemeral):      append([]string(nil), Ephemeral...),
		},
	}
}

func WriteFullManifest(path string, m FullManifest) error {
	for class := range m.RecoveryClasses {
		sort.Strings(m.RecoveryClasses[class])
	}
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Name < m.Artifacts[j].Name })
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("backup: create full manifest: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: encode full manifest: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: close full manifest: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: publish full manifest: %w", err)
	}
	return nil
}

func ReadFullManifest(path string) (FullManifest, error) {
	var m FullManifest
	f, err := os.Open(path)
	if err != nil {
		return m, fmt.Errorf("backup: open full manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return m, fmt.Errorf("backup: decode full manifest: %w", err)
	}
	if m.Format != fullFormatTag {
		return m, fmt.Errorf("backup: not a trstctl full backup manifest (format %q)", m.Format)
	}
	if m.Version != fullVersion {
		return m, fmt.Errorf("backup: unsupported full backup manifest version %d (want %d)", m.Version, fullVersion)
	}
	return m, nil
}

func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	return crypto.SHA256ReaderHex(f)
}

func HashTree(root string) (string, int64, error) {
	var entries []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		entries = append(entries, path)
		return nil
	}); err != nil {
		return "", 0, err
	}
	sort.Strings(entries)
	var payload []byte
	var total int64
	for _, path := range entries {
		sum, n, err := HashFile(path)
		if err != nil {
			return "", total, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return "", total, err
		}
		payload = append(payload, []byte(filepath.ToSlash(rel)+" "+sum+"\n")...)
		total += n
	}
	return crypto.SHA256Hex(payload), total, nil
}

func CopyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func CopyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return CopyFile(path, target, info.Mode().Perm())
	})
}
