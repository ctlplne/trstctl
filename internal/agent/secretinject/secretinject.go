// Package secretinject runs the trstctl workload secret-injection sidecar.
//
// The sidecar reads Kubernetes Secret volume files as bytes and publishes them into
// a shared volume for the application container. Secret values are never converted
// to strings; path and key names are the only string data handled here.
package secretinject

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	DefaultSourceDir = "/var/run/trstctl/source"
	DefaultTargetDir = "/trstctl/secrets"
	DefaultInterval  = 30 * time.Second
	DefaultFileMode  = 0o400
)

type Mapping struct {
	Key  string
	Path string
}

type Options struct {
	SourceDir string
	TargetDir string
	Mappings  []Mapping
	Interval  time.Duration
	FileMode  fs.FileMode
	Once      bool
}

func ParseMappings(raw string) ([]Mapping, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	mappings := make([]Mapping, 0, len(parts))
	for _, part := range parts {
		key, target, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, fmt.Errorf("secretinject: mapping %q must be key=relative/path", part)
		}
		mappings = append(mappings, Mapping{Key: key, Path: target})
	}
	return mappings, nil
}

func Run(ctx context.Context, opts Options) error {
	if err := CopyOnce(opts); err != nil {
		return err
	}
	if opts.Once {
		return nil
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := CopyOnce(opts); err != nil {
				return err
			}
		}
	}
}

func CopyOnce(opts Options) error {
	sourceDir := strings.TrimSpace(opts.SourceDir)
	if sourceDir == "" {
		sourceDir = DefaultSourceDir
	}
	targetDir := strings.TrimSpace(opts.TargetDir)
	if targetDir == "" {
		targetDir = DefaultTargetDir
	}
	fileMode := opts.FileMode
	if fileMode == 0 {
		fileMode = DefaultFileMode
	}
	mappings, err := normalizeMappings(sourceDir, targetDir, opts.Mappings)
	if err != nil {
		return err
	}
	if len(mappings) == 0 {
		mappings, err = discoverMappings(sourceDir, targetDir)
		if err != nil {
			return err
		}
	}
	for _, m := range mappings {
		if err := copyOne(m.Key, m.Path, fileMode); err != nil {
			return err
		}
	}
	return nil
}

func normalizeMappings(sourceDir, targetDir string, mappings []Mapping) ([]Mapping, error) {
	if sourceDir == "" || targetDir == "" {
		return nil, errors.New("secretinject: source and target directories are required")
	}
	out := make([]Mapping, 0, len(mappings))
	for _, m := range mappings {
		key := strings.TrimSpace(m.Key)
		if key == "" || key != filepath.Base(key) || key == "." || key == ".." {
			return nil, fmt.Errorf("secretinject: invalid source key %q", m.Key)
		}
		target, err := cleanTarget(targetDir, m.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, Mapping{Key: filepath.Join(sourceDir, key), Path: target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func discoverMappings(sourceDir, targetDir string) ([]Mapping, error) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("secretinject: read source dir: %w", err)
	}
	out := make([]Mapping, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		target, err := cleanTarget(targetDir, name)
		if err != nil {
			return nil, err
		}
		out = append(out, Mapping{Key: filepath.Join(sourceDir, name), Path: target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func cleanTarget(root, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("secretinject: target path is required")
	}
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("secretinject: target path %q must be relative to target dir", target)
	}
	clean := filepath.Clean(target)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("secretinject: target path %q escapes target dir", target)
	}
	return filepath.Join(root, clean), nil
}

func copyOne(sourcePath, targetPath string, fileMode fs.FileMode) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("secretinject: read %s: %w", filepath.Base(sourcePath), err)
	}
	defer secret.Wipe(data)
	defer runtime.KeepAlive(data)

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("secretinject: create target dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(targetPath), ".trstctl-secret-*")
	if err != nil {
		return fmt.Errorf("secretinject: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("secretinject: write temp file: %w", err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("secretinject: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("secretinject: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("secretinject: publish target file: %w", err)
	}
	return nil
}
