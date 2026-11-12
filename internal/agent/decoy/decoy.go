// SPDX-License-Identifier: BUSL-1.1

// Package decoy plants and watches decoy files on the agent's host (Q6-O1).
// A decoy is an SSH private key — Ed25519, generated on the host and
// authorized nowhere — written at a path the operator chooses where no file
// is. Nothing has a reason to read it, so any process that opens it is a
// signal: the agent reports the open with the process it can name, and the
// control plane raises the decoy alert. The agent never opens its own decoys
// after planting them, and its discovery scans skip them (Is), so its own
// inventory never sets one off.
package decoy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The inventory source and finding kinds decoys report under.
const (
	Source       = "decoy-file"
	KindPlanted  = "decoy_file"
	KindAccessed = "decoy_file_accessed"
)

// Decoy is a planted decoy file.
type Decoy struct {
	Path string `json:"path"`
	// PublicKey is the decoy key's public half (authorized_keys form); it is
	// what identifies the decoy, and it unlocks nothing.
	PublicKey string    `json:"public_key"`
	PlantedAt time.Time `json:"planted_at"`
}

// Access is one open of a decoy file.
type Access struct {
	Path string
	At   time.Time
	// PID and Process name the opener when the watcher can see it (fanotify,
	// or the process still holds the file); zero and empty otherwise.
	PID     int
	Process string
	// Mechanism is the watcher that saw the open: "fanotify" or "inotify".
	Mechanism string
}

var (
	registryMu sync.RWMutex
	registry   = map[string]bool{}
)

// Is reports whether path is one of this agent's decoys; the agent's
// discovery scans skip such a path without opening it.
func Is(path string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if len(registry) == 0 {
		return false
	}
	return registry[filepath.Clean(path)]
}

func register(paths []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, p := range paths {
		registry[filepath.Clean(p)] = true
	}
}

// ErrExists refuses a path that holds a file the agent did not plant: a decoy
// never replaces a real file.
var ErrExists = errors.New("decoy: the path holds a file this agent did not plant")

// Plant writes a decoy SSH private key (mode 0600) at each absolute path that
// holds no file, keeps a decoy this agent planted before (recorded in the
// state file), and refuses any other existing file. It registers every decoy
// with Is before returning.
func Plant(paths []string, statePath string) ([]Decoy, error) {
	state := map[string]Decoy{}
	if raw, err := os.ReadFile(statePath); err == nil { // #nosec G304 -- the agent's own decoy state file (CWE-22)
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, fmt.Errorf("decoy: read state %s: %w", statePath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("decoy: read state %s: %w", statePath, err)
	}
	var out []Decoy
	var cleaned []string
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "." || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("decoy: %q is not an absolute path", raw)
		}
		cleaned = append(cleaned, path)
		if known, ok := state[path]; ok {
			if _, err := os.Lstat(path); err == nil {
				out = append(out, known)
				continue
			}
			delete(state, path) // gone: plant it again
		}
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("%w: %s", ErrExists, path)
		}
		private, public, err := cryptoboundary.GenerateSSHClientKey("backup@" + hostname())
		if err != nil {
			return nil, err
		}
		err = writeNew(path, private)
		secret.Wipe(private)
		if err != nil {
			return nil, err
		}
		d := Decoy{Path: path, PublicKey: string(bytes.TrimSpace(public)), PlantedAt: time.Now().UTC()}
		state[path] = d
		out = append(out, d)
	}
	register(cleaned)
	if err := saveState(statePath, state); err != nil {
		return nil, err
	}
	return out, nil
}

// writeNew creates path (and no other file) with mode 0600 and writes b.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- an operator-configured decoy path, created exclusively (CWE-22)
	if err != nil {
		return fmt.Errorf("decoy: create %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("decoy: write %s: %w", path, err)
	}
	return f.Close()
}

func saveState(statePath string, state map[string]Decoy) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return fmt.Errorf("decoy: state directory: %w", err)
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("decoy: write state: %w", err)
	}
	return os.Rename(tmp, statePath)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}
