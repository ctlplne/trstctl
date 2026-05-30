// Package drift reconciles the credentials the agent installed on a host (S5.2)
// against their declared state, and detects when something on the host has moved
// them away from it: a certificate or key that was replaced, deleted, had its
// permissions loosened, or was relocated. What to do about each is policy
// (internal/agent/drift's Reconciler): alert only, alert and block, or
// auto-remediate — decided per credential class.
//
// Credentials are compared by a content fingerprint computed through the crypto
// boundary (AN-3); the package never parses the PEM and holds no crypto/*
// imports. Declared content used for remediation is carried as []byte (AN-8).
package drift

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"certctl.io/certctl/internal/crypto"
)

// maxScanFileSize bounds the size of files the relocation scan will hash, so a
// directory holding a large unrelated file is not expensive to scan.
const maxScanFileSize = 1 << 20

// Type classifies how on-host state diverged from what the agent declared.
type Type string

const (
	// None means the file matches its declared content and permissions.
	None Type = ""
	// Deleted means the declared file is gone and its content is nowhere in scope.
	Deleted Type = "deleted"
	// Replaced means the file exists but its content differs from declared.
	Replaced Type = "replaced"
	// PermissionChanged means the content matches but the permission bits differ.
	PermissionChanged Type = "permission_changed"
	// Relocated means the declared file is gone but its exact content was found
	// elsewhere in scope.
	Relocated Type = "relocated"
)

// Watched is a credential file the agent installed and now reconciles.
//
// Mode is the declared POSIX permission bits; a zero Mode skips the exact-mode
// check. Restricted declares that the credential is sensitive and must not be
// accessible to broad principals — it is the cross-platform way to ask for
// loosening detection: on POSIX it means no group/other access, and on Windows
// it means no allow ACE for Everyone, Authenticated Users, or Users (since Go's
// mode bits do not reflect the Windows DACL).
type Watched struct {
	Path        string
	Class       string // policy class, e.g. "certificate" or "private-key"
	Fingerprint string // expected SHA-256 hex of the file content
	Mode        os.FileMode
	Restricted  bool
}

// Finding is a detected divergence for one watched file.
type Finding struct {
	Watched    Watched
	Type       Type
	FoundAt    string      // Relocated: where the declared content now lives
	ActualMode os.FileMode // PermissionChanged: the mode found on disk (POSIX)
	Detail     string      // human-readable description of the divergence
}

// Fingerprint is the content fingerprint used to declare and compare a file. It
// routes through the crypto boundary (AN-3).
func Fingerprint(content []byte) string { return crypto.SHA256Hex(content) }

// Detect compares each watched file against the host filesystem and returns a
// Finding for each that has drifted. When a declared file is missing, the parent
// directory of its path — plus any extra scope directories — is scanned for its
// exact content, so a move is reported as Relocated rather than Deleted.
func Detect(watched []Watched, scope ...string) ([]Finding, error) {
	var findings []Finding
	for _, w := range watched {
		f, err := detectOne(w, scope)
		if err != nil {
			return nil, err
		}
		if f.Type != None {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func detectOne(w Watched, scope []string) (Finding, error) {
	info, err := os.Stat(w.Path)
	if errors.Is(err, fs.ErrNotExist) {
		if at, ok := scanForContent(w, scope); ok {
			return Finding{Watched: w, Type: Relocated, FoundAt: at}, nil
		}
		return Finding{Watched: w, Type: Deleted}, nil
	}
	if err != nil {
		return Finding{}, err
	}
	data, err := os.ReadFile(w.Path)
	if err != nil {
		return Finding{}, err
	}
	if Fingerprint(data) != w.Fingerprint {
		return Finding{Watched: w, Type: Replaced}, nil
	}
	if drifted, detail := permissionDrifted(w.Path, info, w); drifted {
		return Finding{Watched: w, Type: PermissionChanged, ActualMode: info.Mode(), Detail: detail}, nil
	}
	return Finding{Watched: w, Type: None}, nil
}

// SupportsPermissionDetection reports whether this platform can detect
// permission/ACL loosening. It is true on POSIX (mode bits) and Windows (the
// DACL), and false on platforms where neither mechanism is available. The agent
// should surface a false result once at startup so operators are not lulled into
// assuming coverage that this host cannot provide.
func SupportsPermissionDetection() bool { return permissionDetectionSupported }

// scanForContent looks for a file holding w's declared content in the parent of
// w.Path and in each scope directory (non-recursive). It returns the first match
// other than w.Path itself.
func scanForContent(w Watched, scope []string) (string, bool) {
	seen := map[string]bool{}
	dirs := append([]string{filepath.Dir(w.Path)}, scope...)
	for _, dir := range dirs {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if p == w.Path {
				continue
			}
			fi, err := e.Info()
			if err != nil || fi.Size() > maxScanFileSize {
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if Fingerprint(data) == w.Fingerprint {
				return p, true
			}
		}
	}
	return "", false
}
