// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/pluginhost"
)

// The connector library's operator side (A242): what the operator approved,
// how each module is doing, and what a failed call was.

// ModuleApproval is the operator's record that they reviewed one module's
// permissions. A later version that asks for no more runs under it; one that
// asks for more, comes from another publisher or is older waits for a new
// approval.
type ModuleApproval struct {
	Version      string                 `json:"version"`
	ModuleSHA256 string                 `json:"module_sha256"`
	Publisher    string                 `json:"publisher"`
	Permissions  pluginhost.Permissions `json:"permissions"`
	ApprovedAt   time.Time              `json:"approved_at"`
}

type moduleApprovalFile struct {
	Modules map[string]ModuleApproval `json:"modules"`
}

// ReadModuleApprovals reads the operator's approval record. A path that does
// not exist yet (or none at all) approves nothing.
func ReadModuleApprovals(path string) (map[string]ModuleApproval, error) {
	if path == "" {
		return map[string]ModuleApproval{}, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own approval record beside the agent key (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ModuleApproval{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("relay: read connector module approvals: %w", err)
	}
	var file moduleApprovalFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("relay: connector module approvals %s: %w", path, err)
	}
	if file.Modules == nil {
		file.Modules = map[string]ModuleApproval{}
	}
	return file.Modules, nil
}

// ApproveModule records st's version, build, publisher and permissions as
// approved in the record at path, replacing any earlier approval for it. The
// file is written whole and renamed into place, owner-only.
func ApproveModule(path string, st ModuleStatus, now time.Time) error {
	if path == "" {
		return errors.New("relay: no connector module approval file is configured")
	}
	if st.State == ModuleIncompatible || st.Digest == "" {
		return fmt.Errorf("relay: connector module %s cannot run on this relay (%s); an approval would not change that", st.Name, st.Reason)
	}
	approvals, err := ReadModuleApprovals(path)
	if err != nil {
		return err
	}
	approvals[st.Name] = ModuleApproval{
		Version: st.Manifest.Version, ModuleSHA256: st.Manifest.ModuleSHA256, Publisher: st.Publisher,
		Permissions: st.Manifest.Permissions, ApprovedAt: now.UTC(),
	}
	raw, err := json.MarshalIndent(moduleApprovalFile{Modules: approvals}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".approvals-*")
	if err != nil {
		return fmt.Errorf("relay: write connector module approvals: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("relay: write connector module approvals: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("relay: write connector module approvals: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("relay: write connector module approvals: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("relay: write connector module approvals: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// Failure classes a module call can end in beyond pluginhost's.
const (
	// FailureGrantDenied: the sandbox refused an operation outside the
	// module's grant.
	FailureGrantDenied = "grant-denied"
	// FailureStatus: the module returned a non-zero status.
	FailureStatus = "status"
)

// ModuleFailure is a third-party module's failed call, in terms the control
// plane may carry (A242): the module's verified identity, the entry point and
// what the host observed. Never text the module or its target chose, which can
// echo a credential back.
type ModuleFailure struct {
	Module  string
	Version string
	Digest  string
	Entry   string
	// Class is a pluginhost failure class, FailureGrantDenied, FailureStatus,
	// or the module's state when it is not loaded.
	Class  string
	Denied int64
	Status uint64
}

// Error is the closed phrase the relay reports.
func (f *ModuleFailure) Error() string {
	id := fmt.Sprintf("connector module %s %s (%s)", f.Module, f.Version, f.Digest)
	switch f.Class {
	case FailureGrantDenied:
		return fmt.Sprintf("%s %s attempted %d operation(s) outside its capability grant", id, f.Entry, f.Denied)
	case FailureStatus:
		return fmt.Sprintf("%s %s returned status %d", id, f.Entry, f.Status)
	case ModuleAwaitingApproval:
		return id + " awaits its operator's approval on this relay"
	case ModuleIncompatible:
		return id + " cannot run on this relay"
	default:
		return fmt.Sprintf("%s %s failed: %s", id, f.Entry, f.Class)
	}
}

// ModuleHealth is one loaded module's record of its calls (A242). Healthy is
// ConsecutiveFailures == 0.
type ModuleHealth struct {
	Calls               int64
	Failures            int64
	ConsecutiveFailures int64
	ByClass             map[string]int64
	LastFailure         string
	LastFailureAt       time.Time
}

type moduleHealth struct {
	mu sync.Mutex
	h  ModuleHealth
}

// record counts one call; class is empty for a success.
func (m *moduleHealth) record(class string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h.Calls++
	if class == "" {
		m.h.ConsecutiveFailures = 0
		return
	}
	m.h.Failures++
	m.h.ConsecutiveFailures++
	if m.h.ByClass == nil {
		m.h.ByClass = map[string]int64{}
	}
	m.h.ByClass[class]++
	m.h.LastFailure, m.h.LastFailureAt = class, time.Now().UTC()
}

func (m *moduleHealth) snapshot() ModuleHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.h
	out.ByClass = make(map[string]int64, len(m.h.ByClass))
	for class, n := range m.h.ByClass {
		out.ByClass[class] = n
	}
	return out
}

// FailureClasses lists a health record's classes, sorted, for reports.
func (h ModuleHealth) FailureClasses() []string {
	out := make([]string, 0, len(h.ByClass))
	for class := range h.ByClass {
		out = append(out, class)
	}
	sort.Strings(out)
	return out
}
