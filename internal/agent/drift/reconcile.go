package drift

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Mode is the remediation policy applied to a credential class when it drifts.
type Mode string

const (
	// AlertOnly records the drift and takes no corrective action.
	AlertOnly Mode = "alert_only"
	// AlertAndBlock records the drift and blocks the credential, signalling the
	// caller to stop relying on it until an operator intervenes.
	AlertAndBlock Mode = "alert_and_block"
	// AutoRemediate records the drift and restores the declared state.
	AutoRemediate Mode = "auto_remediate"
)

// Policy decides the remediation mode for a credential class.
type Policy interface {
	Mode(class string) Mode
}

// ClassPolicy maps a credential class to a remediation mode. An unknown class
// defaults to AlertOnly — the safest mode, which never modifies the host.
type ClassPolicy map[string]Mode

// Mode returns the mode for class, defaulting to AlertOnly.
func (p ClassPolicy) Mode(class string) Mode {
	if m, ok := p[class]; ok {
		return m
	}
	return AlertOnly
}

// Event is the audit record emitted for a detected drift and the action taken.
type Event struct {
	Time       time.Time
	Path       string
	Class      string
	Type       Type
	Mode       Mode // the remediation mode applied
	FoundAt    string
	Remediated bool
	Blocked    bool
	Detail     string
}

// Auditor records drift events. Production wires it to the control-plane audit
// trail (a drift event is reported and projected per AN-2); tests record in
// memory.
type Auditor interface {
	Record(Event)
}

// Restorer restores a drifted file to its declared state for AutoRemediate.
type Restorer interface {
	Restore(ctx context.Context, f Finding) error
}

// Reconciler detects drift across watched files and acts on each per policy,
// auditing every drift it finds.
type Reconciler struct {
	Policy   Policy
	Auditor  Auditor
	Restorer Restorer         // required for AutoRemediate
	Clock    func() time.Time // defaults to time.Now
}

// Report summarizes a reconciliation pass.
type Report struct {
	Findings   []Finding
	Events     []Event
	Blocked    []string // paths blocked
	Remediated []string // paths restored
	// PermissionDetectionSupported reports whether this platform could detect
	// permission/ACL loosening on this pass. When false, permission drift was
	// not checked — the agent should surface that to operators.
	PermissionDetectionSupported bool
}

// Reconcile detects drift for the watched files and applies the policy for each
// finding: it audits every drift, blocks where the policy says so, and restores
// declared state where remediation is enabled.
func (r *Reconciler) Reconcile(ctx context.Context, watched []Watched, scope ...string) (Report, error) {
	findings, err := Detect(watched, scope...)
	if err != nil {
		return Report{}, err
	}
	now := time.Now
	if r.Clock != nil {
		now = r.Clock
	}

	rep := Report{Findings: findings, PermissionDetectionSupported: permissionDetectionSupported}
	for _, f := range findings {
		mode := r.Policy.Mode(f.Watched.Class)
		ev := Event{
			Time:    now(),
			Path:    f.Watched.Path,
			Class:   f.Watched.Class,
			Type:    f.Type,
			Mode:    mode,
			FoundAt: f.FoundAt,
			Detail:  f.Detail,
		}
		switch mode {
		case AutoRemediate:
			if r.Restorer == nil {
				ev.Detail = "auto-remediate configured but no restorer"
			} else if err := r.Restorer.Restore(ctx, f); err != nil {
				ev.Detail = "remediation failed: " + err.Error()
			} else {
				ev.Remediated = true
				rep.Remediated = append(rep.Remediated, f.Watched.Path)
			}
		case AlertAndBlock:
			ev.Blocked = true
			rep.Blocked = append(rep.Blocked, f.Watched.Path)
		}
		r.Auditor.Record(ev)
		rep.Events = append(rep.Events, ev)
	}
	return rep, nil
}

// FileRestorer restores drifted files from the declared content the agent holds,
// keyed by path. Restoring rewrites the declared content with the declared
// permission mode and removes a relocated stray copy.
type FileRestorer struct {
	content map[string][]byte
}

var _ Restorer = (*FileRestorer)(nil)

// NewFileRestorer builds a restorer over a path->declared-content map.
func NewFileRestorer(content map[string][]byte) *FileRestorer {
	return &FileRestorer{content: content}
}

// Restore rewrites the declared content at the watched path with the declared
// mode and, for a relocation, removes the stray copy.
func (fr *FileRestorer) Restore(_ context.Context, f Finding) error {
	data, ok := fr.content[f.Watched.Path]
	if !ok {
		return fmt.Errorf("drift: no declared content for %s", f.Watched.Path)
	}
	if f.Type == Relocated && f.FoundAt != "" {
		if err := os.Remove(f.FoundAt); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("drift: remove relocated copy %s: %w", f.FoundAt, err)
		}
	}
	mode := f.Watched.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(f.Watched.Path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(f.Watched.Path, data, mode); err != nil {
		return err
	}
	// WriteFile is subject to umask and leaves an existing file's mode unchanged;
	// set the declared mode unconditionally.
	return os.Chmod(f.Watched.Path, mode)
}

// LogAuditor is an Auditor that writes drift events to a slog.Logger — a usable
// default when a host has no control-plane connection. Production reporting wires
// the control-plane audit trail behind the same Auditor seam.
type LogAuditor struct{ Logger *slog.Logger }

var _ Auditor = LogAuditor{}

// Record logs the drift event.
func (l LogAuditor) Record(e Event) {
	log := l.Logger
	if log == nil {
		log = slog.Default()
	}
	log.Warn("credential drift",
		"path", e.Path, "class", e.Class, "drift", string(e.Type),
		"mode", string(e.Mode), "remediated", e.Remediated, "blocked", e.Blocked,
		"found_at", e.FoundAt, "detail", e.Detail,
	)
}
