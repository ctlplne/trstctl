// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

const taskExecutionArchivePrefix = "task-completed-"
const maxTaskExecutionArchives = 128

func taskExecutionArchiveName(jobID int64) string {
	return taskExecutionArchivePrefix + strconv.FormatInt(jobID, 10) + ".events"
}
func taskExecutionArchiveJob(name string) (int64, bool) {
	if !strings.HasPrefix(name, taskExecutionArchivePrefix) || !strings.HasSuffix(name, ".events") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, taskExecutionArchivePrefix), ".events")
	id, e := strconv.ParseInt(value, 10, 64)
	return id, e == nil && id > 0 && strconv.FormatInt(id, 10) == value
}
func (s *Store) taskExecutionArchives() ([]string, error) {
	directory, e := s.root.Open(".")
	if e != nil {
		return nil, e
	}
	defer func() { _ = directory.Close() }()
	var names []string
	count := 0
	for {
		entries, e := directory.ReadDir(64)
		if e != nil && !errors.Is(e, io.EOF) {
			return nil, e
		}
		for _, entry := range entries {
			count++
			if count > 1024 {
				return nil, errors.New("reportstate: private task state directory exceeds entry bound")
			}
			if !strings.HasPrefix(entry.Name(), taskExecutionArchivePrefix) {
				continue
			}
			if _, ok := taskExecutionArchiveJob(entry.Name()); !ok {
				return nil, ErrInvalidPending
			}
			names = append(names, entry.Name())
			if len(names) > maxTaskExecutionArchives {
				return nil, ErrInvalidPending
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	return names, nil
}
func completedTaskExecution(p *taskExecutionProjection) bool {
	if p.JobID == 0 || len(p.Steps) == 0 {
		return false
	}
	for _, state := range p.Steps {
		if state.Proof == nil {
			return false
		}
	}
	return true
}
func (s *Store) readTaskExecutionArchive(jobID int64) (*taskExecutionProjection, bool, error) {
	name := taskExecutionArchiveName(jobID)
	if _, e := s.root.Lstat(name); errors.Is(e, fs.ErrNotExist) {
		return nil, false, nil
	} else if e != nil {
		return nil, false, e
	}
	p, e := s.readTaskExecutionsFile(name)
	if e != nil {
		return nil, true, e
	}
	if p.JobID != jobID || !completedTaskExecution(p) {
		return nil, true, ErrInvalidPending
	}
	return p, true, nil
}

// A completed native run with a failed functional observation is retained as
// immutable sealed evidence. A distinct inverse can then run without erasing
// the old job's fence or pretending an unknown start completed.
func (s *Store) archiveCompletedTaskExecution(p *taskExecutionProjection) error {
	if !completedTaskExecution(p) {
		return errors.New("reportstate: unresolved task execution cannot be archived as completed")
	}
	names, e := s.taskExecutionArchives()
	if e != nil {
		return e
	}
	name := taskExecutionArchiveName(p.JobID)
	if _, e := s.root.Lstat(name); errors.Is(e, fs.ErrNotExist) {
		if len(names) >= maxTaskExecutionArchives {
			return errors.New("reportstate: completed failed-task evidence is full; preserve it for explicit recovery")
		}
		if e = s.root.Link(taskExecutionFile, name); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else {
		// A crash may retain both names. Verify exact ciphertext before finishing
		// the old active-name removal; never overwrite different retained evidence.
		a, e := secretfile.Load(filepath.Join(s.path, taskExecutionFile))
		if e != nil {
			return e
		}
		defer secret.Wipe(a)
		b, e := secretfile.Load(filepath.Join(s.path, name))
		if e != nil {
			return e
		}
		defer secret.Wipe(b)
		if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) {
			return ErrInvalidPending
		}
	}
	if e := syncDirectory(s.root); e != nil {
		return e
	}
	if e := s.root.Remove(taskExecutionFile); e != nil {
		return e
	}
	return syncDirectory(s.root)
}

// TaskExecutionReady is read-only preflight for a new rotation. Existing
// unresolved or unacknowledged work must be recovered before changing AD.
func (s *Store) TaskExecutionReady(ctx context.Context, task windependents.Task) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fs.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	if windependents.ValidateTaskSnapshot(task) != nil {
		return errors.New("reportstate: exact native task required")
	}
	p, e := s.readTaskExecutions()
	if e != nil {
		return e
	}
	if p.JobID != 0 {
		return errors.New("reportstate: earlier task work requires observation and acknowledgement before a new directory rotation")
	}
	pending, e := s.read()
	if e != nil {
		return e
	}
	if pending != nil {
		pending.Destroy()
		return errors.New("reportstate: an earlier native report is unacknowledged")
	}
	names, e := s.taskExecutionArchives()
	if e != nil {
		return e
	}
	if len(names) >= maxTaskExecutionArchives {
		return fmt.Errorf("reportstate: completed failed-task evidence reached its %d-job bound", maxTaskExecutionArchives)
	}
	return nil
}
