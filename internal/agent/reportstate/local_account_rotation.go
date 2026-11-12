// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

const localAccountRotationDirectory = "local-account-rotations"
const maxLocalAccountRotations = 5000
const maxLocalAccountRotationRecord = 16 << 10

// LocalAccountRotator owns native effects; the report store never receives a
// native password string and persists only public authority and proof.
type LocalAccountRotator interface {
	Rotate(context.Context, winaccounts.RotationBinding, string, []byte, []byte, winaccounts.RotationFence) (winaccounts.RotationProof, error)
}

// LocalAccountRecoverer settles a begun generation by sign-in (A268-O1).
type LocalAccountRecoverer interface {
	Recover(context.Context, winaccounts.RotationBinding, string, []byte, []byte, winaccounts.RotationFence) (winaccounts.RotationProof, error)
}
type localAccountRotationRecord struct {
	Version                 int                         `json:"version"`
	JobID                   int64                       `json:"job_id"`
	GenerationID            string                      `json:"generation_id"`
	PredecessorGenerationID string                      `json:"predecessor_generation_id,omitempty"`
	Binding                 winaccounts.RotationBinding `json:"binding"`
	StartedAt               time.Time                   `json:"started_at"`
	Phase                   string                      `json:"phase"`
	Proof                   *winaccounts.RotationProof  `json:"proof,omitempty"`
}

func validLocalAccountAuthority(job int64, b winaccounts.RotationBinding, generation, predecessor string) bool {
	id, e := uuid.Parse(generation)
	if job <= 0 || e != nil || id == uuid.Nil || id.String() != generation || b.Validate() != nil || predecessor == generation {
		return false
	}
	if predecessor != "" {
		parent, e := uuid.Parse(predecessor)
		if e != nil || parent == uuid.Nil || parent.String() != predecessor {
			return false
		}
	}
	return true
}
func validLocalAccountProof(p winaccounts.RotationProof) bool {
	return validLocalAccountAuthority(1, p.Binding, p.GenerationID, "") && p.NewAuthenticated && p.OldRefused && !p.ObservedAt.IsZero()
}
func sameAccountRotationProof(a, b winaccounts.RotationProof) bool {
	return a.Binding == b.Binding && a.GenerationID == b.GenerationID && a.NewAuthenticated == b.NewAuthenticated && a.OldRefused == b.OldRefused && a.ObservedAt.Equal(b.ObservedAt)
}
func (r localAccountRotationRecord) valid() bool {
	if r.Version != 1 || !validLocalAccountAuthority(r.JobID, r.Binding, r.GenerationID, r.PredecessorGenerationID) || r.StartedAt.IsZero() {
		return false
	}
	switch r.Phase {
	case "fenced", "not_applied":
		return r.Proof == nil
	case "completed", "acknowledged":
		return r.Proof != nil && validLocalAccountProof(*r.Proof) && r.Proof.Binding == r.Binding && r.Proof.GenerationID == r.GenerationID
	default:
		return false
	}
}
func localAccountRotationName(b winaccounts.RotationBinding) string {
	return crypto.SHA256Hex([]byte(b.Account.SID)) + ".state"
}
func localAccountFileStem(name string) (string, bool) {
	stem, ok := strings.CutSuffix(name, ".state")
	if !ok {
		stem, ok = strings.CutSuffix(name, ".next")
	}
	if !ok || len(stem) != 64 {
		return "", false
	}
	for _, c := range stem {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return stem, true
}
func (s *Store) localAccountDirectory(create bool) (*os.Root, error) {
	info, e := s.root.Lstat(localAccountRotationDirectory)
	if errors.Is(e, fs.ErrNotExist) && create {
		if e = s.root.Mkdir(localAccountRotationDirectory, 0700); e != nil {
			return nil, e
		}
		if e = secretfile.SecurePrivateDirectory(filepath.Join(s.path, localAccountRotationDirectory)); e != nil {
			return nil, e
		}
		if e = syncDirectory(s.root); e != nil {
			return nil, e
		}
		info, e = s.root.Lstat(localAccountRotationDirectory)
	}
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPending
	}
	return s.root.OpenRoot(localAccountRotationDirectory)
}
func (s *Store) localAccountAAD(name string) []byte {
	return []byte("trstctl.agent.local-account-rotation.v1\x00" + s.binding + "\x00" + name)
}
func (s *Store) readLocalAccountRotation(root *os.Root, name string) (*localAccountRotationRecord, error) {
	info, e := root.Lstat(name)
	if errors.Is(e, fs.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() < 28 || info.Size() > maxLocalAccountRotationRecord+64 {
		return nil, ErrInvalidPending
	}
	raw, e := secretfile.LoadBounded(filepath.Join(s.path, localAccountRotationDirectory, name), maxLocalAccountRotationRecord+64)
	if e != nil {
		return nil, e
	}
	defer secret.Wipe(raw)
	var plain []byte
	e = s.withKey(func(key []byte) error {
		var err error
		plain, err = crypto.AESGCMOpen(key, raw, s.localAccountAAD(name))
		return err
	})
	if e != nil {
		return nil, errors.Join(ErrUnopenable, e)
	}
	defer secret.Wipe(plain)
	if len(plain) > maxLocalAccountRotationRecord {
		return nil, ErrInvalidPending
	}
	var record localAccountRotationRecord
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&record); e != nil {
		return nil, ErrInvalidPending
	}
	if e = decoder.Decode(new(any)); !errors.Is(e, io.EOF) || !record.valid() || localAccountRotationName(record.Binding) != name {
		return nil, ErrInvalidPending
	}
	return &record, nil
}

// Inventory has the same account bound. Staging files are not execution proof:
// a torn completion staging file leaves the durable fenced record authoritative.
func (s *Store) localAccountRecords(root *os.Root, validate bool) (int, error) {
	directory, e := root.Open(".")
	if e != nil {
		return 0, e
	}
	defer func() { _ = directory.Close() }()
	names := map[string]struct{}{}
	count := 0
	for {
		entries, readErr := directory.ReadDir(64)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, readErr
		}
		for _, entry := range entries {
			count++
			if count > 2*maxLocalAccountRotations {
				return 0, ErrInvalidPending
			}
			stem, ok := localAccountFileStem(entry.Name())
			if !ok {
				return 0, ErrInvalidPending
			}
			info, e := root.Lstat(entry.Name())
			if e != nil {
				return 0, e
			}
			if !info.Mode().IsRegular() || info.Size() > maxLocalAccountRotationRecord+64 {
				return 0, ErrInvalidPending
			}
			names[stem] = struct{}{}
			if len(names) > maxLocalAccountRotations {
				return 0, ErrInvalidPending
			}
			if validate && strings.HasSuffix(entry.Name(), ".state") {
				if _, e = s.readLocalAccountRotation(root, entry.Name()); e != nil {
					return 0, e
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	return len(names), nil
}
func (s *Store) loadLocalAccountRotations() error {
	root, e := s.localAccountDirectory(false)
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer func() { _ = root.Close() }()
	_, e = s.localAccountRecords(root, true)
	return e
}
func (s *Store) storeLocalAccountRotation(record localAccountRotationRecord) (err error) {
	if !record.valid() {
		return ErrInvalidPending
	}
	defer func() {
		if err != nil {
			s.fault = errors.Join(errors.New("reportstate: local account journal persistence failed; further work refused"), err)
		}
	}()
	root, err := s.localAccountDirectory(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	name := localAccountRotationName(record.Binding)
	if info, e := root.Lstat(name); errors.Is(e, fs.ErrNotExist) {
		count, e := s.localAccountRecords(root, false)
		if e != nil {
			return e
		}
		if count >= maxLocalAccountRotations {
			return errors.New("reportstate: local account rotation identity bound reached; preserve existing fences")
		}
	} else if e != nil {
		return e
	} else if !info.Mode().IsRegular() {
		return ErrInvalidPending
	}
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer secret.Wipe(plain)
	if len(plain) > maxLocalAccountRotationRecord {
		return ErrInvalidPending
	}
	var ciphertext []byte
	err = s.withKey(func(key []byte) error {
		var e error
		ciphertext, e = crypto.AESGCMSeal(key, plain, s.localAccountAAD(name))
		return e
	})
	if err != nil {
		return err
	}
	defer secret.Wipe(ciphertext)
	staging := strings.TrimSuffix(name, ".state") + ".next"
	if info, e := root.Lstat(staging); e == nil && !info.Mode().IsRegular() {
		return ErrInvalidPending
	} else if e != nil && !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	file, err := root.OpenFile(staging, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err = secretfile.SecurePrivateFile(filepath.Join(s.path, localAccountRotationDirectory, staging)); err != nil {
		return err
	}
	if n, e := file.Write(ciphertext); e != nil {
		return e
	} else if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = root.Rename(staging, name); err != nil {
		return err
	}
	return syncDirectory(root)
}
func (s *Store) localAccountPrior(job int64, b winaccounts.RotationBinding, generation, predecessor string) (*localAccountRotationRecord, error) {
	if s.closed {
		return nil, fs.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	if !validLocalAccountAuthority(job, b, generation, predecessor) {
		return nil, ErrInvalidPending
	}
	root, e := s.localAccountDirectory(false)
	if errors.Is(e, fs.ErrNotExist) {
		if predecessor != "" {
			return nil, winaccounts.ErrRotationUncertain
		}
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer func() { _ = root.Close() }()
	record, e := s.readLocalAccountRotation(root, localAccountRotationName(b))
	if e != nil {
		return nil, e
	}
	if record == nil {
		if predecessor != "" {
			return nil, winaccounts.ErrRotationUncertain
		}
		return nil, nil
	}
	if record.GenerationID == generation && record.PredecessorGenerationID == predecessor && record.Binding == b {
		return record, nil
	}
	// A268-O1: a generation the account never took leaves its predecessor
	// current, so the next generation from that predecessor may begin.
	if record.Phase == "not_applied" && predecessor == record.PredecessorGenerationID && record.GenerationID != generation && record.Binding.Machine.SID == b.Machine.SID {
		return nil, nil
	}
	// Stable generation ancestry authorizes succession. Database-local delivery
	// IDs can change during outbox reconciliation or disaster recovery.
	if record.Phase != "acknowledged" || predecessor != record.GenerationID || record.GenerationID == generation || record.Binding.Machine.SID != b.Machine.SID {
		return nil, winaccounts.ErrRotationUncertain
	}
	return nil, nil
}

// ReplayLocalAccountRotation is read-only, so a lost receipt can be recovered
// without redeeming any credential or executing another authentication.
func (s *Store) ReplayLocalAccountRotation(ctx context.Context, job int64, b winaccounts.RotationBinding, generation, predecessor string) (winaccounts.RotationProof, bool, error) {
	var none winaccounts.RotationProof
	if s == nil {
		return none, false, ErrInvalidPending
	}
	if e := ctx.Err(); e != nil {
		return none, false, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, e := s.localAccountPrior(job, b, generation, predecessor)
	if e != nil || record == nil {
		return none, false, e
	}
	if record.Proof == nil {
		return none, false, winaccounts.ErrRotationUncertain
	}
	return *record.Proof, true, nil
}

type localAccountFence struct {
	store       *Store
	job         int64
	binding     winaccounts.RotationBinding
	generation  string
	predecessor string
}

func (f localAccountFence) Begin(ctx context.Context, b winaccounts.RotationBinding, generation string) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if b != f.binding || generation != f.generation {
		return false, ErrInvalidPending
	}
	s := f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	record, e := s.localAccountPrior(f.job, b, generation, f.predecessor)
	if e != nil || record != nil {
		return false, e
	}
	pending, e := s.read()
	if e != nil {
		return false, e
	}
	if pending != nil {
		pending.Destroy()
		return false, errors.New("reportstate: earlier report must be acknowledged before native account work")
	}
	record = &localAccountRotationRecord{Version: 1, JobID: f.job, GenerationID: generation, PredecessorGenerationID: f.predecessor, Binding: b, StartedAt: time.Now().UTC(), Phase: "fenced"}
	if e = s.storeLocalAccountRotation(*record); e != nil {
		return false, e
	}
	return true, nil
}
func (f localAccountFence) Complete(ctx context.Context, p winaccounts.RotationProof) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !validLocalAccountProof(p) || p.Binding != f.binding || p.GenerationID != f.generation {
		return ErrInvalidPending
	}
	s := f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	record, e := s.localAccountPrior(f.job, f.binding, f.generation, f.predecessor)
	if e != nil {
		return e
	}
	if record == nil {
		return ErrInvalidPending
	}
	if record.Proof != nil {
		if sameAccountRotationProof(*record.Proof, p) {
			return nil
		}
		return ErrInvalidPending
	}
	record.Phase = "completed"
	record.Proof = &p
	return s.storeLocalAccountRotation(*record)
}

// ExecuteLocalAccountRotationOnce persists the start fence before native reset.
// Any started attempt without its exact retained proof stays uncertain, including
// after a failed report is acknowledged. Completed proof is replayed without keys.
func (s *Store) ExecuteLocalAccountRotationOnce(ctx context.Context, job int64, b winaccounts.RotationBinding, generation, predecessor string, old, next []byte, executor LocalAccountRotator) (winaccounts.RotationProof, error) {
	var none winaccounts.RotationProof
	if s == nil || executor == nil {
		return none, ErrInvalidPending
	}
	if !s.accountMu.TryLock() {
		return none, errors.New("reportstate: local account rotation worker is busy")
	}
	defer s.accountMu.Unlock()
	p, found, e := s.ReplayLocalAccountRotation(ctx, job, b, generation, predecessor)
	if e != nil || found {
		return p, e
	}
	p, e = executor.Rotate(ctx, b, generation, old, next, localAccountFence{store: s, job: job, binding: b, generation: generation, predecessor: predecessor})
	if e != nil {
		return none, e
	}
	retained, found, e := s.ReplayLocalAccountRotation(ctx, job, b, generation, predecessor)
	if e != nil || !found || !sameAccountRotationProof(p, retained) {
		return none, errors.Join(winaccounts.ErrRotationUncertain, e)
	}
	return retained, nil
}

// RecoverLocalAccountRotationOnce settles a begun generation whose outcome
// is unknown (A268-O1). Only a fenced record of this exact generation is
// recovered, and only by sign-in: a proof completes the record as Rotate's
// would, and a generation the account never took is recorded not applied,
// which lets the next generation from the same predecessor begin. A record
// already settled answers as it was settled; nothing begun answers nothing.
func (s *Store) RecoverLocalAccountRotationOnce(ctx context.Context, job int64, b winaccounts.RotationBinding, generation, predecessor string, old, next []byte, executor LocalAccountRecoverer) (winaccounts.RotationProof, error) {
	var none winaccounts.RotationProof
	if s == nil || executor == nil {
		return none, ErrInvalidPending
	}
	if !s.accountMu.TryLock() {
		return none, errors.New("reportstate: local account rotation worker is busy")
	}
	defer s.accountMu.Unlock()
	if e := ctx.Err(); e != nil {
		return none, e
	}
	s.mu.Lock()
	record, e := s.localAccountPrior(job, b, generation, predecessor)
	s.mu.Unlock()
	switch {
	case e != nil:
		return none, e
	case record == nil:
		return none, ErrInvalidPending
	case record.Proof != nil:
		return *record.Proof, nil
	case record.Phase == "not_applied":
		return none, winaccounts.ErrRotationNotApplied
	case record.Phase != "fenced":
		return none, ErrInvalidPending
	}
	p, e := executor.Recover(ctx, b, generation, old, next, localAccountFence{store: s, job: job, binding: b, generation: generation, predecessor: predecessor})
	if errors.Is(e, winaccounts.ErrRotationNotApplied) {
		s.mu.Lock()
		defer s.mu.Unlock()
		record.Phase = "not_applied"
		if e := s.storeLocalAccountRotation(*record); e != nil {
			return none, errors.Join(winaccounts.ErrRotationUncertain, e)
		}
		return none, winaccounts.ErrRotationNotApplied
	}
	if e != nil {
		return none, e
	}
	retained, found, e := s.ReplayLocalAccountRotation(ctx, job, b, generation, predecessor)
	if e != nil || !found || !sameAccountRotationProof(p, retained) {
		return none, errors.Join(winaccounts.ErrRotationUncertain, e)
	}
	return retained, nil
}

func (s *Store) localAccountProofRecord(p winaccounts.RotationProof) (*localAccountRotationRecord, error) {
	root, e := s.localAccountDirectory(false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = root.Close() }()
	record, e := s.readLocalAccountRotation(root, localAccountRotationName(p.Binding))
	if e != nil {
		return nil, e
	}
	if record == nil || record.Proof == nil || !sameAccountRotationProof(*record.Proof, p) {
		return nil, ErrInvalidPending
	}
	return record, nil
}
func (s *Store) validateLocalAccountRotationReport(o Observation) error {
	if o.LocalAccountRotation == nil {
		return nil
	}
	p := *o.LocalAccountRotation
	if o.Outcome != "verified" || !validLocalAccountProof(p) {
		return ErrInvalidPending
	}
	record, e := s.localAccountProofRecord(p)
	if e != nil {
		return e
	}
	if record == nil || record.Proof == nil || !sameAccountRotationProof(*record.Proof, p) {
		return ErrInvalidPending
	}
	return nil
}
func (s *Store) acknowledgeLocalAccountRotation(o Observation) error {
	if o.LocalAccountRotation == nil {
		return nil
	}
	if e := s.validateLocalAccountRotationReport(o); e != nil {
		return e
	}
	p := *o.LocalAccountRotation
	record, e := s.localAccountProofRecord(p)
	if e != nil {
		return e
	}
	if record == nil {
		return ErrInvalidPending
	}
	if record.Phase == "acknowledged" {
		return nil
	}
	record.Phase = "acknowledged"
	return s.storeLocalAccountRotation(*record)
}
