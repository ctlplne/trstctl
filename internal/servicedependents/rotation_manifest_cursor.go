// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"errors"
	"math"
	"trstctl.com/trstctl/internal/crypto"
)

const ManifestComplete = "complete"

// ManifestPosition is the exact location in an immutable page chain. SQL
// ordinals alone cannot identify native authority: a rewritten index could
// otherwise select a different, individually valid object.
type ManifestPosition struct {
	Stage        string `json:"stage"`
	EntryOrdinal int64  `json:"entry_ordinal"`
	PageNumber   int64  `json:"page_number"`
	EntryIndex   int    `json:"entry_index"`
}
type ManifestCursor struct {
	Direction string           `json:"direction"`
	Position  ManifestPosition `json:"position"`
}

func (p ManifestPosition) validateEffect(direction, action string) error {
	if p.Stage != action || p.EntryOrdinal < 0 || p.PageNumber < 0 || p.PageNumber == math.MaxInt64 || p.EntryIndex < 0 || direction == Inverse && p.Stage == Preflight {
		return errors.New("service dependents: exact manifest stage and nonnegative source location required")
	}
	switch p.Stage {
	case Preflight, Stop, Update, Start, Probe:
		return nil
	}
	return errors.New("service dependents: unknown manifest effect stage")
}
func (c ManifestCursor) Validate(seal RotationManifestSeal) error {
	if err := seal.ValidateShape(); err != nil {
		return err
	}
	if c.Direction != Forward && c.Direction != Inverse {
		return errors.New("service dependents: invalid manifest direction")
	}
	p := c.Position
	if p.Stage == ManifestComplete {
		if p.EntryOrdinal != seal.EntryCount || p.PageNumber != seal.PageCount || p.EntryIndex != 0 {
			return errors.New("service dependents: noncanonical complete cursor")
		}
		return nil
	}
	if err := p.validateEffect(c.Direction, p.Stage); err != nil {
		return err
	}
	if p.EntryOrdinal >= seal.EntryCount || p.PageNumber >= seal.PageCount {
		return errors.New("service dependents: manifest location exceeds its seal")
	}
	return nil
}

// RotationManifestResolver holds only scalar authority and a bounded page
// reader. Its caller must read pages from canonical immutable sources, validate
// their tenant and source identity, and prove the seal's complete chain before
// admitting the root. A cached SQL index is not an implementation of Page.
type RotationManifestResolver struct {
	Header RotationManifestHeader
	Seal   RotationManifestSeal
	Page   func(int64) (RotationManifestPage, error)
}

func (r RotationManifestResolver) page(number int64) (RotationManifestPage, error) {
	if r.Page == nil || number < 0 || number >= r.Seal.PageCount {
		return RotationManifestPage{}, errors.New("service dependents: bounded canonical page reader required")
	}
	if err := r.Seal.Validate(r.Header); err != nil {
		return RotationManifestPage{}, err
	}
	p, err := r.Page(number)
	if err != nil {
		return p, err
	}
	if err := p.Validate(r.Header); err != nil {
		return p, err
	}
	if p.Number != number || p.Number == r.Seal.PageCount-1 && p.Digest != r.Seal.TailDigest {
		return p, errors.New("service dependents: canonical page differs from sealed location")
	}
	return p, nil
}
func (r RotationManifestResolver) edge(stage string, reverse bool) (ManifestPosition, error) {
	n := int64(0)
	if reverse {
		n = r.Seal.PageCount - 1
	}
	p, err := r.page(n)
	if err != nil {
		return ManifestPosition{}, err
	}
	for {
		if len(p.Entries) > 0 {
			v := ManifestPosition{Stage: stage, PageNumber: p.Number}
			if reverse {
				v.EntryOrdinal = r.Seal.EntryCount - 1
				v.EntryIndex = len(p.Entries) - 1
			}
			return v, nil
		}
		p, err = r.adjacent(p, reverse)
		if err != nil {
			return ManifestPosition{}, err
		}
	}
}
func (r RotationManifestResolver) adjacent(p RotationManifestPage, reverse bool) (RotationManifestPage, error) {
	n := p.Number + 1
	if reverse {
		n = p.Number - 1
	}
	next, err := r.page(n)
	if err != nil {
		return next, err
	}
	if reverse {
		err = ValidateRotationManifestLink(r.Header, p, &next)
	} else {
		err = ValidateRotationManifestLink(r.Header, next, &p)
	}
	return next, err
}
func (r RotationManifestResolver) Initial(direction string) (ManifestCursor, error) {
	stage := Preflight
	if direction == Inverse {
		stage = Stop
	} else if direction != Forward {
		return ManifestCursor{}, errors.New("service dependents: invalid manifest direction")
	}
	p, err := r.edge(stage, stage == Stop)
	if err != nil {
		return ManifestCursor{}, err
	}
	c := ManifestCursor{Direction: direction, Position: p}
	return c, c.Validate(r.Seal)
}
func (r RotationManifestResolver) Entry(c ManifestCursor) (RotationManifestEntry, error) {
	if err := c.Validate(r.Seal); err != nil {
		return RotationManifestEntry{}, err
	}
	if c.Position.Stage == ManifestComplete {
		return RotationManifestEntry{}, errors.New("service dependents: complete cursor carries no native entry")
	}
	p, err := r.page(c.Position.PageNumber)
	if err != nil {
		return RotationManifestEntry{}, err
	}
	if c.Position.EntryIndex >= len(p.Entries) {
		return RotationManifestEntry{}, errors.New("service dependents: entry index exceeds exact source page")
	}
	return p.Entries[c.Position.EntryIndex], nil
}

// Advance preserves the global stages, including reverse-order stops. It does
// not prove execution. A source transition must separately prove a successful
// current-head native receipt or that the exact snapshot makes this stage idle.
func (r RotationManifestResolver) Advance(c ManifestCursor) (ManifestCursor, error) {
	if err := c.Validate(r.Seal); err != nil {
		return ManifestCursor{}, err
	}
	if c.Position.Stage == ManifestComplete {
		return ManifestCursor{}, errors.New("service dependents: complete cursor has no successor")
	}
	p, err := r.page(c.Position.PageNumber)
	if err != nil {
		return ManifestCursor{}, err
	}
	position := c.Position
	if position.EntryIndex >= len(p.Entries) {
		return ManifestCursor{}, errors.New("service dependents: entry index exceeds exact source page")
	}
	reverse := position.Stage == Stop
	delta := 1
	if reverse {
		delta = -1
	}
	index := position.EntryIndex + delta
	ordinalEnd := position.EntryOrdinal == r.Seal.EntryCount-1
	if reverse {
		ordinalEnd = position.EntryOrdinal == 0
	}
	for index < 0 || index >= len(p.Entries) {
		pageEnd := p.Number == r.Seal.PageCount-1
		if reverse {
			pageEnd = p.Number == 0
		}
		if pageEnd {
			break
		}
		p, err = r.adjacent(p, reverse)
		if err != nil {
			return ManifestCursor{}, err
		}
		index = 0
		if reverse {
			index = len(p.Entries) - 1
		}
	}
	hasNext := index >= 0 && index < len(p.Entries)
	if hasNext == ordinalEnd {
		return ManifestCursor{}, errors.New("service dependents: cursor ordinal disagrees with its source-chain boundary")
	}
	if hasNext {
		position.PageNumber = p.Number
		position.EntryIndex = index
		position.EntryOrdinal += int64(delta)
	} else {
		stage := ""
		switch position.Stage {
		case Preflight:
			stage = Stop
		case Stop:
			stage = Update
		case Update:
			stage = Start
		case Start:
			stage = Probe
		case Probe:
			stage = ManifestComplete
		}
		if stage == ManifestComplete {
			position = ManifestPosition{Stage: stage, EntryOrdinal: r.Seal.EntryCount, PageNumber: r.Seal.PageCount}
		} else {
			position, err = r.edge(stage, stage == Stop)
			if err != nil {
				return ManifestCursor{}, err
			}
		}
	}
	next := ManifestCursor{Direction: c.Direction, Position: position}
	return next, next.Validate(r.Seal)
}

// Step resolves one exact native object from one signed, bounded inventory.
// False means a stage has no effect for this snapshot, never native success.
func (r RotationManifestResolver) Step(intent RotationIntent, c ManifestCursor, input RotationHostInput) (RotationStep, bool, error) {
	exact, err := NewRotationIntentFromManifest(r.Header, r.Seal)
	if err != nil {
		return RotationStep{}, false, err
	}
	digest, err := intent.Digest()
	if err != nil {
		return RotationStep{}, false, err
	}
	want, err := exact.Digest()
	if err != nil || want != digest {
		return RotationStep{}, false, errors.New("service dependents: native intent differs from canonical sealed header")
	}
	entry, err := r.Entry(c)
	if err != nil {
		return RotationStep{}, false, err
	}
	host := entry.Host
	if input.Binding != host.Binding || input.InventoryDigest != host.InventoryDigest || input.Inventory.RunID != host.InventoryRunID || !input.Inventory.ObservedAt.Equal(host.ObservedAt) {
		return RotationStep{}, false, errors.New("service dependents: native input differs from exact manifest scan")
	}
	scan, err := NewInventoryIntent(host.InventoryRunID, host.Binding)
	if err != nil {
		return RotationStep{}, false, err
	}
	if err := input.Inventory.Validate(scan); err != nil {
		return RotationStep{}, false, err
	}
	raw, err := json.Marshal(input.Inventory)
	if err != nil || crypto.SHA256Hex(raw) != host.InventoryDigest || !input.Inventory.Complete() {
		return RotationStep{}, false, errors.New("service dependents: incomplete or rewritten native inventory")
	}
	position := c.Position
	step := RotationStep{ManifestPosition: &position, RotationID: intent.Plan.ID, PlanDigest: digest, Direction: c.Direction, Action: position.Stage, Ref: entry.Ref, AccountSID: intent.Plan.Account.SID, ProbeID: entry.ProbeID}
	for _, v := range input.Inventory.Services {
		if entry.Ref.Family == "services" && entry.Ref.Name == v.Name {
			snapshot := v
			step.Service = &snapshot
		}
	}
	for _, v := range input.Inventory.Tasks {
		if entry.Ref.Family == "tasks" && entry.Ref.Name == v.Path {
			snapshot := v
			step.Task = &snapshot
		}
	}
	for _, v := range input.Inventory.Pools {
		if entry.Ref.Family == "iis" && entry.Ref.Name == v.Name {
			snapshot := v
			step.Pool = &snapshot
		}
	}
	if step.Service == nil && step.Task == nil && step.Pool == nil {
		return RotationStep{}, false, errors.New("service dependents: manifest reference is absent from signed native scan")
	}
	applicable := true
	switch step.Action {
	case Stop, Start:
		applicable = step.Task == nil && step.Active()
	case Update:
		applicable = step.Task == nil || step.Task.LogonType == 1
	}
	if !applicable {
		return RotationStep{}, false, nil
	}
	step.ID = crypto.SHA256Hex([]byte(step.RotationID + "\x00" + step.PlanDigest + "\x00" + step.Direction + "\x00" + step.Action + "\x00" + dependentKey(step.Ref)))[:32]
	return step, true, step.Validate()
}
