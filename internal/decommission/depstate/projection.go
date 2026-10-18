// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// KeyState is the folded per-key dependency state and the substrate for
// VDEC-claim-15: a deterministic-replay projection over the ledger from which the
// set difference between dependents registered as of a stated ledger position and
// dependents accounted for by completion, release, or erasure-designation events
// must be empty before destruction.
type KeyState struct {
	KeyID             string
	TenantID          string
	Registered        []Dependent
	Accounted         []Dependent
	Released          []Dependent
	ErasureDesignated []Dependent
	LedgerPosition    uint64
}

func (s KeyState) Unaccounted() []Dependent {
	accounted := make(map[string]struct{}, len(s.Accounted)+len(s.Released)+len(s.ErasureDesignated))
	for _, dep := range s.Accounted {
		accounted[dep.key()] = struct{}{}
	}
	for _, dep := range s.Released {
		accounted[dep.key()] = struct{}{}
	}
	for _, dep := range s.ErasureDesignated {
		accounted[dep.key()] = struct{}{}
	}
	out := make([]Dependent, 0)
	for _, dep := range s.Registered {
		if _, ok := accounted[dep.key()]; !ok {
			out = append(out, dep)
		}
	}
	return out
}

type ProjectionKey struct {
	TenantID string
	KeyID    string
}

type Projection map[ProjectionKey]KeyState

func (p Projection) Lookup(tenantID, keyID string) (KeyState, bool) {
	state, ok := p[ProjectionKey{TenantID: tenantID, KeyID: keyID}]
	return state, ok
}

type keyBuilder struct {
	state KeyState

	registered  map[string]struct{}
	accounted   map[string]struct{}
	released    map[string]struct{}
	erased      map[string]struct{}
	leafSources map[string]managedLeafSource
	ceremonies  map[string]*releaseCeremony
}

type releaseCeremony struct {
	purpose   string
	threshold int
	opener    string
	approvals map[string]string
	cancelled bool
}

type managedLeafSource struct {
	eventID           string
	sequence          uint64
	serial            string
	certificateSHA256 string
}

func newKeyBuilder(tenantID, keyID string) *keyBuilder {
	return &keyBuilder{
		state:       KeyState{KeyID: keyID, TenantID: tenantID},
		registered:  make(map[string]struct{}),
		accounted:   make(map[string]struct{}),
		released:    make(map[string]struct{}),
		erased:      make(map[string]struct{}),
		leafSources: make(map[string]managedLeafSource),
		ceremonies:  make(map[string]*releaseCeremony),
	}
}

func (b *keyBuilder) advance(pos uint64) {
	if pos > b.state.LedgerPosition {
		b.state.LedgerPosition = pos
	}
}

func (b *keyBuilder) register(dep Dependent) {
	appendUnique(b.registered, &b.state.Registered, dep)
}

func (b *keyBuilder) account(dep Dependent) {
	appendUnique(b.accounted, &b.state.Accounted, dep)
}

func (b *keyBuilder) release(dep Dependent) {
	if appendUnique(b.released, &b.state.Released, dep) {
		b.account(dep)
	}
}

func (b *keyBuilder) erase(dep Dependent) {
	b.register(dep)
	if appendUnique(b.erased, &b.state.ErasureDesignated, dep) {
		b.account(dep)
	}
}

func appendUnique(set map[string]struct{}, dst *[]Dependent, dep Dependent) bool {
	k := dep.key()
	if _, ok := set[k]; ok {
		return false
	}
	set[k] = struct{}{}
	*dst = append(*dst, dep)
	return true
}

func (b *keyBuilder) snapshot() KeyState {
	out := b.state
	out.Registered = append([]Dependent(nil), b.state.Registered...)
	out.Accounted = append([]Dependent(nil), b.state.Accounted...)
	out.Released = append([]Dependent(nil), b.state.Released...)
	out.ErasureDesignated = append([]Dependent(nil), b.state.ErasureDesignated...)
	return out
}

func Fold(seq []eventspec.Event) (Projection, error) {
	builders := make(map[ProjectionKey]*keyBuilder)
	ceremonyIndex := make(map[string]*keyBuilder)
	// position is the 1-based ordinal of the event within seq, tracked as uint64
	// so the ledger position never needs a width conversion.
	var position uint64
	for i, e := range seq {
		position++
		if err := applyReleaseCeremonyEvent(e, builders, ceremonyIndex); err != nil {
			return nil, fmt.Errorf("depstate: fold ceremony event %d: %w", i, err)
		}
		registrations, err := CARegistrations(e)
		if err != nil {
			return nil, fmt.Errorf("depstate: fold CA event %d (%s): %w", i, e.Type, err)
		}
		for _, registered := range registrations {
			b := builderFor(builders, registered.TenantID, registered.KeyID)
			b.register(registered.Dependent)
			if err := b.rememberManagedLeaf(e, registered.Dependent); err != nil {
				return nil, fmt.Errorf("depstate: fold CA event %d (%s): %w", i, e.Type, err)
			}
			b.advance(ledgerPosition(e, position))
		}
		payload, err := Decode(e)
		if err != nil {
			return nil, fmt.Errorf("depstate: fold event %d (%s): %w", i, e.Type, err)
		}
		c, ok := payloadChange(payload)
		if !ok {
			continue
		}
		b := builderFor(builders, c.tenantID, c.keyID)
		if released, ok := payload.(DependencyReleasedV2); ok {
			if err := b.validateSourceBoundRelease(e, released); err != nil {
				return nil, fmt.Errorf("depstate: fold event %d (%s): %w", i, e.Type, err)
			}
		}
		b.apply(c.op, c.dependent)
		if released, ok := payload.(DependencyReleasedV2); ok {
			delete(b.ceremonies, released.CeremonyID)
			delete(ceremonyIndex, released.CeremonyID)
		}
		b.advance(ledgerPosition(e, position))
	}
	out := make(Projection, len(builders))
	for key, b := range builders {
		out[key] = b.snapshot()
	}
	return out, nil
}

// KeyFolder keeps only one key's dependency sets while consuming a tenant's
// event history. It is the streaming counterpart of Fold for a signer gate:
// unrelated tenant history cannot grow signer memory with tenant age.
type KeyFolder struct {
	tenantID string
	keyID    string
	builder  *keyBuilder
	position uint64
	touched  bool
}

func NewKeyFolder(tenantID, keyID string) *KeyFolder {
	return &KeyFolder{tenantID: tenantID, keyID: keyID, builder: newKeyBuilder(tenantID, keyID)}
}

func (f *KeyFolder) Apply(e eventspec.Event) error {
	f.position++
	if err := applyReleaseCeremonyToKey(e, f.keyID, f.builder); err != nil {
		return err
	}
	registrations, err := CARegistrations(e)
	if err != nil {
		return err
	}
	for _, registration := range registrations {
		if registration.TenantID == f.tenantID && registration.KeyID == f.keyID {
			f.builder.register(registration.Dependent)
			if err := f.builder.rememberManagedLeaf(e, registration.Dependent); err != nil {
				return err
			}
			f.builder.advance(ledgerPosition(e, f.position))
			f.touched = true
		}
	}
	payload, err := Decode(e)
	if err != nil {
		return err
	}
	change, ok := payloadChange(payload)
	if ok && change.tenantID == f.tenantID && change.keyID == f.keyID {
		if released, ok := payload.(DependencyReleasedV2); ok {
			if err := f.builder.validateSourceBoundRelease(e, released); err != nil {
				return err
			}
		}
		f.builder.apply(change.op, change.dependent)
		if released, ok := payload.(DependencyReleasedV2); ok {
			delete(f.builder.ceremonies, released.CeremonyID)
		}
		f.builder.advance(ledgerPosition(e, f.position))
		f.touched = true
	}
	return nil
}

const (
	caCeremonyStarted    = "ca.ceremony.started"
	caCeremonyApproved   = "ca.ceremony.approved"
	caCeremonyCancelled  = "ca.ceremony.cancelled"
	releasePurposePrefix = "release-managed-ca-leaf-v2:"
)

func releasePurposeKey(purpose string) (string, bool) {
	if !strings.HasPrefix(purpose, releasePurposePrefix) {
		return "", false
	}
	var review struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(purpose, releasePurposePrefix)), &review); err != nil || review.KeyID == "" {
		return "", false
	}
	return review.KeyID, true
}

func applyReleaseCeremonyEvent(e eventspec.Event, builders map[ProjectionKey]*keyBuilder, index map[string]*keyBuilder) error {
	switch e.Type {
	case caCeremonyStarted:
		var started struct {
			CeremonyID string `json:"ceremony_id"`
			Purpose    string `json:"purpose"`
			Threshold  int    `json:"threshold"`
			Opener     string `json:"opener"`
		}
		if err := json.Unmarshal(e.Data, &started); err != nil {
			return err
		}
		keyID, relevant := releasePurposeKey(started.Purpose)
		if !relevant {
			return nil
		}
		if started.CeremonyID == "" || started.Threshold < 2 {
			return fmt.Errorf("release ceremony lacks ID or two-custodian floor")
		}
		builder := builderFor(builders, e.TenantID, keyID)
		if _, duplicate := index[started.CeremonyID]; duplicate {
			return fmt.Errorf("duplicate release ceremony identity")
		}
		builder.ceremonies[started.CeremonyID] = &releaseCeremony{purpose: started.Purpose, threshold: started.Threshold, opener: started.Opener, approvals: map[string]string{}}
		index[started.CeremonyID] = builder
	case caCeremonyApproved, caCeremonyCancelled:
		var action struct {
			CeremonyID string `json:"ceremony_id"`
			Custodian  string `json:"custodian"`
		}
		if err := json.Unmarshal(e.Data, &action); err != nil {
			return err
		}
		builder := index[action.CeremonyID]
		if builder == nil || builder.state.TenantID != e.TenantID {
			return nil
		}
		err := builder.applyCeremonyAction(e, action.CeremonyID, action.Custodian)
		if e.Type == caCeremonyCancelled {
			delete(builder.ceremonies, action.CeremonyID)
			delete(index, action.CeremonyID)
		}
		return err
	}
	return nil
}

func applyReleaseCeremonyToKey(e eventspec.Event, keyID string, b *keyBuilder) error {
	switch e.Type {
	case caCeremonyStarted:
		var started struct {
			CeremonyID string `json:"ceremony_id"`
			Purpose    string `json:"purpose"`
			Threshold  int    `json:"threshold"`
			Opener     string `json:"opener"`
		}
		if err := json.Unmarshal(e.Data, &started); err != nil {
			return err
		}
		purposeKey, relevant := releasePurposeKey(started.Purpose)
		if !relevant || purposeKey != keyID || e.TenantID != b.state.TenantID {
			return nil
		}
		if started.CeremonyID == "" || started.Threshold < 2 {
			return fmt.Errorf("release ceremony lacks ID or two-custodian floor")
		}
		if _, duplicate := b.ceremonies[started.CeremonyID]; duplicate {
			return fmt.Errorf("duplicate release ceremony identity")
		}
		b.ceremonies[started.CeremonyID] = &releaseCeremony{purpose: started.Purpose, threshold: started.Threshold, opener: started.Opener, approvals: map[string]string{}}
	case caCeremonyApproved, caCeremonyCancelled:
		var action struct {
			CeremonyID string `json:"ceremony_id"`
			Custodian  string `json:"custodian"`
		}
		if err := json.Unmarshal(e.Data, &action); err != nil {
			return err
		}
		if e.TenantID != b.state.TenantID {
			return nil
		}
		err := b.applyCeremonyAction(e, action.CeremonyID, action.Custodian)
		if e.Type == caCeremonyCancelled {
			delete(b.ceremonies, action.CeremonyID)
		}
		return err
	}
	return nil
}

func (b *keyBuilder) applyCeremonyAction(e eventspec.Event, ceremonyID, custodian string) error {
	ceremony := b.ceremonies[ceremonyID]
	if ceremony == nil {
		return nil
	}
	if e.Type == caCeremonyCancelled {
		ceremony.cancelled = true
		return nil
	}
	if e.ID == "" || custodian == "" || custodian == ceremony.opener || ceremony.cancelled {
		return fmt.Errorf("release ceremony approval lacks distinct immutable evidence")
	}
	if prior, exists := ceremony.approvals[custodian]; exists && prior != e.ID {
		return fmt.Errorf("release ceremony repeats custodian")
	}
	ceremony.approvals[custodian] = e.ID
	return nil
}

func (f *KeyFolder) Snapshot() (KeyState, bool) {
	return f.builder.snapshot(), f.touched
}

type change struct {
	tenantID, keyID string
	dependent       Dependent
	op              byte
}

const (
	opRegister byte = iota
	opRelease
	opErase
	opAccount
)

func payloadChange(p Payload) (change, bool) {
	switch v := p.(type) {
	case DependencyRegisteredV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opRegister}, true
	case DependencyReleasedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opRelease}, true
	case DependencyReleasedV2:
		return change{v.TenantID, v.KeyID, v.Dependent, opRelease}, true
	case DependencyErasureDesignatedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opErase}, true
	case ReprotectionCompletedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opAccount}, true
	case RevocationCompletedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opAccount}, true
	default:
		return change{}, false
	}
}

// rememberManagedLeaf retains only the exact immutable source for managed CA
// leaves. Explicit registrations, PKI secrets, child CAs and serial-only legacy
// events cannot authorize a v2 certificate release.
func (b *keyBuilder) rememberManagedLeaf(e eventspec.Event, dep Dependent) error {
	if e.Type != caevent.EventCAEndEntityIssued ||
		(e.SchemaVersion != caevent.CAIssuedCertificateEvidenceSchemaVersion &&
			e.SchemaVersion != caevent.CAEndEntityInventorySchemaVersion) {
		return nil
	}
	var issued struct {
		Serial         string `json:"serial"`
		Fingerprint    string `json:"fingerprint"`
		CertificateDER []byte `json:"certificate_der"`
	}
	if err := json.Unmarshal(e.Data, &issued); err != nil {
		return err
	}
	if e.ID == "" || e.Sequence == 0 || issued.Serial == "" || len(issued.CertificateDER) == 0 {
		return nil // The incomplete source remains a conservative blocker.
	}
	digest := crypto.SHA256Hex(issued.CertificateDER)
	if !strings.EqualFold(issued.Fingerprint, digest) {
		return nil // No release can use an inconsistent mint receipt.
	}
	source := managedLeafSource{eventID: e.ID, sequence: e.Sequence, serial: issued.Serial, certificateSHA256: digest}
	if prior, found := b.leafSources[dep.key()]; found && prior != source {
		return fmt.Errorf("conflicting managed CA leaf sources for dependent %s", dep.ID)
	}
	b.leafSources[dep.key()] = source
	return nil
}

func (b *keyBuilder) validateSourceBoundRelease(e eventspec.Event, release DependencyReleasedV2) error {
	if e.TenantID == "" || release.TenantID != e.TenantID || release.KeyID != b.state.KeyID ||
		release.Dependent.Class != DependentCredential || release.Dependent.ID == "" ||
		release.SourceEventID == "" || release.SourceSequence == 0 || release.Serial == "" ||
		release.CertificateSHA256 == "" || release.CeremonyID == "" || release.Actor == "" ||
		strings.TrimSpace(release.Reason) == "" || !release.RiskAccepted || len(release.ApprovalEventIDs) < 2 {
		return fmt.Errorf("source-bound certificate release lacks required identity, approvals, reason, or risk acceptance")
	}
	seen := make(map[string]struct{}, len(release.ApprovalEventIDs))
	for _, approval := range release.ApprovalEventIDs {
		if approval == "" {
			return fmt.Errorf("source-bound certificate release has empty approval evidence")
		}
		if _, duplicate := seen[approval]; duplicate {
			return fmt.Errorf("source-bound certificate release repeats approval evidence")
		}
		seen[approval] = struct{}{}
	}
	source, registered := b.leafSources[release.Dependent.key()]
	if !registered || source.eventID != release.SourceEventID || source.sequence != release.SourceSequence ||
		source.serial != release.Serial || source.certificateSHA256 != release.CertificateSHA256 ||
		(e.Sequence != 0 && e.Sequence <= source.sequence) {
		return fmt.Errorf("source-bound certificate release does not match an earlier exact managed CA mint")
	}
	if _, already := b.accounted[release.Dependent.key()]; already {
		return fmt.Errorf("source-bound certificate release repeats an accounted dependent")
	}
	ceremony := b.ceremonies[release.CeremonyID]
	if ceremony == nil || ceremony.cancelled || ceremony.purpose != ReleasePurposeV2(release) ||
		ceremony.threshold < 2 || len(ceremony.approvals) < ceremony.threshold ||
		len(ceremony.approvals) != len(release.ApprovalEventIDs) {
		return fmt.Errorf("source-bound certificate release lacks its exact approved ceremony")
	}
	for _, approvalEventID := range release.ApprovalEventIDs {
		found := false
		for _, approvedID := range ceremony.approvals {
			if approvedID == approvalEventID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("source-bound certificate release approval event differs from ceremony")
		}
	}
	return nil
}

func (b *keyBuilder) apply(op byte, dep Dependent) {
	switch op {
	case opRegister:
		b.register(dep)
	case opRelease:
		b.release(dep)
	case opErase:
		b.erase(dep)
	case opAccount:
		b.account(dep)
	}
}

func builderFor(builders map[ProjectionKey]*keyBuilder, tenantID, keyID string) *keyBuilder {
	key := ProjectionKey{TenantID: tenantID, KeyID: keyID}
	if b, ok := builders[key]; ok {
		return b
	}
	b := newKeyBuilder(tenantID, keyID)
	builders[key] = b
	return b
}

// ledgerPosition reports the ledger position of e, falling back to its 1-based
// ordinal within the folded sequence when the event carries no sequence number.
func ledgerPosition(e eventspec.Event, position uint64) uint64 {
	if e.Sequence != 0 {
		return e.Sequence
	}
	return position
}
