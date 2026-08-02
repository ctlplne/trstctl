// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/orchestrator"
)

const RevocationStateFailClosed = "fail-closed"

var (
	ErrFailClosedProtectiveUse       = errors.New("vdec reprotect: key is fail-closed for protective use")
	ErrFailClosedGuardUnavailable    = errors.New("vdec reprotect: fail-closed signer guard is unavailable")
	ErrReprotectJobIdentityRequired  = errors.New("vdec reprotect: re-protection job identity is required")
	ErrRevocationDestinationRequired = errors.New("vdec reprotect: revocation destination is required")
	ErrRevocationCompletionMissing   = errors.New("vdec reprotect: revocation completion is missing")
	ErrNilRevocationCompletionSink   = errors.New("vdec reprotect: nil revocation completion sink")
)

type KeyUse string

const (
	KeyUseEncrypt KeyUse = "encrypt"
	KeyUseSign    KeyUse = "sign"
	KeyUseWrap    KeyUse = "wrap"
	KeyUseDecrypt KeyUse = "decrypt"
)

// KeyUseRequest is the signer-side decision input for one key operation. It
// carries identity only; no plaintext, ciphertext, or key bytes cross this gate.
type KeyUseRequest struct {
	TenantID       string
	KeyID          string
	Use            KeyUse
	ReprotectJobID string
}

// FailClosedKeyGuard is the EE signer adapter's in-memory policy core for the
// fail-closed state. Production callers persist the state through RevokeFirst and
// hydrate this guard inside the isolated signer process.
type FailClosedKeyGuard struct {
	mu         sync.RWMutex
	failClosed map[string]FailClosedStateChange
}

func NewFailClosedKeyGuard() *FailClosedKeyGuard {
	return &FailClosedKeyGuard{failClosed: make(map[string]FailClosedStateChange)}
}

func (g *FailClosedKeyGuard) MarkFailClosed(change FailClosedStateChange) error {
	if g == nil {
		return ErrFailClosedGuardUnavailable
	}
	normalized, err := normalizeFailClosedChange(change)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failClosed[keyStateID(normalized.TenantID, normalized.KeyID)] = normalized
	return nil
}

func (g *FailClosedKeyGuard) Authorize(req KeyUseRequest) error {
	normalized, err := normalizeKeyUseRequest(req)
	if err != nil {
		return err
	}
	if g == nil {
		return ErrFailClosedGuardUnavailable
	}
	g.mu.RLock()
	_, closed := g.failClosed[keyStateID(normalized.TenantID, normalized.KeyID)]
	g.mu.RUnlock()
	if !closed {
		return nil
	}
	if normalized.Use == KeyUseDecrypt {
		if normalized.ReprotectJobID == "" {
			return ErrReprotectJobIdentityRequired
		}
		return nil
	}
	return ErrFailClosedProtectiveUse
}

type FailClosedStateChange struct {
	TenantID string
	KeyID    string
	JobID    string
	Reason   string
	State    string
}

type RevocationDestination struct {
	ID                string `json:"id"`
	OutboxDestination string `json:"outbox_destination,omitempty"`
	Kind              string `json:"kind,omitempty"`
}

type RevokeFirstRequest struct {
	TenantID     string
	KeyID        string
	JobID        string
	Reason       string
	Dependent    depstate.Dependent
	Destinations []RevocationDestination
}

type RevokeFirstResult struct {
	StateChange FailClosedStateChange
	Intents     []orchestrator.Entry
}

// RevocationTransaction is the minimal AN-6 surface VDEC-04 needs: the caller's
// implementation must commit the fail-closed state change and every outbox intent
// together, or persist none of them.
type RevocationTransaction interface {
	MarkKeyFailClosed(context.Context, FailClosedStateChange) error
	EnqueueRevocationIntent(context.Context, orchestrator.Entry) error
}

type RevocationTransactor interface {
	WithinRevocationTx(context.Context, string, func(context.Context, RevocationTransaction) error) error
}

// RevokeFirstCoordinator practices VDEC-claim-3: it moves the key to fail-closed
// before destruction (new protective use refused, re-protection decryption still
// permitted) and records every per-destination revocation intent in the same
// database transaction as the fail-closed state change.
type RevokeFirstCoordinator struct {
	tx RevocationTransactor
}

func NewRevokeFirstCoordinator(tx RevocationTransactor) (*RevokeFirstCoordinator, error) {
	if tx == nil {
		return nil, errors.New("reprotect: revocation transactor is required")
	}
	return &RevokeFirstCoordinator{tx: tx}, nil
}

func (c *RevokeFirstCoordinator) RevokeFirst(ctx context.Context, req RevokeFirstRequest) (RevokeFirstResult, error) {
	if c == nil || c.tx == nil {
		return RevokeFirstResult{}, errors.New("reprotect: revoke-first coordinator is not configured")
	}
	normalized, err := normalizeRevokeFirstRequest(req)
	if err != nil {
		return RevokeFirstResult{}, err
	}
	state := FailClosedStateChange{
		TenantID: normalized.TenantID,
		KeyID:    normalized.KeyID,
		JobID:    normalized.JobID,
		Reason:   normalized.Reason,
		State:    RevocationStateFailClosed,
	}
	intents, err := revocationIntents(normalized)
	if err != nil {
		return RevokeFirstResult{}, err
	}
	err = c.tx.WithinRevocationTx(ctx, normalized.TenantID, func(ctx context.Context, tx RevocationTransaction) error {
		if err := tx.MarkKeyFailClosed(ctx, state); err != nil {
			return err
		}
		for _, intent := range intents {
			if err := tx.EnqueueRevocationIntent(ctx, intent); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return RevokeFirstResult{}, err
	}
	return RevokeFirstResult{StateChange: state, Intents: append([]orchestrator.Entry(nil), intents...)}, nil
}

type RevocationCompletionEventSink interface {
	AppendRevocationCompleted(context.Context, depstate.RevocationCompletedV1) error
}

type RevocationCompletionResult struct {
	Recorded bool
	Event    depstate.RevocationCompletedV1
}

type RevocationCompletionRecorder struct {
	mu   sync.Mutex
	sink RevocationCompletionEventSink
	seen map[string]struct{}
}

func NewRevocationCompletionRecorder(sink RevocationCompletionEventSink) *RevocationCompletionRecorder {
	return &RevocationCompletionRecorder{sink: sink, seen: make(map[string]struct{})}
}

func (r *RevocationCompletionRecorder) RecordDestinationCompletion(ctx context.Context, req RevokeFirstRequest, dst RevocationDestination) (RevocationCompletionResult, error) {
	if r == nil || r.sink == nil {
		return RevocationCompletionResult{}, ErrNilRevocationCompletionSink
	}
	normalized, err := normalizeRevokeFirstRequest(req)
	if err != nil {
		return RevocationCompletionResult{}, err
	}
	dst, err = normalizeDestination(dst)
	if err != nil {
		return RevocationCompletionResult{}, err
	}
	if !destinationRequired(normalized.Destinations, dst.ID) {
		return RevocationCompletionResult{}, fmt.Errorf("%w: %s", ErrRevocationDestinationRequired, dst.ID)
	}
	event := depstate.RevocationCompletedV1{
		TenantID:    normalized.TenantID,
		KeyID:       normalized.KeyID,
		JobID:       normalized.JobID,
		Dependent:   normalized.Dependent,
		Destination: dst.ID,
	}
	key := revocationCompletionKey(event)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[key]; ok {
		return RevocationCompletionResult{Recorded: false, Event: event}, nil
	}
	if err := r.sink.AppendRevocationCompleted(ctx, event); err != nil {
		return RevocationCompletionResult{}, err
	}
	r.seen[key] = struct{}{}
	return RevocationCompletionResult{Recorded: true, Event: event}, nil
}

type RevocationCompletionStatus struct {
	Satisfied    bool
	Required     []string
	Completed    []string
	Missing      []string
	MissingError error
}

func EvaluateRevocationCompletionRequirement(req RevokeFirstRequest, events []depstate.RevocationCompletedV1) (RevocationCompletionStatus, error) {
	normalized, err := normalizeRevokeFirstRequest(req)
	if err != nil {
		return RevocationCompletionStatus{}, err
	}
	required := make([]string, 0, len(normalized.Destinations))
	for _, dst := range normalized.Destinations {
		norm, err := normalizeDestination(dst)
		if err != nil {
			return RevocationCompletionStatus{}, err
		}
		required = append(required, norm.ID)
	}
	seen := make(map[string]struct{}, len(events))
	completed := make([]string, 0, len(required))
	for _, ev := range events {
		if ev.TenantID != normalized.TenantID || ev.KeyID != normalized.KeyID || ev.JobID != normalized.JobID || ev.Dependent != normalized.Dependent {
			continue
		}
		dst := strings.TrimSpace(ev.Destination)
		if !destinationRequired(normalized.Destinations, dst) {
			continue
		}
		if _, ok := seen[dst]; ok {
			continue
		}
		seen[dst] = struct{}{}
		completed = append(completed, dst)
	}
	missing := make([]string, 0)
	for _, dst := range required {
		if _, ok := seen[dst]; !ok {
			missing = append(missing, dst)
		}
	}
	status := RevocationCompletionStatus{
		Satisfied: len(missing) == 0,
		Required:  append([]string(nil), required...),
		Completed: completed,
		Missing:   missing,
	}
	if !status.Satisfied {
		status.MissingError = fmt.Errorf("%w: %s", ErrRevocationCompletionMissing, strings.Join(missing, ","))
	}
	return status, nil
}

func RequireRevocationCompletions(req RevokeFirstRequest, events []depstate.RevocationCompletedV1) error {
	status, err := EvaluateRevocationCompletionRequirement(req, events)
	if err != nil {
		return err
	}
	if !status.Satisfied {
		return status.MissingError
	}
	return nil
}

type revocationIntentPayload struct {
	TenantID    string                `json:"tenant_id"`
	KeyID       string                `json:"key_id"`
	JobID       string                `json:"job_id"`
	Reason      string                `json:"reason,omitempty"`
	Dependent   depstate.Dependent    `json:"dependent"`
	Destination RevocationDestination `json:"destination"`
	State       string                `json:"state"`
}

func revocationIntents(req RevokeFirstRequest) ([]orchestrator.Entry, error) {
	intents := make([]orchestrator.Entry, 0, len(req.Destinations))
	for _, dst := range req.Destinations {
		norm, err := normalizeDestination(dst)
		if err != nil {
			return nil, err
		}
		payload, err := json.Marshal(revocationIntentPayload{
			TenantID:    req.TenantID,
			KeyID:       req.KeyID,
			JobID:       req.JobID,
			Reason:      strings.TrimSpace(req.Reason),
			Dependent:   req.Dependent,
			Destination: norm,
			State:       RevocationStateFailClosed,
		})
		if err != nil {
			return nil, fmt.Errorf("reprotect: encode revocation intent: %w", err)
		}
		intents = append(intents, orchestrator.Entry{
			TenantID:       req.TenantID,
			Destination:    norm.workerDestination(),
			IdempotencyKey: stableRevocationIntentKey(req, norm),
			Payload:        payload,
		})
	}
	return intents, nil
}

func validateKeyUseRequest(req KeyUseRequest) error {
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.KeyID) == "" {
		return fmt.Errorf("%w: tenant_id and key_id are required", ErrInvalidState)
	}
	switch req.Use {
	case KeyUseEncrypt, KeyUseSign, KeyUseWrap, KeyUseDecrypt:
		return nil
	default:
		return fmt.Errorf("%w: unsupported key use %q", ErrInvalidState, req.Use)
	}
}

func normalizeKeyUseRequest(req KeyUseRequest) (KeyUseRequest, error) {
	if err := validateKeyUseRequest(req); err != nil {
		return KeyUseRequest{}, err
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.ReprotectJobID = strings.TrimSpace(req.ReprotectJobID)
	return req, nil
}

func validateFailClosedChange(change FailClosedStateChange) error {
	if strings.TrimSpace(change.TenantID) == "" || strings.TrimSpace(change.KeyID) == "" || strings.TrimSpace(change.JobID) == "" {
		return fmt.Errorf("%w: tenant_id, key_id, and job_id are required", ErrInvalidState)
	}
	state := strings.TrimSpace(change.State)
	if state != "" && state != RevocationStateFailClosed {
		return fmt.Errorf("%w: state must be %s", ErrInvalidState, RevocationStateFailClosed)
	}
	return nil
}

func normalizeFailClosedChange(change FailClosedStateChange) (FailClosedStateChange, error) {
	if err := validateFailClosedChange(change); err != nil {
		return FailClosedStateChange{}, err
	}
	change.TenantID = strings.TrimSpace(change.TenantID)
	change.KeyID = strings.TrimSpace(change.KeyID)
	change.JobID = strings.TrimSpace(change.JobID)
	change.Reason = strings.TrimSpace(change.Reason)
	change.State = RevocationStateFailClosed
	return change, nil
}

func validateRevokeFirstRequest(req RevokeFirstRequest) error {
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.KeyID) == "" || strings.TrimSpace(req.JobID) == "" {
		return fmt.Errorf("%w: tenant_id, key_id, and job_id are required", ErrInvalidState)
	}
	if req.Dependent.Class == "" || strings.TrimSpace(req.Dependent.ID) == "" {
		return fmt.Errorf("%w: dependent class and id are required", ErrInvalidState)
	}
	if len(req.Destinations) == 0 {
		return ErrRevocationDestinationRequired
	}
	seen := make(map[string]struct{}, len(req.Destinations))
	for _, dst := range req.Destinations {
		norm, err := normalizeDestination(dst)
		if err != nil {
			return err
		}
		if _, ok := seen[norm.ID]; ok {
			return fmt.Errorf("%w: duplicate %s", ErrRevocationDestinationRequired, norm.ID)
		}
		seen[norm.ID] = struct{}{}
	}
	return nil
}

func normalizeRevokeFirstRequest(req RevokeFirstRequest) (RevokeFirstRequest, error) {
	if err := validateRevokeFirstRequest(req); err != nil {
		return RevokeFirstRequest{}, err
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.JobID = strings.TrimSpace(req.JobID)
	req.Reason = strings.TrimSpace(req.Reason)
	req.Dependent.ID = strings.TrimSpace(req.Dependent.ID)
	req.Destinations = append([]RevocationDestination(nil), req.Destinations...)
	for i, dst := range req.Destinations {
		norm, err := normalizeDestination(dst)
		if err != nil {
			return RevokeFirstRequest{}, err
		}
		req.Destinations[i] = norm
	}
	return req, nil
}

func normalizeDestination(dst RevocationDestination) (RevocationDestination, error) {
	dst.ID = strings.TrimSpace(dst.ID)
	dst.OutboxDestination = strings.TrimSpace(dst.OutboxDestination)
	dst.Kind = strings.TrimSpace(dst.Kind)
	if dst.ID == "" {
		return RevocationDestination{}, ErrRevocationDestinationRequired
	}
	return dst, nil
}

func (d RevocationDestination) workerDestination() string {
	if d.OutboxDestination != "" {
		return d.OutboxDestination
	}
	return d.ID
}

func destinationRequired(destinations []RevocationDestination, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, dst := range destinations {
		norm, err := normalizeDestination(dst)
		if err != nil {
			continue
		}
		if norm.ID == id {
			return true
		}
	}
	return false
}

func stableRevocationIntentKey(req RevokeFirstRequest, dst RevocationDestination) string {
	return fmt.Sprintf("vdec-revoke-first-idem/%s/%s/%s/%s", encodePart(req.TenantID), encodePart(req.KeyID), encodePart(req.JobID), encodePart(dst.ID))
}

func revocationCompletionKey(event depstate.RevocationCompletedV1) string {
	return event.TenantID + "\x00" + event.KeyID + "\x00" + event.JobID + "\x00" + dependentKey(event.Dependent) + "\x00" + event.Destination
}

func keyStateID(tenantID, keyID string) string {
	return tenantID + "\x00" + keyID
}
