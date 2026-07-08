// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"encoding/base64"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/decommission/depstate"
)

// JobKind names the re-protection action class. The values are descriptive job
// labels only; no key or plaintext material is carried in the job model.
type JobKind string

const (
	JobKindReEncrypt   JobKind = "re-encrypt"
	JobKindReWrap      JobKind = "re-wrap"
	JobKindReIssue     JobKind = "re-issue"
	JobKindRevokeLease JobKind = "revoke-lease"
	JobKindReDerive    JobKind = "re-derive"
)

var (
	ErrInvalidState             = errors.New("vdec reprotect: invalid dependency state")
	ErrUnsupportedDependentType = errors.New("vdec reprotect: unsupported dependent type")
)

// Job is one deterministic unit of work generated from dependency state. It
// contains only tenant, key, dependent, and idempotency identifiers; key bytes and
// plaintext are intentionally absent.
type Job struct {
	ID             string             `json:"id"`
	TenantID       string             `json:"tenant_id"`
	KeyID          string             `json:"key_id"`
	LedgerPosition uint64             `json:"ledger_position"`
	Kind           JobKind            `json:"kind"`
	Dependent      depstate.Dependent `json:"dependent"`
	IdempotencyKey string             `json:"idempotency_key"`
}

// PlanFromState emits exactly one job for each registered dependent that still
// requires re-protection according to the dependency-state projection. Released,
// erasure-designated, and already-completed dependents are accounted for by the
// projection and do not produce jobs.
func PlanFromState(state depstate.KeyState) ([]Job, error) {
	if state.TenantID == "" || state.KeyID == "" {
		return nil, fmt.Errorf("%w: tenant_id and key_id are required", ErrInvalidState)
	}
	accounted := dependentSet(state.Accounted, state.Released, state.ErasureDesignated)
	seen := make(map[string]struct{}, len(state.Registered))
	jobs := make([]Job, 0, len(state.Registered))
	for _, dep := range state.Registered {
		if dep.Class == "" || dep.ID == "" {
			return nil, fmt.Errorf("%w: dependent class and id are required", ErrInvalidState)
		}
		depKey := dependentKey(dep)
		if _, ok := seen[depKey]; ok {
			continue
		}
		seen[depKey] = struct{}{}
		if _, ok := accounted[depKey]; ok {
			continue
		}
		kind, ok := kindForDependent(dep.Class)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedDependentType, dep.Class)
		}
		id := stableJobID(state, dep, kind)
		jobs = append(jobs, Job{
			ID:             id,
			TenantID:       state.TenantID,
			KeyID:          state.KeyID,
			LedgerPosition: state.LedgerPosition,
			Kind:           kind,
			Dependent:      dep,
			IdempotencyKey: stableIdempotencyKey(state, dep, kind),
		})
	}
	return jobs, nil
}

func kindForDependent(class depstate.DependentClass) (JobKind, bool) {
	switch class {
	case depstate.DependentCiphertext:
		return JobKindReEncrypt, true
	case depstate.DependentWrappedKey:
		return JobKindReWrap, true
	case depstate.DependentCredential:
		return JobKindReIssue, true
	case depstate.DependentLeasedSecret:
		return JobKindRevokeLease, true
	case depstate.DependentDataSet:
		return JobKindReDerive, true
	default:
		return "", false
	}
}

func validateJob(job Job) error {
	if job.ID == "" || job.TenantID == "" || job.KeyID == "" || job.IdempotencyKey == "" {
		return fmt.Errorf("%w: job id, tenant_id, key_id, and idempotency_key are required", ErrInvalidState)
	}
	if job.Dependent.Class == "" || job.Dependent.ID == "" {
		return fmt.Errorf("%w: dependent class and id are required", ErrInvalidState)
	}
	kind, ok := kindForDependent(job.Dependent.Class)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedDependentType, job.Dependent.Class)
	}
	if job.Kind != kind {
		return fmt.Errorf("%w: job kind %s does not match dependent class %s", ErrInvalidState, job.Kind, job.Dependent.Class)
	}
	return nil
}

func dependentSet(groups ...[]depstate.Dependent) map[string]struct{} {
	out := make(map[string]struct{})
	for _, group := range groups {
		for _, dep := range group {
			out[dependentKey(dep)] = struct{}{}
		}
	}
	return out
}

func dependentKey(dep depstate.Dependent) string {
	return string(dep.Class) + "\x00" + dep.ID
}

func stableJobID(state depstate.KeyState, dep depstate.Dependent, kind JobKind) string {
	return fmt.Sprintf("vdec-reprotect/%s/%s/%s/%s", encodePart(state.TenantID), encodePart(state.KeyID), kind, encodePart(dependentKey(dep)))
}

func stableIdempotencyKey(state depstate.KeyState, dep depstate.Dependent, kind JobKind) string {
	return fmt.Sprintf("vdec-reprotect-idem/%s/%s/%s/%s", encodePart(state.TenantID), encodePart(state.KeyID), kind, encodePart(dependentKey(dep)))
}

func encodePart(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
