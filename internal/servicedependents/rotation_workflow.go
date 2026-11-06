// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"slices"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

const RotationDestination = "host.windows_dependents.rotation"
const Forward = "forward"
const Inverse = "inverse"
const Preflight = "preflight"
const Stop = "stop"
const Update = "update"
const Start = "start"
const Probe = "probe"

type ProbeBinding struct {
	Ref     DependentRef `json:"ref"`
	ProbeID string       `json:"probe_id"`
}

// RotationIntent adds publication and local functional authority to the frozen
// inventory plan. Probe IDs select operator-owned host configuration, never URLs
// or commands supplied by a remote requester.
type RotationIntent struct {
	Plan            RotationPlan   `json:"plan"`
	ExpectedVersion int            `json:"expected_version"`
	ProviderBinding string         `json:"provider_binding"`
	Probes          []ProbeBinding `json:"probes"`
}

func validProbeID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}
func (intent RotationIntent) Digest() (string, error) {
	if e := intent.Plan.Validate(); e != nil {
		return "", e
	}
	raw, e := json.Marshal(intent)
	if e != nil {
		return "", e
	}
	if len(raw) > MaxRotationPlanBytes {
		return "", errors.New("service dependents: rotation intent exceeds bounded request size")
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-account.rotation-intent.v1\x00"), raw...)), nil
}
func (intent RotationIntent) Validate(inputs []RotationHostInput) error {
	if intent.ExpectedVersion < 1 || !rotationDigestValid(intent.ProviderBinding) {
		return errors.New("service dependents: exact provider and vault predecessor required")
	}
	recreated, e := NewRotationPlan(intent.Plan.ID, intent.Plan.Account, intent.Plan.SecretName, inputs, intent.Plan.Order, intent.Plan.CreatedAt)
	if e != nil {
		return e
	}
	if recreated.Digest != intent.Plan.Digest {
		return errors.New("service dependents: frozen inventory differs from reviewed plan")
	}
	expected := map[string]bool{}
	for _, ref := range intent.Plan.Order {
		expected[dependentKey(ref)] = true
	}
	for _, probe := range intent.Probes {
		if !expected[dependentKey(probe.Ref)] || !validProbeID(probe.ProbeID) {
			return errors.New("service dependents: invalid or substituted local functional authority")
		}
		delete(expected, dependentKey(probe.Ref))
	}
	if len(expected) > 0 {
		return errors.New("service dependents: useful-work binding required for every dependent")
	}
	// SCM names are case insensitive. A selected dependency must start first and
	// stop last; SCM itself refuses an unselected running dependent during Stop.
	positions := map[string]int{}
	for i, ref := range intent.Plan.Order {
		if ref.Family == "services" {
			positions[ref.AgentID+"\x00"+strings.ToLower(ref.Name)] = i
		}
	}
	for _, input := range inputs {
		for _, svc := range input.Inventory.Services {
			own := positions[input.Binding.AgentID+"\x00"+strings.ToLower(svc.Name)]
			for _, dep := range svc.Dependencies {
				if p, ok := positions[input.Binding.AgentID+"\x00"+strings.ToLower(dep)]; ok && p >= own {
					return errors.New("service dependents: reviewed service order violates native dependency graph")
				}
			}
		}
	}
	_, e = intent.Digest()
	return e
}

// RotationStep is exact native authority for one bounded host effect. There is
// one typed snapshot, a parent intent digest, a direction and a fixed operation.
type RotationStep struct {
	RotationID   string                 `json:"rotation_id"`
	PlanDigest   string                 `json:"plan_digest"`
	ID           string                 `json:"step_id"`
	Direction    string                 `json:"direction"`
	Action       string                 `json:"action"`
	Ref          DependentRef           `json:"ref"`
	AccountSID   string                 `json:"account_sid"`
	ProbeID      string                 `json:"probe_id"`
	Service      *windependents.Service `json:"service,omitempty"`
	Task         *windependents.Task    `json:"task,omitempty"`
	Pool         *windependents.Pool    `json:"pool,omitempty"`
	PreviousPIDs []uint32               `json:"previous_pids,omitempty"`
	Challenge    string                 `json:"challenge,omitempty"`
	NotBefore    time.Time              `json:"not_before"`
	Deadline     time.Time              `json:"deadline"`
}

func (step RotationStep) Active() bool {
	return step.Service != nil && step.Service.WasRunning || step.Pool != nil && step.Pool.WasStarted || step.Task != nil && step.Task.Enabled
}
func (step RotationStep) Validate() error {
	if !canonicalID(step.RotationID) || !rotationDigestValid(step.PlanDigest) || !canonicalID(step.Ref.AgentID) || !windependents.ValidAccountSID(step.AccountSID) || (step.Direction != Forward && step.Direction != Inverse) || !validProbeID(step.ProbeID) {
		return errors.New("service dependents: incomplete native step authority")
	}
	switch step.Action {
	case Preflight, Stop, Update, Start, Probe:
	default:
		return errors.New("service dependents: unsupported native effect")
	}
	count := 0
	if step.Service != nil {
		count++
		if step.Ref.Family != "services" || step.Ref.Name != step.Service.Name || step.AccountSID != step.Service.AccountSID || windependents.ValidateServiceSnapshot(*step.Service) != nil {
			return errors.New("service dependents: service snapshot differs")
		}
	}
	if step.Task != nil {
		count++
		if step.Ref.Family != "tasks" || step.Ref.Name != step.Task.Path || step.AccountSID != step.Task.AccountSID || windependents.ValidateTaskSnapshot(*step.Task) != nil || step.Action == Stop || step.Action == Start || step.Action == Update && step.Task.LogonType != 1 {
			return errors.New("service dependents: task snapshot or password mode differs")
		}
	}
	if step.Pool != nil {
		count++
		if step.Ref.Family != "iis" || step.Ref.Name != step.Pool.Name || step.AccountSID != step.Pool.AccountSID || windependents.ValidatePoolSnapshot(*step.Pool) != nil {
			return errors.New("service dependents: pool snapshot differs")
		}
	}
	if count != 1 {
		return errors.New("service dependents: one exact native object required")
	}
	expected := crypto.SHA256Hex([]byte(step.RotationID + "\x00" + step.PlanDigest + "\x00" + step.Direction + "\x00" + step.Action + "\x00" + dependentKey(step.Ref)))[:32]
	if step.ID != expected {
		return errors.New("service dependents: native step identity differs")
	}
	if len(step.PreviousPIDs) > 128 {
		return errors.New("service dependents: predecessor process count exceeds bound")
	}
	seen := map[uint32]bool{}
	for _, pid := range step.PreviousPIDs {
		if pid == 0 || seen[pid] {
			return errors.New("service dependents: invalid predecessor process identity")
		}
		seen[pid] = true
	}
	if step.Challenge != "" || !step.NotBefore.IsZero() || !step.Deadline.IsZero() {
		if !canonicalID(step.Challenge) || step.NotBefore.IsZero() || !step.Deadline.After(step.NotBefore) || step.Deadline.After(step.NotBefore.Add(3*time.Minute)) {
			return errors.New("service dependents: bounded fresh step lease required")
		}
	}
	return nil
}
func (intent RotationIntent) Steps(inputs []RotationHostInput, direction string) ([]RotationStep, error) {
	if direction != Forward && direction != Inverse {
		return nil, errors.New("service dependents: invalid rotation direction")
	}
	if e := intent.Validate(inputs); e != nil {
		return nil, e
	}
	digest, e := intent.Digest()
	if e != nil {
		return nil, e
	}
	snapshots := map[string]RotationStep{}
	probes := map[string]string{}
	for _, p := range intent.Probes {
		probes[dependentKey(p.Ref)] = p.ProbeID
	}
	for _, input := range inputs {
		put := func(ref DependentRef, svc *windependents.Service, task *windependents.Task, pool *windependents.Pool) {
			snapshots[dependentKey(ref)] = RotationStep{RotationID: intent.Plan.ID, PlanDigest: digest, Direction: direction, Ref: ref, AccountSID: intent.Plan.Account.SID, ProbeID: probes[dependentKey(ref)], Service: svc, Task: task, Pool: pool}
		}
		for _, svc := range input.Inventory.Services {
			v := svc
			put(DependentRef{input.Binding.AgentID, "services", v.Name}, &v, nil, nil)
		}
		for _, task := range input.Inventory.Tasks {
			v := task
			put(DependentRef{input.Binding.AgentID, "tasks", v.Path}, nil, &v, nil)
		}
		for _, pool := range input.Inventory.Pools {
			v := pool
			put(DependentRef{input.Binding.AgentID, "iis", v.Name}, nil, nil, &v)
		}
	}
	var result []RotationStep
	add := func(action string, ref DependentRef) {
		step := snapshots[dependentKey(ref)]
		step.Action = action
		step.ID = crypto.SHA256Hex([]byte(step.RotationID + "\x00" + step.PlanDigest + "\x00" + step.Direction + "\x00" + step.Action + "\x00" + dependentKey(step.Ref)))[:32]
		result = append(result, step)
	}
	if direction == Forward {
		for _, ref := range intent.Plan.Order {
			add(Preflight, ref)
		}
	}
	for i := len(intent.Plan.Order) - 1; i >= 0; i-- {
		ref := intent.Plan.Order[i]
		s := snapshots[dependentKey(ref)]
		if s.Task == nil && s.Active() {
			add(Stop, ref)
		}
	}
	for _, ref := range intent.Plan.Order {
		s := snapshots[dependentKey(ref)]
		if s.Task == nil || s.Task.LogonType == 1 {
			add(Update, ref)
		}
	}
	for _, ref := range intent.Plan.Order {
		s := snapshots[dependentKey(ref)]
		if s.Task == nil && s.Active() {
			add(Start, ref)
		}
	}
	for _, ref := range intent.Plan.Order {
		add(Probe, ref)
	}
	for _, step := range result {
		if e := step.Validate(); e != nil {
			return nil, e
		}
	}
	return result, nil
}

type FunctionalProof struct {
	ProbeID        string `json:"probe_id"`
	Challenge      string `json:"challenge"`
	ProcessID      uint32 `json:"process_id,omitempty"`
	AccountSID     string `json:"account_sid"`
	TaskInstanceID string `json:"task_instance_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
type StepReport struct {
	RotationID string                          `json:"rotation_id"`
	PlanDigest string                          `json:"plan_digest"`
	StepID     string                          `json:"step_id"`
	Direction  string                          `json:"direction"`
	Status     string                          `json:"status"`
	Failure    string                          `json:"failure,omitempty"`
	ObservedAt time.Time                       `json:"observed_at"`
	Runtime    *windependents.Runtime          `json:"runtime,omitempty"`
	TaskProof  *windependents.TaskRunProof     `json:"task_proof,omitempty"`
	PoolProof  *windependents.PoolRestartProof `json:"pool_proof,omitempty"`
	Functional *FunctionalProof                `json:"functional,omitempty"`
}

func (report StepReport) Validate(step RotationStep) error {
	if e := step.Validate(); e != nil {
		return e
	}
	if step.Challenge == "" || report.RotationID != step.RotationID || report.PlanDigest != step.PlanDigest || report.StepID != step.ID || report.Direction != step.Direction || report.ObservedAt.Before(step.NotBefore) {
		return errors.New("service dependents: native receipt differs from its exact step")
	}
	if report.Status == "failed" || report.Status == "uncertain" {
		if report.Runtime != nil || report.TaskProof != nil || report.PoolProof != nil || report.Functional != nil {
			return errors.New("service dependents: failure report carries unvalidated native evidence")
		}

		if report.ObservedAt.After(step.Deadline.Add(5 * time.Minute)) {
			return errors.New("service dependents: native failure observation is too late")
		}
		switch report.Failure {
		case "native_authority_changed", "local_grant_absent", "native_operation_failed", "functional_probe_failed", "task_start_uncertain", "deadline_exceeded":
			return nil
		}
		return errors.New("service dependents: unsupported closed failure marker")
	}
	if report.ObservedAt.After(step.Deadline) {
		return errors.New("service dependents: native success exceeds the execution lease")
	}
	if report.Status != "succeeded" || report.Failure != "" {
		return errors.New("service dependents: native result must state a closed outcome")
	}
	if step.Action != Probe && (report.Functional != nil || report.TaskProof != nil) {
		return errors.New("service dependents: unexpected useful-work evidence outside its native probe")
	}
	if report.PoolProof != nil && step.Pool == nil || report.TaskProof != nil && step.Task == nil || report.Runtime != nil && step.Task != nil && step.Active() {
		return errors.New("service dependents: native evidence names another family")
	}
	if step.Action == Update && (report.Runtime != nil || report.PoolProof != nil) {
		return errors.New("service dependents: password update cannot claim process or restart evidence")
	}
	if step.Action == Preflight && step.Service != nil {
		if report.Runtime == nil || report.Runtime.Running != step.Service.WasRunning || step.Active() && (report.Runtime.ProcessID == 0 || report.Runtime.AccountSID != step.AccountSID) || !step.Active() && report.Runtime.ProcessID != 0 {
			return errors.New("service dependents: service preflight lacks exact native state")
		}
	}
	if step.Action == Preflight && step.Pool != nil {
		if report.Runtime == nil || report.Runtime.Running != step.Pool.WasStarted || report.Runtime.ProcessID != 0 {
			return errors.New("service dependents: pool preflight lacks exact native state")
		}
	}
	if step.Pool != nil && step.Active() && (step.Action == Start || step.Action == Probe) && report.PoolProof == nil {
		return errors.New("service dependents: native pool restart evidence required")
	}
	if report.PoolProof != nil {
		var e error
		if step.Action == Stop {
			e = windependents.ValidateStoppedPoolProof(*step.Pool, *report.PoolProof)
		} else {
			e = windependents.ValidatePoolRestartProof(*step.Pool, *report.PoolProof)
		}
		if e != nil {
			return e
		}
		if step.Action != Stop && !slices.Equal(step.PreviousPIDs, report.PoolProof.PreviousPIDs) {
			return errors.New("service dependents: pool evidence replaced the stopped predecessor set")
		}
	}
	if step.Action == Stop && step.Service != nil && (report.Runtime == nil || report.Runtime.Running || report.Runtime.ProcessID != 0) {
		return errors.New("service dependents: native service stop is unproven")
	}
	if step.Action == Stop && step.Pool != nil && (report.PoolProof == nil || !report.PoolProof.StoppedObserved || report.PoolProof.StartedObserved) {
		return errors.New("service dependents: native pool stop is unproven")
	}
	if step.Action == Start || step.Action == Probe {
		if step.Service != nil && step.Active() && (report.Runtime == nil || !report.Runtime.Running || report.Runtime.ProcessID == 0 || report.Runtime.AccountSID != step.AccountSID || slices.Contains(step.PreviousPIDs, report.Runtime.ProcessID)) {
			return errors.New("service dependents: fresh native service identity is unproven")
		}
		if step.Pool != nil && step.Active() && step.Action == Start && (report.PoolProof == nil || !report.PoolProof.StartedObserved) {
			return errors.New("service dependents: native pool start is unproven")
		}
	}
	if step.Action == Probe {
		if !step.Active() {
			if report.Functional != nil || report.Runtime == nil || report.Runtime.Running || report.Runtime.ProcessID != 0 {
				return errors.New("service dependents: originally inactive state is unproven")
			}
			return nil
		}
		f := report.Functional
		if f == nil || f.ProbeID != step.ProbeID || f.Challenge != step.Challenge || f.AccountSID != step.AccountSID || !rotationDigestValid(f.EvidenceSHA256) {
			return errors.New("service dependents: fresh useful-work evidence required")
		}
		if step.Task != nil {
			if f.ProcessID != 0 {
				return errors.New("service dependents: task useful work requires a native instance rather than a process claim")
			}
			if report.TaskProof == nil || windependents.ValidateTaskRunFreshness(*step.Task, *report.TaskProof, step.NotBefore, report.ObservedAt) != nil || f.TaskInstanceID != report.TaskProof.InstanceID {
				return errors.New("service dependents: useful task work is not bound to the native instance")
			}
		} else if f.TaskInstanceID != "" || report.Runtime == nil || !report.Runtime.Running || report.Runtime.AccountSID != step.AccountSID || f.ProcessID == 0 || f.ProcessID != report.Runtime.ProcessID || slices.Contains(step.PreviousPIDs, f.ProcessID) {
			return errors.New("service dependents: useful work is not bound to the fresh native process")
		}
	}
	return nil
}
func (step RotationStep) Summary() string {
	return fmt.Sprintf("%s %s %s", step.Direction, step.Action, step.Ref.Family)
}

func StepSourceID(rotationID, stepID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.service-dependent-step.v1\x00"+rotationID+"\x00"+stepID)).String()
}

// StepObservedSourceID retains the first signed result for this exact native
// effect across response loss and operational outbox reconstruction.
func StepObservedSourceID(rotationID, stepID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.service-dependent-step-observed.v1\x00"+rotationID+"\x00"+stepID)).String()
}

const RotationCredentialName = "service-dependent.password"

func InverseSourceID(id string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.service-dependent-inverse.v1\x00"+id)).String()
}
func DirectoryRestoredSourceID(id string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.service-dependent-directory-restored.v1\x00"+id)).String()
}
func DecodeRotationStep(raw []byte) (RotationStep, error) {
	var v RotationStep
	if e := decodeInventoryJSON(raw, 64<<10, &v); e != nil {
		return v, e
	}
	return v, v.Validate()
}
func DecodeStepReport(raw []byte) (StepReport, error) {
	var v StepReport
	e := decodeInventoryJSON(raw, 64<<10, &v)
	return v, e
}

func ValidProbeID(id string) bool { return validProbeID(id) }
func DecodeFunctionalProof(raw []byte, out *FunctionalProof) error {
	if out == nil {
		return errors.New("service dependents: functional evidence destination required")
	}
	if e := decodeInventoryJSON(raw, 16<<10, out); e != nil {
		return e
	}
	if !rotationDigestValid(out.EvidenceSHA256) {
		return errors.New("service dependents: useful-work digest required")
	}
	return nil
}

func DirectoryApplyStartedSourceID(rotationID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.service-dependent-directory-apply.v1\x00"+rotationID)).String()
}
