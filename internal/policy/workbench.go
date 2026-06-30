package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
)

// DryRunKind selects the policy package shape the workbench validates.
type DryRunKind string

const (
	DryRunKindLifecycle DryRunKind = "lifecycle"
	DryRunKindABAC      DryRunKind = "abac"
)

// DryRunConfig is the candidate policy, normalized input, and trace budget for a
// policy workbench run. The input is JSON-shaped and should already be scoped to
// the caller's tenant by the transport layer.
type DryRunConfig struct {
	Kind       DryRunKind
	Module     string
	Input      map[string]any
	TraceLimit int
}

// DryRunResult is a candidate validation + evaluation result safe to return to a
// browser and safe to summarize into audit. Trace rows deliberately carry policy
// source locations and expression text, not plugged local variables, so caller
// input values do not leak into the event log.
type DryRunResult struct {
	Kind         DryRunKind    `json:"kind"`
	Valid        bool          `json:"valid"`
	ModuleSHA256 string        `json:"module_sha256"`
	Package      string        `json:"package"`
	Query        string        `json:"query"`
	Allow        bool          `json:"allow"`
	Deny         bool          `json:"deny"`
	Reason       string        `json:"reason,omitempty"`
	Error        string        `json:"error,omitempty"`
	Trace        []DryRunTrace `json:"trace"`
}

// DryRunTrace is one bounded, non-secret evaluation trace row.
type DryRunTrace struct {
	Op       string `json:"op"`
	QueryID  uint64 `json:"query_id"`
	ParentID uint64 `json:"parent_id,omitempty"`
	Location string `json:"location,omitempty"`
	Node     string `json:"node,omitempty"`
	Message  string `json:"message,omitempty"`
}

const defaultDryRunTraceLimit = 80

// DryRun compiles and evaluates a candidate Rego module without changing the live
// enforcement engine. Compile/evaluation failures are returned as first-class
// result.Error values so an authoring UI can show policy-error states as data.
func DryRun(ctx context.Context, cfg DryRunConfig) (DryRunResult, error) {
	kind := cfg.Kind
	if kind == "" {
		kind = DryRunKindLifecycle
	}
	input := cfg.Input
	if input == nil {
		input = map[string]any{}
	}
	switch kind {
	case DryRunKindLifecycle:
		return dryRunLifecycle(ctx, cfg.Module, input, cfg.TraceLimit)
	case DryRunKindABAC:
		return dryRunABAC(ctx, cfg.Module, input, cfg.TraceLimit)
	default:
		return DryRunResult{}, fmt.Errorf("policy: unsupported dry-run kind %q", kind)
	}
}

func dryRunLifecycle(ctx context.Context, module string, input map[string]any, limit int) (DryRunResult, error) {
	module = moduleOrBase(module, BaseModule)
	result := baseDryRunResult(DryRunKindLifecycle, module, "trstctl.policy", "data.trstctl.policy")
	if err := validateLifecycleDryRunInput(input); err != nil {
		return DryRunResult{}, err
	}
	rs, trace, err := evalRego(ctx, "trstctl.policy.rego", module, result.Query, input, limit)
	result.Trace = trace
	if err != nil {
		result.Valid = strings.Contains(err.Error(), "eval")
		result.Error = err.Error()
		return result, nil
	}
	result.Valid = true
	decision := decisionFrom(rs)
	result.Allow = decision.Allow
	result.Deny = !decision.Allow
	result.Reason = decision.Reason
	return result, nil
}

func dryRunABAC(ctx context.Context, module string, input map[string]any, limit int) (DryRunResult, error) {
	module = moduleOrBase(module, BaseABACModule)
	result := baseDryRunResult(DryRunKindABAC, module, "trstctl.abac", "data.trstctl.abac")
	if err := validateABACDryRunInput(input); err != nil {
		return DryRunResult{}, err
	}
	rs, trace, err := evalRego(ctx, "trstctl.abac.rego", module, result.Query, input, limit)
	result.Trace = trace
	if err != nil {
		result.Valid = strings.Contains(err.Error(), "eval")
		result.Error = err.Error()
		return result, nil
	}
	result.Valid = true
	decision := abacDecisionFrom(rs)
	result.Allow = !decision.Deny
	result.Deny = decision.Deny
	result.Reason = decision.Reason
	return result, nil
}

func baseDryRunResult(kind DryRunKind, module, pkg, query string) DryRunResult {
	return DryRunResult{
		Kind:         kind,
		ModuleSHA256: trstcrypto.SHA256Hex([]byte(module)),
		Package:      pkg,
		Query:        query,
	}
}

func moduleOrBase(module, base string) string {
	module = strings.TrimSpace(module)
	if module == "" {
		return base
	}
	return module
}

func evalRego(ctx context.Context, filename, module, query string, input map[string]any, limit int) (rego.ResultSet, []DryRunTrace, error) {
	prepared, err := rego.New(
		rego.Query(query),
		rego.Module(filename, module),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, []DryRunTrace{{Op: "Compile", Message: "candidate module did not compile"}}, fmt.Errorf("policy: compile: %w", err)
	}
	tracer := newDryRunTracer(limit)
	rs, err := prepared.Eval(ctx, rego.EvalInput(input), rego.EvalQueryTracer(tracer))
	trace := tracer.rows()
	if err != nil {
		return nil, trace, fmt.Errorf("policy: eval: %w", err)
	}
	return rs, trace, nil
}

func validateLifecycleDryRunInput(input map[string]any) error {
	action, _ := input["action"].(string)
	switch Action(strings.TrimSpace(action)) {
	case ActionIssue, ActionDeploy, ActionRevoke:
	default:
		return errors.New("policy: lifecycle dry-run input.action must be issue, deploy, or revoke")
	}
	if tenant, _ := input["tenant_id"].(string); strings.TrimSpace(tenant) == "" {
		return errors.New("policy: dry-run input.tenant_id is required")
	}
	return nil
}

func validateABACDryRunInput(input map[string]any) error {
	permission, _ := input["permission"].(string)
	if strings.TrimSpace(permission) == "" {
		return errors.New("policy: abac dry-run input.permission is required")
	}
	if tenant, _ := input["tenant_id"].(string); strings.TrimSpace(tenant) == "" {
		return errors.New("policy: dry-run input.tenant_id is required")
	}
	return nil
}

type dryRunTracer struct {
	limit int
	rowsV []DryRunTrace
}

func newDryRunTracer(limit int) *dryRunTracer {
	if limit <= 0 || limit > 200 {
		limit = defaultDryRunTraceLimit
	}
	return &dryRunTracer{limit: limit}
}

func (t *dryRunTracer) Enabled() bool { return t != nil }

func (t *dryRunTracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{PlugLocalVars: false}
}

func (t *dryRunTracer) TraceEvent(evt topdown.Event) {
	if len(t.rowsV) >= t.limit {
		return
	}
	switch evt.Op {
	case topdown.EnterOp, topdown.EvalOp, topdown.FailOp, topdown.ExitOp, topdown.NoteOp:
	default:
		return
	}
	row := DryRunTrace{
		Op:       string(evt.Op),
		QueryID:  evt.QueryID,
		ParentID: evt.ParentID,
		Message:  strings.TrimSpace(evt.Message),
	}
	if evt.Location != nil {
		row.Location = fmt.Sprintf("%s:%d", evt.Location.File, evt.Location.Row)
	}
	if evt.Node != nil {
		row.Node = trimTraceNode(evt.Node.String())
	}
	t.rowsV = append(t.rowsV, row)
}

func (t *dryRunTracer) rows() []DryRunTrace {
	return append([]DryRunTrace(nil), t.rowsV...)
}

func trimTraceNode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= 220 {
		return s
	}
	return s[:217] + "..."
}

// CloneInputMap deep-copies JSON-shaped dry-run input before the transport layer
// overlays tenant and actor values.
func CloneInputMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}
