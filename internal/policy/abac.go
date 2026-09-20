// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/events"
)

// ABACInput is the attribute context evaluated by the deny overlay. RBAC and the
// mutation policy gate decide whether the caller may act at all; ABAC narrows that
// decision using actor attributes, resource attributes, configured environment, and
// deterministic time fields.
type ABACInput struct {
	Permission string            `json:"permission"`
	Action     Action            `json:"action,omitempty"`
	TenantID   string            `json:"tenant_id"`
	Profile    string            `json:"profile,omitempty"`
	Subject    string            `json:"subject,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	ActorAttrs map[string]string `json:"actor_attrs,omitempty"`
	Resource   map[string]string `json:"resource,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Now        string            `json:"now,omitempty"`
	NowUnix    int64             `json:"now_unix,omitempty"`
	NowHourUTC int               `json:"now_hour_utc,omitempty"`
	NowWeekday string            `json:"now_weekday_utc,omitempty"`
}

// ABACDecision is the deny-overlay result. Deny=false is silent: the caller still
// needs RBAC and, where configured, the primary policy gate. Deny=true vetoes.
type ABACDecision struct {
	Deny   bool
	Reason string
}

// ABACEngine evaluates a compiled Rego deny overlay. It is safe for concurrent use.
type ABACEngine struct {
	query rego.PreparedEvalQuery
	pool  *bulkhead.Pool
	log   *events.Log
}

// ABACConfig wires an ABACEngine.
type ABACConfig struct {
	// Module must declare package trstctl.abac and a boolean `deny`; it may define a
	// string `reason`. Empty uses BaseABACModule, a no-deny overlay.
	Module string
	Pool   *bulkhead.Pool
	Log    *events.Log
}

// BaseABACModule is a safe no-deny overlay. It exists so code can compile a known
// package shape for tests or explicit empty config, but production deployments
// normally provide their own module.
const BaseABACModule = `package trstctl.abac

default deny := false
default reason := ""
`

// NewABAC compiles a deny-overlay module. A non-compiling module is a hard error:
// an enabled-but-broken ABAC config must not serve.
func NewABAC(cfg ABACConfig) (*ABACEngine, error) {
	module := cfg.Module
	if module == "" {
		module = BaseABACModule
	}
	q, err := rego.New(
		rego.Query("data.trstctl.abac"),
		rego.Module("trstctl.abac.rego", module),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("policy: compile abac module: %w", err)
	}
	return &ABACEngine{query: q, pool: cfg.Pool, log: cfg.Log}, nil
}

// EvaluateDeny returns the ABAC deny decision for in. It fails closed: evaluation
// errors, saturated bulkheads, and malformed policy outputs produce Deny=true.
func (e *ABACEngine) EvaluateDeny(ctx context.Context, in ABACInput) (ABACDecision, error) {
	d, err := e.runDeny(ctx, in)
	e.auditABAC(ctx, in, d, err)
	return d, err
}

func (e *ABACEngine) runDeny(ctx context.Context, in ABACInput) (ABACDecision, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return ABACDecision{Deny: true, Reason: "abac: bad input"}, err
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return ABACDecision{Deny: true, Reason: "abac: bad input"}, err
	}

	eval := func() (ABACDecision, error) {
		rs, err := e.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return ABACDecision{Deny: true, Reason: "abac evaluation error"}, fmt.Errorf("policy: abac eval: %w", err)
		}
		return abacDecisionFrom(rs), nil
	}
	if e.pool == nil {
		return eval()
	}
	type result struct {
		d   ABACDecision
		err error
	}
	done := make(chan result, 1)
	if err := e.pool.Submit(func() { d, err := eval(); done <- result{d, err} }); err != nil {
		return ABACDecision{Deny: true, Reason: "abac engine busy"}, bulkhead.ErrRejected
	}
	r := <-done
	return r.d, r.err
}

func abacDecisionFrom(rs rego.ResultSet) ABACDecision {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return ABACDecision{Deny: true, Reason: "abac default deny (no policy decision)"}
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return ABACDecision{Deny: true, Reason: "abac default deny (malformed policy result)"}
	}
	deny, _ := m["deny"].(bool)
	reason, _ := m["reason"].(string)
	if deny && reason == "" {
		reason = "denied by ABAC"
	}
	return ABACDecision{Deny: deny, Reason: reason}
}

func (e *ABACEngine) auditABAC(ctx context.Context, in ABACInput, d ABACDecision, evalErr error) {
	if e.log == nil {
		return
	}
	payload, _ := json.Marshal(struct {
		Permission string `json:"permission"`
		Action     Action `json:"action,omitempty"`
		Actor      string `json:"actor,omitempty"`
		Subject    string `json:"subject,omitempty"`
		Deny       bool   `json:"deny"`
		Reason     string `json:"reason,omitempty"`
		Error      string `json:"error,omitempty"`
	}{in.Permission, in.Action, in.Actor, in.Subject, d.Deny, d.Reason, errString(evalErr)})
	_, _ = e.log.Append(ctx, events.Event{Type: "policy.abac.decision", TenantID: in.TenantID, Data: payload})
}
