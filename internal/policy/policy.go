package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/events"
)

// S10.1 — Policy engine GA. An embedded OPA/Rego gate over the issue, deploy, and revoke
// lifecycle operations. Decisions are default-deny, evaluated on a bounded pool so a
// policy storm cannot starve issuance (AN-7), and every decision is an audited event
// (AN-2). The Rego policy document is the source of truth; this engine just compiles it
// once and evaluates it per request. It composes on top of certificate profiles (S8.1):
// profiles say what a credential may contain, policy says who may do what, when.

// Action is the lifecycle operation a decision gates.
type Action string

const (
	ActionIssue  Action = "issue"
	ActionDeploy Action = "deploy"
	ActionRevoke Action = "revoke"
)

// Input is the decision input. It is marshalled to the Rego document `input`, so policies
// reference `input.action`, `input.profile`, etc.
type Input struct {
	Action   Action         `json:"action"`
	TenantID string         `json:"tenant_id"`
	Profile  string         `json:"profile,omitempty"`
	Subject  string         `json:"subject,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	Attrs    map[string]any `json:"attrs,omitempty"`
}

// Decision is the policy outcome.
type Decision struct {
	Allow  bool
	Reason string
}

// Engine evaluates a compiled Rego policy. It is safe for concurrent use.
type Engine struct {
	query rego.PreparedEvalQuery
	pool  *bulkhead.Pool
	log   *events.Log
}

// Config wires an Engine.
type Config struct {
	// Module is the Rego policy source. It must declare `package trstctl.policy` and a
	// boolean `allow` (default false); it may define a string `reason`.
	Module string
	Pool   *bulkhead.Pool // AN-7; nil runs inline.
	Log    *events.Log    // AN-2; nil disables the decision audit.
}

// BaseModule is a conservative default policy: deny by default, permit revocation, and
// permit issuance/deployment only when a certificate profile is bound (S8.1). Operators
// replace or extend it; it exists so a fresh deployment is safe-by-default, not open.
const BaseModule = `package trstctl.policy

default allow := false
default reason := ""

allow if {
	input.action == "issue"
	object.get(input, "profile", "") != ""
}

allow if {
	input.action == "deploy"
	object.get(input, "profile", "") != ""
}

allow if {
	input.action == "revoke"
}

reason := "issuance and deployment require a bound certificate profile" if {
	input.action != "revoke"
	object.get(input, "profile", "") == ""
}
`

// New compiles the policy module and returns an Engine. A module that does not compile is
// a hard error — the caller must not run without an enforceable policy.
func New(cfg Config) (*Engine, error) {
	module := cfg.Module
	if module == "" {
		module = BaseModule
	}
	q, err := rego.New(
		rego.Query("data.trstctl.policy"),
		rego.Module("trstctl.policy.rego", module),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("policy: compile module: %w", err)
	}
	return &Engine{query: q, pool: cfg.Pool, log: cfg.Log}, nil
}

// Evaluate returns the policy decision for in. It fails closed: any evaluation error, a
// saturated pool, or an ambiguous result yields a deny. Every call is audited (AN-2).
func (e *Engine) Evaluate(ctx context.Context, in Input) (Decision, error) {
	d, err := e.run(ctx, in)
	e.audit(ctx, in, d, err)
	return d, err
}

func (e *Engine) run(ctx context.Context, in Input) (Decision, error) {
	// Convert through JSON so Rego sees the json-tagged field names (input.action, ...).
	raw, err := json.Marshal(in)
	if err != nil {
		return Decision{Reason: "policy: bad input"}, err
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return Decision{Reason: "policy: bad input"}, err
	}

	eval := func() (Decision, error) {
		rs, err := e.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return Decision{Allow: false, Reason: "policy evaluation error"}, fmt.Errorf("policy: eval: %w", err)
		}
		return decisionFrom(rs), nil
	}

	if e.pool == nil {
		return eval()
	}
	// AN-7: evaluate on the bounded pool; a saturated pool sheds fast (fail closed).
	type result struct {
		d   Decision
		err error
	}
	done := make(chan result, 1)
	if err := e.pool.Submit(func() { d, err := eval(); done <- result{d, err} }); err != nil {
		return Decision{Allow: false, Reason: "policy engine busy"}, bulkhead.ErrRejected
	}
	r := <-done
	return r.d, r.err
}

func decisionFrom(rs rego.ResultSet) Decision {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{Allow: false, Reason: "default deny (no policy decision)"}
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return Decision{Allow: false, Reason: "default deny (malformed policy result)"}
	}
	allow, _ := m["allow"].(bool)
	reason, _ := m["reason"].(string)
	if !allow && reason == "" {
		reason = "denied by policy"
	}
	return Decision{Allow: allow, Reason: reason}
}

func (e *Engine) audit(ctx context.Context, in Input, d Decision, evalErr error) {
	if e.log == nil {
		return
	}
	payload, _ := json.Marshal(struct {
		Action  Action `json:"action"`
		Profile string `json:"profile,omitempty"`
		Actor   string `json:"actor,omitempty"`
		Allow   bool   `json:"allow"`
		Reason  string `json:"reason,omitempty"`
		Error   string `json:"error,omitempty"`
	}{in.Action, in.Profile, in.Actor, d.Allow, d.Reason, errString(evalErr)})
	_, _ = e.log.Append(ctx, events.Event{Type: "policy.decision", TenantID: in.TenantID, Data: payload})
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
