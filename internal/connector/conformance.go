package connector

import (
	"context"
	"errors"
	"sort"
	"strings"

	"certctl.io/certctl/internal/pluginhost"
)

// conformance sample credential (opaque bytes; connectors do not parse PEM).
var (
	conformanceCert = []byte("-----BEGIN CERTIFICATE-----\nconformance-leaf\n-----END CERTIFICATE-----\n")
	conformanceKey  = []byte("-----BEGIN PRIVATE KEY-----\nconformance-key\n-----END PRIVATE KEY-----\n")
)

const conformanceTarget = "conformance.target"

// Check is one conformance check and its outcome.
type Check struct {
	Name   string
	Passed bool
	Detail string
}

// Report is the result of running the connector conformance suite.
type Report struct {
	Checks []Check
}

// OK reports whether every check passed (and at least one ran).
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if !c.Passed {
			return false
		}
	}
	return len(r.Checks) > 0
}

func (r *Report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: passed, Detail: detail})
}

// Conformance runs the shared connector conformance suite against c. It is what
// a connector author runs to self-validate and the contract every connector
// from this template must satisfy: name itself, declare at least one capability
// (and no more than it uses — least privilege), deploy a credential through the
// sandbox, do so idempotently, and have operations outside its grant denied.
func Conformance(ctx context.Context, c Connector) Report {
	var r Report

	r.add("names itself", c.Name() != "", c.Name())

	grant := c.Capabilities()
	declares := grant.Has(pluginhost.CapFSRead) || grant.Has(pluginhost.CapFSWrite) ||
		grant.Has(pluginhost.CapNetDial) || grant.Has(CapExec)
	r.add("declares at least one capability", declares, "")

	ops := NewMemoryOps()
	dep := NewDeployment(conformanceTarget, conformanceCert, conformanceKey)
	if _, err := Run(ctx, c, ops, dep); err != nil {
		r.add("deploys a credential", false, err.Error())
		return r
	}
	r.add("deploys a credential", true, "")

	performed := len(ops.Targets()) > 0 || len(ops.Files()) > 0 || len(ops.Execs()) > 0
	r.add("performs a deployment operation", performed, "")

	// Idempotency is over persistent target state (files + sent), not over
	// side-effecting reloads, which may safely repeat.
	before := stateSignature(ops)
	if _, err := Run(ctx, c, ops, dep); err != nil {
		r.add("redeploy is idempotent", false, err.Error())
		return r
	}
	r.add("redeploy is idempotent", stateSignature(ops) == before, "")

	// Least privilege: every capability the connector did not request is denied
	// by the sandbox, and it requests fewer than all of them.
	r.add("denies operations outside its grant", deniesUngranted(grant), "")

	return r
}

// deniesUngranted builds a sandbox from grant and confirms that each operation
// whose capability is not granted is refused, requiring at least one such
// refusal (so the connector is not all-powerful).
func deniesUngranted(grant pluginhost.Grant) bool {
	sb := &sandbox{grant: grant, ops: NewMemoryOps()}
	deniedAny := false
	if !grant.Has(pluginhost.CapFSWrite) {
		if !errors.Is(sb.WriteFile("/conformance/denied", nil), ErrDenied) {
			return false
		}
		deniedAny = true
	}
	if !grant.Has(pluginhost.CapNetDial) {
		if !errors.Is(sb.Send("conformance:1", nil), ErrDenied) {
			return false
		}
		deniedAny = true
	}
	if !grant.Has(CapExec) {
		if !errors.Is(sb.Exec("denied"), ErrDenied) {
			return false
		}
		deniedAny = true
	}
	return deniedAny
}

// stateSignature is a deterministic fingerprint of a target's persistent state
// (written files and sent payloads), used to check idempotency.
func stateSignature(m *MemoryOps) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := make([]string, 0, len(m.files)+len(m.sent))
	for k, v := range m.files {
		parts = append(parts, "F:"+k+"="+string(v))
	}
	for k, v := range m.sent {
		parts = append(parts, "S:"+k+"="+string(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}
