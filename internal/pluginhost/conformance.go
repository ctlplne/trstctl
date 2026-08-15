// SPDX-License-Identifier: MPL-2.0

package pluginhost

import "context"

// Check is one conformance check and its outcome.
type Check struct {
	Name   string
	Passed bool
	Detail string
}

// Report is the result of running the conformance suite against a plugin.
type Report struct {
	Checks []Check
}

// OK reports whether every check passed.
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

// Conformance validates that a plugin meets the host contract at ZERO
// capabilities: it is a valid WASM module, instantiates under an empty grant,
// exports the required run function, executes without trapping, and performs no
// privileged operation.
//
// Because the sandbox shapes the environment by the grant, "instantiates under an
// empty grant" now proves something specific and useful: the plugin declares no
// privileged import at all. A plugin that does declare one fails this check —
// correctly, since it is not a zero-capability plugin — and should be admitted
// with ConformanceUnderGrant against the grant it will actually run under.
func (h *Host) Conformance(ctx context.Context, wasm []byte) Report {
	return h.ConformanceUnderGrant(ctx, wasm, NewGrant())
}

// ConformanceUnderGrant validates a plugin against the grant it will be run with.
// It is the admission check for a plugin that legitimately needs capabilities: a
// connector that writes certificates has to be judged under a grant that permits
// writing them, not under an empty one it could never satisfy.
//
// The privileged-operation check is relative to the grant: under an empty grant it
// asserts the plugin did nothing privileged; under a real grant it asserts the
// plugin was never DENIED, which is the signal that it is reaching for something
// its grant does not cover.
func (h *Host) ConformanceUnderGrant(ctx context.Context, wasm []byte, grant Grant) Report {
	var r Report

	p, err := h.Load(ctx, wasm, grant)
	if err != nil {
		r.add("instantiates under sandbox", false, err.Error())
		return r
	}
	defer func() { _ = p.Close(ctx) }()
	r.add("instantiates under sandbox", true, "")

	if !p.HasExport("run") {
		r.add("exports run()", false, "no exported function named run")
		return r
	}
	r.add("exports run()", true, "")

	if _, err := h.Invoke(ctx, p, "run"); err != nil {
		r.add("run() executes", false, err.Error())
		return r
	}
	r.add("run() executes", true, "")

	stats := p.Stats()
	if grant.Empty() {
		// Nothing was permitted, so nothing may have happened.
		if stats.Writes != 0 || stats.Reads != 0 || stats.Dials != 0 {
			r.add("sandbox respected under empty grant", false,
				"plugin performed a privileged operation with no grant")
		} else {
			r.add("sandbox respected under empty grant", true, "")
		}
		return r
	}
	// Under a real grant, a denial means the plugin reached past what it was given.
	// That is not a sandbox failure — the sandbox held — but it is a plugin that
	// will not behave as its author expects, so admission should surface it.
	if stats.Denied != 0 {
		r.add("stays within its grant", false,
			"plugin attempted an operation its grant does not cover")
	} else {
		r.add("stays within its grant", true, "")
	}
	return r
}
