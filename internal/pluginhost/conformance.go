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

// Conformance validates that a plugin meets the host contract: it is a valid WASM
// module, instantiates under the sandbox, exports the required run function,
// executes without trapping, and — given no grant — performs no privileged
// operation (its sandbox holds). It is the tool a plugin author runs against
// their build, and what the host uses to admit a plugin.
func (h *Host) Conformance(ctx context.Context, wasm []byte) Report {
	var r Report

	p, err := h.Load(ctx, wasm, NewGrant()) // empty grant: nothing is permitted
	if err != nil {
		r.add("instantiates under sandbox", false, err.Error())
		return r
	}
	defer func() { _ = p.Close(ctx) }()
	r.add("instantiates under sandbox", true, "")

	if p.mod.ExportedFunction("run") == nil {
		r.add("exports run()", false, "no exported function named run")
		return r
	}
	r.add("exports run()", true, "")

	if _, err := h.Invoke(ctx, p, "run"); err != nil {
		r.add("run() executes", false, err.Error())
		return r
	}
	r.add("run() executes", true, "")

	// With no capabilities granted, the plugin must not have performed any
	// privileged operation.
	if p.Stats().Writes != 0 {
		r.add("sandbox respected under empty grant", false, "plugin performed a privileged write with no grant")
	} else {
		r.add("sandbox respected under empty grant", true, "")
	}
	return r
}
