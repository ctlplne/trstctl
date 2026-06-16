package connector

import (
	"context"
	"errors"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/pluginhost"
)

// conformance sample credential: a real ECDSA P-256 certificate and key, so the
// suite works for connectors that parse the certificate (compute a thumbprint,
// build a PFX) as well as those that treat it as opaque bytes.
var (
	conformanceCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBiDCCAS2gAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpjb25mb3Jt
YW5jZS5jb25uZWN0b3IudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw
MDBaMCUxIzAhBgNVBAMTGmNvbmZvcm1hbmNlLmNvbm5lY3Rvci50ZXN0MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE4TYNtNbbVlPcVpyznJuujANXTbsaRNL5D41K
VfB5GdJEG372Pgtn59Mp7+1+PUbyHTbaKJ1RU0n6vgW5/BCC1aNOMEwwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCUGA1UdEQQeMByCGmNvbmZv
cm1hbmNlLmNvbm5lY3Rvci50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQD2NqiRyoq8
T1vJogCsCMRDiEMMsA04Qhbs5uF149egpgIhALTX3I6Xe4dQk3GMTEaXC5GWXkaj
O9xXOtFRqPTY0dXn
-----END CERTIFICATE-----
`)
	conformanceKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2drNvkGQeqFUx3xE
zejpKQlXChZFd7J3qw/JXoL+x72hRANCAAThNg201ttWU9xWnLOcm66MA1dNuxpE
0vkPjUpV8HkZ0kQbfvY+C2fn0ynv7X49RvIdNtoonVFTSfq+Bbn8EILV
-----END PRIVATE KEY-----
`)
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

	performed := len(ops.Targets()) > 0 || len(ops.Files()) > 0 || len(ops.Execs()) > 0 || len(ops.Requests()) > 0
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
	parts := make([]string, 0, len(m.files)+len(m.sent)+len(m.requests))
	for k, v := range m.files {
		parts = append(parts, "F:"+k+"="+string(v))
	}
	for k, v := range m.sent {
		parts = append(parts, "S:"+k+"="+string(v))
	}
	for k, v := range m.requests {
		parts = append(parts, "R:"+k+"="+string(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}
