// Package connector is the deployment-connector SDK (F7, F20). It extracts the
// shape shared by every deployment target — write the renewed credential out and
// activate it — so each connector (NGINX, Apache, IIS, HAProxy, F5, the cloud
// certificate stores) is a small, near-identical change: implement one seam and
// declare the capabilities it needs.
//
// A connector deploys through a capability-gated Sandbox: every privileged
// operation is checked against the connector's grant (the same
// pluginhost.Grant model that governs WASM plugins), so a connector can only
// ever do what it was granted — the rest is denied. Delivery is outbox-driven
// (AN-6): a deploy intent is enqueued with the state change and a worker hands
// it to the connector via the Registry, idempotently. Credentials are carried
// as []byte (AN-8); the package treats PEM as opaque (no crypto/*), computing
// fingerprints through the crypto boundary (AN-3).
package connector

import (
	"context"
	"errors"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/pluginhost"
)

// CapExec is the capability to run a local activation command (for example
// "nginx -s reload"). It extends the shared pluginhost capability vocabulary
// (fs.read/fs.write/net.dial) for deployment.
const CapExec pluginhost.Capability = "process.exec"

// ErrDenied is returned by the Sandbox when a connector attempts an operation
// its grant does not permit.
var ErrDenied = errors.New("connector: operation not permitted by the connector's capability grant")

// Deployment is the credential to deploy to a target.
type Deployment struct {
	// Target is the connector-specific destination (an address, an instance id,
	// a path root) the connector knows how to interpret.
	Target string
	// CertPEM and KeyPEM are the renewed credential (opaque PEM; AN-8).
	CertPEM []byte
	KeyPEM  []byte
	// Fingerprint is the SHA-256 of the certificate, used for idempotency and
	// audit. NewDeployment fills it via the crypto boundary.
	Fingerprint string
}

// NewDeployment builds a Deployment, computing the certificate fingerprint via
// the crypto boundary (AN-3).
func NewDeployment(target string, certPEM, keyPEM []byte) Deployment {
	return Deployment{
		Target:      target,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: crypto.SHA256Hex(certPEM),
	}
}

// Sandbox is the capability-gated environment a connector deploys through. Each
// method performs the operation only if the connector's grant permits it,
// returning ErrDenied otherwise.
type Sandbox interface {
	// Send delivers payload to a network target (requires net.dial for target).
	Send(target string, payload []byte) error
	// WriteFile writes data at path (requires fs.write covering path).
	WriteFile(path string, data []byte) error
	// Exec runs an activation command (requires process.exec).
	Exec(name string, args ...string) error
}

// Ops performs the raw deployment operations a Sandbox gates. Production wires
// real network/filesystem/exec; tests and conformance wire MemoryOps.
type Ops interface {
	Send(target string, payload []byte) error
	WriteFile(path string, data []byte) error
	Exec(name string, args []string) error
}

// Connector is the target-specific seam a connector author fills in: name
// itself, declare the capabilities it needs, and deploy a credential using only
// Sandbox operations its grant permits. It must be idempotent on
// Deployment.Fingerprint. It is the only code a new connector writes.
type Connector interface {
	Name() string
	Capabilities() pluginhost.Grant
	Deploy(ctx context.Context, sb Sandbox, dep Deployment) error
}

// Stats records what a deployment did.
type Stats struct {
	// Denied counts operations refused because they exceeded the grant.
	Denied int
}

// sandbox enforces a grant over an Ops: each call is capability-checked first.
type sandbox struct {
	grant  pluginhost.Grant
	ops    Ops
	denied int
}

func (s *sandbox) Send(target string, payload []byte) error {
	if !s.grant.Allows(pluginhost.CapNetDial, target) {
		s.denied++
		return ErrDenied
	}
	return s.ops.Send(target, payload)
}

func (s *sandbox) WriteFile(path string, data []byte) error {
	if !s.grant.Allows(pluginhost.CapFSWrite, path) {
		s.denied++
		return ErrDenied
	}
	return s.ops.WriteFile(path, data)
}

func (s *sandbox) Exec(name string, args ...string) error {
	if !s.grant.Has(CapExec) {
		s.denied++
		return ErrDenied
	}
	return s.ops.Exec(name, args)
}

// Run deploys dep through connector c, enforcing c's declared capabilities over
// ops. Operations outside the grant are refused (ErrDenied), so a connector can
// never exceed its grant — the same discipline the plugin host enforces for
// WASM connectors. It returns the deployment's stats.
func Run(ctx context.Context, c Connector, ops Ops, dep Deployment) (Stats, error) {
	sb := &sandbox{grant: c.Capabilities(), ops: ops}
	err := c.Deploy(ctx, sb, dep)
	return Stats{Denied: sb.denied}, err
}
