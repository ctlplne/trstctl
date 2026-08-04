// SPDX-License-Identifier: MPL-2.0

package connector

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Rollback as an executable operation (epic D4).
//
// The obvious design is to re-deploy the previous certificate, and it is not
// available to us. After B1 the control plane never holds a subject private
// key, so there is nothing to push back — a "rollback" that re-uploaded would
// need the key, and the whole point of CSR-first issuance is that we do not
// have it. Storing keys to make rollback easy would trade the strongest
// property in the product for an operator convenience.
//
// The executable form is a re-BIND. The predecessor certificate is already
// installed on the appliance; what changed at deploy time was which installed
// object the listener points at. Rollback points it back. No key moves, nothing
// is uploaded, and the operation is available precisely because the control
// plane holds nothing.
//
// That only works if the predecessor SURVIVES the deploy, and it did not: every
// appliance connector installed under a name derived from the target, so each
// deploy overwrote the object before it. Hence DeployedObjectName below —
// deployments install under a name carrying the certificate's fingerprint, so
// two deployments are two objects and the earlier one is still there to bind
// back to.

// Rollback names a re-bind to an already-installed predecessor.
//
// It carries no certificate and no key, deliberately. A rollback that needed
// either would be a redeploy wearing a different name, and would reintroduce
// the requirement to hold key material that B1 removed.
type Rollback struct {
	// Target is the listener, profile, or virtual service to re-point.
	Target string
	// PredecessorFingerprint identifies the installed object to bind back to.
	// It is the same fingerprint the earlier deployment carried, which is what
	// makes the object addressable without the control plane storing anything
	// about the appliance's internal naming.
	PredecessorFingerprint string
	// Reason is operator-facing context recorded with the transcript. It never
	// reaches the appliance.
	Reason string
}

// Rollbacker is the optional re-bind capability of a Connector.
//
// Optional on purpose. A connector whose API cannot address an installed object
// separately from uploading one cannot roll back this way, and the honest
// outcome is that it does not implement this interface and the census says so —
// rather than a Rollback method that returns nil and lets an operator believe a
// listener was re-pointed when nothing happened.
type Rollbacker interface {
	Connector
	// Rollback re-binds the target to the named predecessor object.
	//
	// It must fail — not silently succeed — when the predecessor object is not
	// present on the appliance. A rollback that cannot find what it is rolling
	// back to has not rolled anything back, and reporting success would leave a
	// bad certificate serving traffic behind a receipt that says otherwise.
	Rollback(ctx context.Context, sb Sandbox, rb Rollback) error
}

// ErrNoPredecessorInstalled is returned when the object a rollback names is not
// on the target. It is a distinct error because the operator response differs
// from a network or auth failure: there is nothing to roll back to, and no
// amount of retrying will produce one.
var ErrNoPredecessorInstalled = errors.New("connector: the predecessor object is not installed on the target")

// ErrRollbackUnsupported is returned when a connector cannot re-bind.
var ErrRollbackUnsupported = errors.New("connector: this connector cannot roll back by re-binding")

// objectNameFingerprintLen is how much of the fingerprint goes in an object
// name. Twelve hex characters is 48 bits — far beyond collision risk for the
// handful of certificates one target sees.
//
// It does NOT guarantee the result fits an appliance's object-name limit;
// nothing here measures that, and the base is operator-supplied. Callers own
// their limits. Truncating the base to make room would be worse than a rejected
// deploy: two targets sharing a prefix would collide into one object, and the
// second deploy would silently overwrite the first — destroying exactly the
// predecessor this naming exists to preserve.
const objectNameFingerprintLen = 12

// DeployedObjectName is the name a deployment installs its certificate under.
//
// Deriving it from the fingerprint is what makes rollback possible at all: two
// deployments produce two objects, so the predecessor is still there when the
// successor turns out to be wrong. It also keeps deploys idempotent for free —
// the same certificate computes the same name, so a retried deploy overwrites
// itself rather than accumulating.
//
// base is the connector's per-target object base (a profile name, a virtual
// service name). An empty fingerprint returns base unchanged, which is the
// pre-D4 behaviour: a connector that has no fingerprint to work with should
// deploy the way it always did rather than inventing a name.
func DeployedObjectName(base, fingerprint string) string {
	fp := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(fingerprint), "sha256:"))
	fp = strings.ReplaceAll(fp, ":", "")
	if fp == "" || base == "" {
		return base
	}
	if len(fp) > objectNameFingerprintLen {
		fp = fp[:objectNameFingerprintLen]
	}
	return base + "-" + fp
}

// RollbackObjectName is the object a rollback binds back to. It is
// DeployedObjectName for the predecessor's fingerprint — the same function, so
// the two can never disagree about how a name is built, which is the failure
// that would make every rollback report "not installed" for objects that are.
func RollbackObjectName(base, predecessorFingerprint string) string {
	return DeployedObjectName(base, predecessorFingerprint)
}

// rollbackCapableFamilies is the census of connectors that can execute a
// re-bind (the C1a discipline: advertise only what ships).
//
// A static list rather than a type assertion over the registry, because an
// assertion passes for a stub — and a stub returning nil is precisely the thing
// that would let an operator believe a listener was re-pointed when nothing
// happened. A test cross-checks this list against the interface in both
// directions: everything named here must implement Rollbacker, and nothing that
// implements Rollbacker may be missing from here.
var rollbackCapableFamilies = []string{
	// Each of these has an API that addresses an INSTALLED object separately
	// from uploading one — a bind/patch call naming a crypto object, a certkey,
	// a certificate name — which is the property a re-bind needs.
	"f5",
	"kemp",
	"netscaler",
	"a10",
}

// RollbackCapableConnectors reports which connector families can roll back by
// re-binding, sorted.
func RollbackCapableConnectors() []string {
	out := append([]string(nil), rollbackCapableFamilies...)
	sort.Strings(out)
	return out
}

// CanRollback reports whether a connector family can execute a re-bind.
func CanRollback(name string) bool {
	for _, n := range rollbackCapableFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// RunRollback executes a re-bind through connector c, enforcing c's declared
// capabilities over ops exactly as Run does for a deploy.
//
// Rollback runs under the SAME grant as deploy, not a wider one. It is tempting
// to give an emergency path more room — it runs when something is already
// broken — but a rollback that could reach further than the deploy it undoes
// would be a capability escalation available to anyone who can cause a deploy
// to fail.
//
// A connector that cannot re-bind returns ErrRollbackUnsupported rather than
// nil. The difference is the whole point: an operator staring at a failing
// listener needs to know that nothing happened.
func RunRollback(ctx context.Context, c Connector, ops Ops, rb Rollback) (Stats, error) {
	r, ok := c.(Rollbacker)
	if !ok {
		return Stats{}, ErrRollbackUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	err := r.Rollback(ctx, sb, rb)
	return Stats{Denied: sb.denied}, err
}

// FingerprintFromObjectName recovers the fingerprint prefix an object name
// carries (epic E2).
//
// The inverse of DeployedObjectName, and it lives beside it so the two cannot
// drift: a readback that parsed names by a rule the deploy did not follow would
// report every correctly-bound listener as diverged, which during an incident is
// worse than reporting nothing.
//
// Returns the PREFIX, not a full fingerprint — the name only ever carried a
// prefix. Callers compare with strings.HasPrefix, and ClassifyReadback does.
func FingerprintFromObjectName(name string) string {
	idx := strings.LastIndex(name, "-")
	if idx < 0 || idx+1 >= len(name) {
		return ""
	}
	candidate := strings.ToLower(name[idx+1:])
	if len(candidate) != objectNameFingerprintLen {
		return ""
	}
	for _, r := range candidate {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return candidate
}
