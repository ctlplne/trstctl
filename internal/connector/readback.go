// SPDX-License-Identifier: MPL-2.0

package connector

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Asking the appliance what it actually has (epic E2).
//
// A deploy that returns nil means the device accepted the request. It does not
// mean the device is serving the certificate, and on an appliance the gap
// between those two is wide enough to drive an outage through: the upload
// succeeds, the crypto object installs, and the virtual server keeps pointing at
// the previous profile — so every receipt reads green while clients keep getting
// the old certificate until it expires.
//
// D2 added the handshake half of the answer: connect to the listener and see
// what it presents. This is the other half, and the two are not redundant.
//
//	handshake says old cert + API says installed  -> installed but not bound
//	handshake says old cert + API says absent     -> the deploy did not take
//	handshake unreachable   + API says installed  -> the work landed; the probe
//	                                                 could not reach the VIP
//
// One signal alone cannot separate those, and they send an operator to three
// different places. A handshake failure with no readback reads as "the deploy
// failed" when the far more common cause is a binding the deploy never touched.

// Readbacker is the optional post-mutation readback capability of a Connector.
//
// Optional for the same reason Rollbacker is: a family whose API cannot report
// what is installed cannot do this, and the honest outcome is that it does not
// implement the interface and the census says so — rather than a Readback that
// returns "looks fine" without asking anything.
type Readbacker interface {
	Connector
	// Readback asks the device what it has installed for this target.
	//
	// It reports what the DEVICE says, not what the deploy intended. An
	// implementation that echoes the deployment back would turn this surface
	// into an expensive way of restating the request.
	Readback(ctx context.Context, sb Sandbox, target string) (Installed, error)
}

// Installed is what the device reports for a target.
type Installed struct {
	// Fingerprint is the SHA-256 of the certificate the device says is bound to
	// this target, lowercase hex. Empty when the device reports an object but
	// exposes no fingerprint for it — which is a real limitation of some APIs
	// and must not be rendered as a mismatch.
	Fingerprint string
	// ObjectName is the device's own name for the installed object, so an
	// operator can find it in the appliance's UI.
	ObjectName string
	// Bound reports whether the object is actually attached to the serving
	// listener, as distinct from merely present on the device.
	//
	// This is the field the epic exists for. "Uploaded" and "serving" are
	// different states on every appliance in the census, and the one that hurts
	// is uploaded-but-not-bound: it looks like success from every angle except
	// the client's.
	Bound bool
}

// ErrReadbackUnsupported is returned when a family cannot report installed state.
var ErrReadbackUnsupported = errors.New("connector: this family's API cannot report what is installed")

// readbackCapableFamilies are the families whose API can report installed state.
//
// Each of these exposes a call that lists or gets an installed object and its
// binding, separately from the call that uploads one. That is the same property
// rollback needs, and for the same reason — an API that can only push cannot be
// asked what it has.
var readbackCapableFamilies = []string{
	"f5",
	"kemp",
	"netscaler",
	"a10",
}

// CanReadback reports whether a family can be asked what it has installed.
func CanReadback(name string) bool {
	for _, n := range readbackCapableFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// ReadbackCapableConnectors reports the families that can report installed
// state, sorted.
func ReadbackCapableConnectors() []string {
	out := append([]string(nil), readbackCapableFamilies...)
	sort.Strings(out)
	return out
}

// RunReadback asks a connector what the device has, enforcing its grant exactly
// as Run does for a deploy.
//
// A family that cannot report returns ErrReadbackUnsupported before touching the
// network, so a caller learns the capability is absent rather than watching a
// request fail and having to guess why.
func RunReadback(ctx context.Context, c Connector, ops Ops, target string) (Installed, error) {
	rb, ok := c.(Readbacker)
	if !ok {
		return Installed{}, ErrReadbackUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	return rb.Readback(ctx, sb, target)
}

// ReadbackVerdict classifies a readback against what was deployed (epic E2).
//
// A closed set, like D2's mismatch classes, because these strings reach an
// operator during an incident and each one implies a different next action. An
// open-ended detail string would let a future caller invent a fourth state
// nobody has a runbook for.
type ReadbackVerdict string

const (
	// ReadbackServing: the device reports our certificate, bound to the target.
	ReadbackServing ReadbackVerdict = "serving"
	// ReadbackInstalledNotBound: the object is on the device and the listener is
	// not using it. The deploy worked and the binding did not — the specific
	// failure this epic exists to catch, and the one that reads as success
	// everywhere else.
	ReadbackInstalledNotBound ReadbackVerdict = "installed_not_bound"
	// ReadbackAbsent: the device does not have what we deployed.
	ReadbackAbsent ReadbackVerdict = "absent"
	// ReadbackDiverged: the device has something bound that is not ours.
	ReadbackDiverged ReadbackVerdict = "diverged"
	// ReadbackUnknown: the device answered without a fingerprint, so what is
	// bound cannot be compared. NOT a pass — it is the absence of an answer, and
	// collapsing it into "serving" is the overclaim this workstream removes.
	ReadbackUnknown ReadbackVerdict = "unknown"
)

// ClassifyReadback compares what the device reports against what was deployed.
func ClassifyReadback(got Installed, deployedFingerprint string) ReadbackVerdict {
	want := strings.ToLower(strings.TrimSpace(deployedFingerprint))
	have := strings.ToLower(strings.TrimSpace(got.Fingerprint))

	if have == "" {
		if got.ObjectName == "" {
			return ReadbackAbsent
		}
		// The device named an object but will not say which certificate it is.
		// That is a limit of the API, not evidence of success.
		return ReadbackUnknown
	}
	// PREFIX comparison, because an object name carries a fingerprint prefix
	// rather than the whole digest. Requiring equality would classify every
	// correctly-bound listener as diverged — the failure mode that would get
	// this surface switched off in a week.
	if want != "" && !strings.HasPrefix(want, have) && !strings.HasPrefix(have, want) {
		return ReadbackDiverged
	}
	if !got.Bound {
		return ReadbackInstalledNotBound
	}
	return ReadbackServing
}
