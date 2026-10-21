// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"context"
	"errors"
	"sort"
)

// Takedown as an executable operation (A43).
//
// Rollback re-binds a listener to a predecessor object and leaves the bad
// object on the appliance. A rogue or compromised certificate that stays
// installed can be bound again by anyone with appliance access, and it keeps
// its private key on the device. Takedown removes the fingerprint-named object
// (and its key) that a trstctl deploy installed, by the same naming rule the
// deploy and the rollback use, so the three can never disagree about which
// object is meant.
//
// It never unbinds a listener. Removing the object a listener is serving would
// take the service down or leave the appliance in an inconsistent state, so a
// bound object is refused with ErrTakedownObjectBound: roll back or deploy a
// replacement first, then take the old object down.

// Takedown names the installed object to remove.
type Takedown struct {
	// Target is the listener, profile, virtual service or template whose
	// deploys named the object.
	Target string
	// Fingerprint identifies the installed object, as the deploy named it.
	Fingerprint string
	// Reason is operator-facing context for the transcript. It never reaches
	// the appliance.
	Reason string
}

// Takedowner is the optional object-removal capability of a Connector.
//
// Optional on purpose, like Rollbacker: a family whose API cannot delete an
// installed object by name cannot do this, and the honest outcome is that it
// does not implement the interface and the census says so.
type Takedowner interface {
	Connector
	// Takedown removes the named object. It must return ErrTakedownObjectBound
	// when the object is what the target currently serves, and
	// ErrTakedownNotInstalled when there is nothing of that name to remove.
	Takedown(ctx context.Context, sb Sandbox, td Takedown) error
}

// ErrTakedownUnsupported is returned when a connector cannot remove objects.
var ErrTakedownUnsupported = errors.New("connector: this connector cannot remove an installed object by name")

// ErrTakedownObjectBound is returned when the object is bound to the serving
// listener. Removing it would take the service down; re-bind first.
var ErrTakedownObjectBound = errors.New("connector: the object is bound to the serving listener; roll back or deploy a replacement before taking it down")

// ErrTakedownNotInstalled is returned when no object of that name exists.
var ErrTakedownNotInstalled = errors.New("connector: no installed object carries that fingerprint on the target")

// takedownCapableFamilies is the census of connectors that can delete the
// fingerprint-named object a deploy installed. Each appliance here exposes a
// delete-by-name call for certificate objects or files, separate from upload.
var takedownCapableFamilies = []string{
	"f5",
	"kemp",
	"netscaler",
	"a10",
}

// TakedownCapableConnectors reports the families that can remove installed
// objects, sorted.
func TakedownCapableConnectors() []string {
	out := append([]string(nil), takedownCapableFamilies...)
	sort.Strings(out)
	return out
}

// CanTakedown reports whether a connector family can remove an installed object.
func CanTakedown(name string) bool {
	for _, n := range takedownCapableFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// RunTakedown executes an object removal through connector c under the same
// grant as a deploy. A connector that cannot remove objects answers
// ErrTakedownUnsupported before touching the network.
func RunTakedown(ctx context.Context, c Connector, ops Ops, td Takedown) (Stats, error) {
	r, ok := c.(Takedowner)
	if !ok {
		return Stats{}, ErrTakedownUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	err := r.Takedown(ctx, sb, td)
	return Stats{Denied: sb.denied}, err
}
