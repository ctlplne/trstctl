// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/connector"
)

// Asking the appliance what it has, right after mutating it (epic E2).
//
// The relay is the only party that can ask. It holds the management credential
// for exactly this attempt, it is on the segment the appliance answers on, and
// the credential's life ends when the job returns — so the question has to be
// asked here or not at all.
//
// It runs ALONGSIDE the D2 handshake rather than instead of it, because the two
// answer different halves and only together do they locate a fault:
//
//	handshake old + readback ours-and-bound -> the VIP is fronted by something
//	                                           else, or DNS points elsewhere
//	handshake old + readback theirs         -> the binding did not move; the
//	                                           deploy patched the wrong profile
//	handshake old + readback absent         -> the deploy did not take at all
//
// A handshake failure alone reads as "the deploy failed", and the most common
// cause is the middle row — a binding the deploy never touched, on a device that
// reported success at every step.

// applianceReadback asks the connector's device what it has installed.
//
// Returns an empty verdict when the family cannot be asked. That is not a
// failure and must not be reported as one: an API with no way to enumerate an
// installed object cannot answer, and treating silence as divergence would make
// every cisco, fortigate and paloalto deploy look broken.
func applianceReadback(
	ctx context.Context, client *http.Client, intent DeployIntent, material Material,
) (connector.ReadbackVerdict, string) {
	if !connector.CanReadback(intent.Connector) {
		return "", ""
	}
	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return "", ""
		}
	}
	built, err := buildRelayConnector(intent.Connector, target, material)
	if err != nil {
		return "", ""
	}
	if closer, ok := built.(interface{ Close() }); ok {
		defer closer.Close()
	}

	installed, err := connector.RunReadback(ctx, built, connector.NewHTTPOps(client), intent.Target)
	if err != nil {
		// The device did not answer. Distinct from answering with something
		// unexpected, and reported as such — an unreachable management API after
		// a successful deploy is a monitoring problem, not a bad certificate.
		return "", "the appliance did not answer a readback after the deploy"
	}
	verdict := connector.ClassifyReadback(installed, intent.Fingerprint)
	return verdict, readbackDetail(verdict, installed)
}

// readbackDetail is the operator-facing sentence for a verdict.
//
// Each one names what to do next, because this text is read during an incident
// by somebody deciding where to look. "Readback failed" would send them to the
// wrong machine as often as not.
func readbackDetail(verdict connector.ReadbackVerdict, installed connector.Installed) string {
	switch verdict {
	case connector.ReadbackServing:
		return fmt.Sprintf("the appliance reports %q bound to this target", installed.ObjectName)
	case connector.ReadbackInstalledNotBound:
		return fmt.Sprintf("the certificate is installed on the appliance as %q but is not bound "+
			"to the serving object; the deploy landed and the binding did not", installed.ObjectName)
	case connector.ReadbackDiverged:
		return fmt.Sprintf("the appliance has %q bound to this target, which is not the "+
			"certificate this deploy installed; the binding did not move", installed.ObjectName)
	case connector.ReadbackAbsent:
		return "the appliance reports nothing installed for this target"
	case connector.ReadbackUnknown:
		return "the appliance named an installed object but not which certificate it is, so the " +
			"binding could not be compared"
	default:
		return ""
	}
}

// readbackConfirms reports whether a verdict is consistent with a good deploy.
//
// Only ReadbackServing and an absent verdict count. ReadbackUnknown does NOT:
// an API that will not say which certificate is bound has not confirmed
// anything, and folding it into success is exactly the overclaim D2 and D3 exist
// to remove.
func readbackConfirms(verdict connector.ReadbackVerdict) bool {
	return verdict == "" || verdict == connector.ReadbackServing
}
