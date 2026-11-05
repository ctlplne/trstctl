// SPDX-License-Identifier: BUSL-1.1

package relay

// KindAccessGatewayRulesSession is a versioned, policy-bearing session. An old
// gateway does not claim this kind and cannot ignore its enforcement snapshot.
const KindAccessGatewayRulesSession = "access.gateway.session.rules.v1"

func IsAccessGatewaySession(kind string) bool {
	return kind == KindAccessGatewaySession || kind == KindAccessGatewayRulesSession
}
