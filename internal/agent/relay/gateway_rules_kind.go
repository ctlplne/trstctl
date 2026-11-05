// SPDX-License-Identifier: BUSL-1.1

package relay

// KindAccessGatewayRulesSession is a versioned, policy-bearing session. An old
// gateway does not claim this kind and cannot ignore its enforcement snapshot.
const KindAccessGatewayRulesSession = "access.gateway.session.rules.v1"

const KindAccessGatewaySSHRulesSession = "access.gateway.session.rules.ssh.v1"

func IsCommandRulesSession(kind string) bool {
	return kind == KindAccessGatewayRulesSession || kind == KindAccessGatewaySSHRulesSession
}

func IsAccessGatewaySession(kind string) bool {
	return kind == KindAccessGatewaySession || IsCommandRulesSession(kind)
}
