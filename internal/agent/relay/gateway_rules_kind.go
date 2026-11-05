// SPDX-License-Identifier: BUSL-1.1

package relay

// KindAccessGatewayRulesSession is a versioned, policy-bearing session. An old
// gateway does not claim this kind and cannot ignore its enforcement snapshot.
const KindAccessGatewayRulesSession = "access.gateway.session.rules.v1"

const KindAccessGatewaySSHRulesSession = "access.gateway.session.rules.ssh.v1"

const KindAccessGatewayMySQLRulesSession = "access.gateway.session.rules.mysql.v1"

const KindAccessGatewayRedisRulesSession = "access.gateway.session.rules.redis.v1"

const KindAccessGatewayMongoRulesSession = "access.gateway.session.rules.mongodb.v1"

func IsCommandRulesSession(kind string) bool {
	return kind == KindAccessGatewayRulesSession || kind == KindAccessGatewaySSHRulesSession || kind == KindAccessGatewayMySQLRulesSession || kind == KindAccessGatewayRedisRulesSession || kind == KindAccessGatewayMongoRulesSession
}

func IsAccessGatewaySession(kind string) bool {
	return kind == KindAccessGatewaySession || IsCommandRulesSession(kind)
}
