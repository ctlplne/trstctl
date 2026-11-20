// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"trstctl.com/trstctl/internal/netsec"
)

// DatabaseTransport is supplied by the provider, independently of DSN bytes.
// The dialer's policy is applied even when no private CA is configured.
type DatabaseTransport struct {
	Dialer           netsec.DatabaseDialer
	CAPEM            []byte
	ServerName       string
	RoutingEndpoints []string
	// InitialDatabase fills an omitted database on a bound workload proof.
	InitialDatabase string
}

func databaseTransport(configured *DatabaseTransport) DatabaseTransport {
	if configured != nil {
		return *configured
	}
	// Direct library callers already hold operator-provided credentials.
	// They still get a bounded TCP dialer and can supply trust only by value.
	return DatabaseTransport{Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true})}
}
