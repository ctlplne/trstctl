// SPDX-License-Identifier: BUSL-1.1

//go:build gofuzz

package dynsecret

import (
	"context"
	"errors"
)

// Fuzz builds (ClusterFuzzLite compiles every fuzz target with -tags gofuzz)
// leave the Cassandra driver out: gocql v2.1.2's own gofuzz-only file does
// not compile, and nothing a fuzz target runs reaches a Cassandra node. This
// build of the provider refuses to connect.

var errCassandraFuzzBuild = errors.New("dynsecret cassandra: the driver is not part of fuzz builds")

func cassandraAlreadyMember(error) bool { return false }

func cassandraErrorCode(error) string { return "not built" }

func (b *CassandraBackend) dialAdmin(context.Context) (cassandraAdmin, error) {
	return nil, errCassandraFuzzBuild
}
