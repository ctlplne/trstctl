// SPDX-License-Identifier: BUSL-1.1
package accessrules

import "bytes"

var mongoOperationNames = []string{"aggregate", "atlasversion", "buildinfo", "bulkwrite", "collmod", "collstats", "connectionstatus", "count", "create", "createindexes", "dbstats", "delete", "distinct", "drop", "dropdatabase", "dropindexes", "endsessions", "explain", "find", "findandmodify", "getmore", "getparameter", "insert", "killcursors", "listcollections", "listdatabases", "listindexes", "ping", "renamecollection", "rolesinfo", "serverstatus", "update", "usersinfo", "validate", "whatsmyuri"}

// MongoOperation classifies a command name only. Document values, authentication
// and sequence documents cannot become selector facts. Aliases and aggregation
// stages are separate command classes, not containment of an equivalent effect.
func MongoOperation(name []byte) string {
	if len(name) < 1 || len(name) > 64 {
		return ""
	}
	for _, c := range name {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return ""
		}
	}
	for _, op := range mongoOperationNames {
		if bytes.EqualFold(name, []byte(op)) {
			return op
		}
	}
	return ""
}
