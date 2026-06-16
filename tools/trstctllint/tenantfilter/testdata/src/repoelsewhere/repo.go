//trstctl:repository
package repoelsewhere

// A repository package outside internal/store opts in with the marker directive
// above; its DML queries are then subject to AN-1 too.
const tokensByName = "SELECT id FROM tokens WHERE name = $1" // want "does not filter on tenant_id"
