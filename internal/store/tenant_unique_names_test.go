// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// tenantUniqueNameGuards is how each table with a tenant-unique index on a
// name stays clear of LS-1: a command that appends a duplicate name whose
// projection then meets the index leaves an event no rebuild applies. The
// tables of tenantNameHeldSQL refuse a held name under the projection lock;
// every other table is listed with the reason a duplicate cannot reach its
// projection, or with the open lead that closes it.
var tenantUniqueNameGuards = map[string]string{ // #nosec G101 -- table names and reasons, not credentials (CWE-798)
	"acme_dns01_provider_configs":     "the API refuses a held name under the projection lock (EnsureACMEDNS01ProviderConfigNameAvailable) and the projection skips one",
	"certificate_profiles":            "a held name is the profile's next version (NextProfileVersion under the projection lock); the projection upserts on (tenant_id, name, version) and deactivates the other active versions first",
	"credentials":                     "not projected from events: written directly with ON CONFLICT (tenant_id, scope, ref, name) DO UPDATE",
	"discovery_schedules":             "the command refuses a held name under another id before the append (ErrDiscoveryScheduleIdentityConflict, 409)",
	"discovery_segments":              "the segment's id derives from its name (uuid.NewSHA1), so a held name is that segment's update",
	"discovery_sources":               "the command reuses a held name's id, or refuses another kind or id (ErrDiscoverySourceIdentityConflict, 409), under the tenant's resource-creation lock",
	"secret_store":                    "not a rebuilt read model (sealed secrets are kept across a rebuild); a create refuses a held name (409) before its event, under the secret's mutation fence",
	"secret_store_versions":           "a version is its secret's next, under the secret's mutation fence; the name is the secret's own",
	"ticket_intake_schedules":         "the projection upserts on (tenant_id, system, name): a held name is that schedule's update",
	"workload_attester_trust_sources": "the API refuses a held name before the append (ensureWorkloadAttesterTrustSourceNameAvailable) and the projection skips one; ids derive from the lowercased name",
	"external_observers":              "the command refuses a held name (ErrObserverNameTaken, 409) under the projection lock and the projection skips one",
	"tenant_members":                  "SCIM refuses a held userName (409 uniqueness) under the projection lock (applySCIMUser) before the member's event",
	"provider_operators":              "open lead LS-1-L2: a provider SCIM user with a new externalID under a held userName is not refused",
}

// TestEveryTenantUniqueNameIndexIsGuardedLS1: every table a migration gives a
// tenant-unique index on a name column is in tenantNameHeldSQL or
// tenantUniqueNameGuards, and neither lists a table that has none.
func TestEveryTenantUniqueNameIndexIsGuardedLS1(t *testing.T) {
	indexed := tenantUniqueNameIndexes(t)
	if len(indexed) < 15 {
		t.Fatalf("found %d tables with a tenant-unique name index; the scan is broken: %v", len(indexed), indexed)
	}
	var unguarded []string
	for table, where := range indexed {
		_, checked := tenantNameHeldSQL[table]
		reason, listed := tenantUniqueNameGuards[table]
		switch {
		case checked && listed:
			t.Errorf("%s is refused under the projection lock and also listed with a reason (%q); keep one", table, reason)
		case !checked && !listed:
			unguarded = append(unguarded, table+" ("+where+")")
		case listed && strings.TrimSpace(reason) == "":
			t.Errorf("%s is listed with no reason", table)
		}
	}
	sort.Strings(unguarded)
	for _, table := range unguarded {
		t.Errorf("%s has a tenant-unique name index and no LS-1 guard: refuse a held name under the projection lock "+
			"(tenantNameHeldSQL and the command) and make the projection apply a held name as a no-op, or list why a "+
			"duplicate cannot reach its projection in tenantUniqueNameGuards", table)
	}
	for table := range tenantNameHeldSQL {
		if _, ok := indexed[table]; !ok {
			t.Errorf("tenantNameHeldSQL checks %s, which has no tenant-unique name index", table)
		}
	}
	for table := range tenantUniqueNameGuards {
		if _, ok := indexed[table]; !ok {
			t.Errorf("tenantUniqueNameGuards lists %s, which has no tenant-unique name index", table)
		}
	}
}

var (
	createTableRE  = regexp.MustCompile(`(?s)CREATE TABLE(?: IF NOT EXISTS)?\s+([a-z_0-9]+)\s*\((.*?)\n\s*\);`)
	inlineUniqueRE = regexp.MustCompile(`UNIQUE\s*\(([^)]*)\)`)
	uniqueIndexRE  = regexp.MustCompile(`(?s)CREATE UNIQUE INDEX(?: CONCURRENTLY)?(?: IF NOT EXISTS)?\s+[a-z_0-9]+\s+ON\s+([a-z_0-9]+)\s*\((.*?)\)\s*(?:WHERE[^;]*)?;`)
	addUniqueRE    = regexp.MustCompile(`ALTER TABLE(?: IF EXISTS)?\s+([a-z_0-9]+)\s+ADD CONSTRAINT\s+[a-z_0-9]+\s+UNIQUE\s*\(([^)]*)\)`)
	sqlCommentRE   = regexp.MustCompile(`--[^\n]*`)
)

// tenantUniqueNameIndexes maps each table with a unique index or constraint
// whose first column is tenant_id and a later one a name column (name,
// user_name, lower(name), a JSON user_name) to the migration that made it.
func tenantUniqueNameIndexes(t *testing.T) map[string]string {
	t.Helper()
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	note := func(table, columns, file string) {
		cols := splitIndexColumns(columns)
		if len(cols) < 2 || cols[0] != "tenant_id" {
			return
		}
		for _, c := range cols[1:] {
			if strings.Contains(c, "name") {
				if _, seen := out[table]; !seen {
					out[table] = file
				}
				return
			}
		}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sql := sqlCommentRE.ReplaceAllString(string(raw), "")
		for _, m := range createTableRE.FindAllStringSubmatch(sql, -1) {
			for _, u := range inlineUniqueRE.FindAllStringSubmatch(m[2], -1) {
				note(m[1], u[1], e.Name())
			}
		}
		for _, m := range uniqueIndexRE.FindAllStringSubmatch(sql, -1) {
			note(m[1], m[2], e.Name())
		}
		for _, m := range addUniqueRE.FindAllStringSubmatch(sql, -1) {
			note(m[1], m[2], e.Name())
		}
	}
	return out
}

// splitIndexColumns splits an index's column list at the commas outside
// parentheses (lower(name), a JSON expression).
func splitIndexColumns(list string) []string {
	var cols []string
	depth, start := 0, 0
	for i, r := range list {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				cols = append(cols, strings.TrimSpace(list[start:i]))
				start = i + 1
			}
		}
	}
	return append(cols, strings.TrimSpace(list[start:]))
}
