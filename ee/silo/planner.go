package silo

import (
	"sort"
	"strings"
)

func ProvisionPlan(schema string, tenantTables []string) []string {
	tables := append([]string(nil), tenantTables...)
	sort.Strings(tables)
	qSchema := quoteIdent(schema)
	plan := []string{
		"CREATE SCHEMA IF NOT EXISTS " + qSchema,
		"GRANT USAGE ON SCHEMA " + qSchema + " TO trstctl_app",
	}
	for _, table := range tables {
		qTable := qSchema + "." + quoteIdent(table)
		plan = append(plan,
			"CREATE TABLE IF NOT EXISTS "+qTable+" (LIKE public."+quoteIdent(table)+" INCLUDING ALL)",
			"ALTER TABLE "+qTable+" ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE "+qTable+" FORCE ROW LEVEL SECURITY",
			"DROP POLICY IF EXISTS tenant_isolation ON "+qTable,
			"CREATE POLICY tenant_isolation ON "+qTable+" USING (tenant_id = NULLIF(current_setting('trstctl.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('trstctl.tenant_id', true), '')::uuid)",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON "+qTable+" TO trstctl_app",
		)
	}
	return plan
}

func TeardownPlan(schema string) []string {
	return []string{"DROP SCHEMA IF EXISTS " + quoteIdent(schema) + " CASCADE"}
}

func quoteIdent(raw string) string {
	return `"` + strings.ReplaceAll(raw, `"`, `""`) + `"`
}
