// SPDX-License-Identifier: MPL-2.0

package eventsource

import (
	"fmt"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestReadModelTablesTrackStoreManifest(t *testing.T) {
	if !reflect.DeepEqual(readModelTables, store.ReadModelTables) {
		t.Fatalf("eventsource readModelTables drifted from store.ReadModelTables\nlinter=%v\nstore=%v", readModelTables, store.ReadModelTables)
	}
}

func TestRawSQLGuardCoversEveryStoreReadModelTable(t *testing.T) {
	for _, table := range store.ReadModelTables {
		for name, query := range map[string]string{
			"insert": fmt.Sprintf("INSERT INTO %s (tenant_id) VALUES ($1)", table),
			"update": fmt.Sprintf("UPDATE %s SET tenant_id = $1", table),
			"delete": fmt.Sprintf("DELETE FROM %s WHERE tenant_id = $1", table),
		} {
			t.Run(table+"/"+name, func(t *testing.T) {
				got, bad := rawReadModelWrite(query)
				if !bad || got != table {
					t.Fatalf("rawReadModelWrite(%q) = (%q, %v), want (%q, true)", query, got, bad, table)
				}
			})
		}
	}
}
