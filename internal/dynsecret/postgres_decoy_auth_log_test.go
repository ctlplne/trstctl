// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"testing"
	"time"
)

// Q6-L6: refused sign-ins by watched roles are read from PostgreSQL's jsonlog
// lines (its documented keys); anything else — another role, a successful
// connection, another error, a line that is not a record — is not.
func TestDecoyRefusedSignInsAreReadFromTheJSONLogQ6L6(t *testing.T) {
	lines := `{"timestamp":"2026-11-15 01:02:03.456 UTC","user":"app_7f3a","dbname":"app_7f3a_db","pid":4242,"remote_host":"203.0.113.9","remote_port":51234,"session_id":"6736a1b3.1092","line_num":1,"ps":"authentication","session_start":"2026-11-15 01:02:03 UTC","vxid":"3/7","txid":0,"error_severity":"FATAL","state_code":"28P01","message":"password authentication failed for user \"app_7f3a\"","detail":"Connection matched file \"pg_hba.conf\" line 1: \"host all all all scram-sha-256\"","backend_type":"client backend","query_id":0}
{"timestamp":"2026-11-15 01:02:04.000 UTC","user":"app_7f3a","dbname":"postgres","pid":4243,"remote_host":"203.0.113.10","error_severity":"FATAL","state_code":"28000","message":"no pg_hba.conf entry for host \"203.0.113.10\", user \"app_7f3a\", database \"postgres\", no encryption","backend_type":"client backend"}
{"timestamp":"2026-11-15 01:02:05.000 UTC","user":"orders_app","dbname":"orders","pid":4244,"remote_host":"198.51.100.4","error_severity":"FATAL","state_code":"28P01","message":"password authentication failed for user \"orders_app\"","backend_type":"client backend"}
{"timestamp":"2026-11-15 01:02:06.000 UTC","user":"app_7f3a","dbname":"app_7f3a_db","pid":4245,"error_severity":"LOG","state_code":"00000","message":"connection authorized: user=app_7f3a database=app_7f3a_db","backend_type":"client backend"}
{"timestamp":"2026-11-15 01:02:07.000 UTC","user":"app_7f3a","dbname":"app_7f3a_db","pid":4246,"error_severity":"ERROR","state_code":"42501","message":"permission denied for table secrets","backend_type":"client backend"}
not a log record "state_code":"28P01"`
	found := parseDecoyAuthLog(lines, map[string]bool{"app_7f3a": true})
	if len(found) != 2 {
		t.Fatalf("read %d refusals, want the decoy's two: %+v", len(found), found)
	}
	first, second := found[0], found[1]
	if first.Role != "app_7f3a" || first.Database != "app_7f3a_db" || first.RemoteHost != "203.0.113.9" || first.StateCode != "28P01" ||
		!first.At.Equal(time.Date(2026, 11, 15, 1, 2, 3, 456_000_000, time.UTC)) {
		t.Fatalf("the wrong password reads %+v", first)
	}
	if second.StateCode != "28000" || second.Database != "postgres" || second.RemoteHost != "203.0.113.10" {
		t.Fatalf("the pg_hba refusal reads %+v", second)
	}
	if got := parseDecoyAuthLog(lines, map[string]bool{"someone_else": true}); len(got) != 0 {
		t.Fatalf("an unwatched role's refusals were read: %+v", got)
	}
}
