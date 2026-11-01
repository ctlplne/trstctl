// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"strings"
	"testing"
)

// Q6: the decoy's DSN names its own database and the login, and nothing in it
// says "decoy" — a thief reading it sees an ordinary generated application login.
func TestPostgresDecoyDSNNamesTheDecoyDatabaseAndNothingSaysDecoy(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ admin, want string }{
		"uri with query": { // #nosec G101 -- placeholder test DSNs, not credentials (CWE-798)
			admin: "postgres://admin:adminpw@db.internal:5432/postgres?sslmode=require&application_name=x",
			want:  "postgres://trstctl_app_0123456789:pw@db.internal:5432/trstctl_app_0123456789_db?sslmode=require&application_name=x",
		},
		"uri without a path": { // #nosec G101 -- placeholder test DSNs, not credentials (CWE-798)
			admin: "postgresql://admin:adminpw@db.internal:5432",
			want:  "postgresql://trstctl_app_0123456789:pw@db.internal:5432/trstctl_app_0123456789_db",
		},
		"keyword": {
			admin: "host=db.internal port=5432 user=admin password=adminpw dbname=postgres sslmode=disable",
			want:  "dbname=trstctl_app_0123456789_db",
		},
	} {
		t.Run(name, func(t *testing.T) {
			role := "trstctl_app_0123456789"
			got, err := postgresDecoyDSN([]byte(tc.admin), role, []byte("pw"), DecoyDatabaseName(role))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.want) || strings.Contains(string(got), "adminpw") || strings.Contains(strings.ToLower(string(got)), "decoy") {
				t.Fatalf("decoy DSN = %q; want it to contain %q, no admin password and no hint of a decoy", got, tc.want)
			}
		})
	}
	req := GenerateRequest{Role: DecoyRole, LeaseID: "lease-1"}
	named := req
	named.Role = decoyLoginFragment
	user, err := scopedNameForRequest("trstctl", named, decoyLoginNameMaximum, "_")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(user, "decoy") || len(DecoyDatabaseName(user)) > 63 {
		t.Fatalf("decoy login %q (database %q) gives itself away or exceeds 63 characters", user, DecoyDatabaseName(user))
	}
}
