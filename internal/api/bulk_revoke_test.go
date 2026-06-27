package api

import "testing"

func TestBulkRevokeRoutesAreRegistered(t *testing.T) {
	routes := New(nil, nil, nil).Routes()
	want := map[string]bool{
		"POST /api/v1/certificates/bulk-revoke": false,
		"POST /api/v1/identities/bulk-revoke":   false,
	}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		if _, ok := want[key]; ok {
			if rt.OperationID == "" || !rt.Mutation {
				t.Fatalf("%s route metadata = operation:%q mutation:%v", key, rt.OperationID, rt.Mutation)
			}
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("missing bulk revoke route %s", key)
		}
	}
}
