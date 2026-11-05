// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import "testing"

func TestCredentialAccountReadsTheSignInAccount(t *testing.T) {
	for _, tc := range []struct {
		providerType, credential, want string
		ok                             bool
	}{
		{"postgresql", "postgres://orders_app_a:pw@db.internal:5432/orders?sslmode=disable", "orders_app_a", true},
		{"postgresql", "host=db.internal user=orders_app_b password=pw dbname=orders", "orders_app_b", true},
		{"mysql", "orders_app_a:pw@tcp(db.internal:3306)/orders", "orders_app_a", true},
		{"mysql", "not a dsn", "", false},
		{"redis", "redis://user:pw@cache:6379", "", false},
	} {
		got, ok := CredentialAccount(tc.providerType, []byte(tc.credential))
		if got != tc.want || ok != tc.ok {
			t.Errorf("CredentialAccount(%s, %q) = %q, %v; want %q, %v", tc.providerType, tc.credential, got, ok, tc.want, tc.ok)
		}
	}
}
