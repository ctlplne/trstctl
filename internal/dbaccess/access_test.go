// SPDX-License-Identifier: BUSL-1.1

package dbaccess

import "testing"

// A239-L1: a role's class is its binding or its exact name, nothing looser.
func TestOfRoleReadsOnlyABindingOrAnExactClassName(t *testing.T) {
	for _, tc := range []struct {
		role, binding string
		want          Access
		ok            bool
	}{
		{"readonly", "", Read, true},
		{"ReadOnly", "", Read, true},
		{"reader", "", Read, true},
		{"read", "", Read, true},
		{"read-only", "", Read, true},
		{"readwrite", "", ReadWrite, true},
		{"read_write", "", ReadWrite, true},
		{"writer", "", ReadWrite, true},
		// A name that merely contains a class word states nothing.
		{"support-read", "", Unset, false},
		{"readonly-reporting", "", Unset, false},
		{"mysql-reader", "", Unset, false},
		{"viewer", "", Unset, false},
		{"reporting", "", Unset, false},
		{"", "", Unset, false},
		// A binding wins over the name, either way.
		{"viewer", "read", Read, true},
		{"reporting", "readWrite", ReadWrite, true},
		{"readonly", "readwrite", ReadWrite, true},
		{"writer", " READ ", Read, true},
		// A binding that names no class is no class.
		{"readonly", "admin", Unset, false},
		{"reader", "select", Unset, false},
	} {
		got, ok := OfRole(tc.role, tc.binding)
		if got != tc.want || ok != tc.ok {
			t.Errorf("OfRole(%q, %q) = %v, %v; want %v, %v", tc.role, tc.binding, got, ok, tc.want, tc.ok)
		}
	}
	if Read.String() != BindingRead || ReadWrite.String() != BindingReadWrite || Unset.String() != "unset" {
		t.Fatalf("class spellings %q %q %q", Read, ReadWrite, Unset)
	}
}
