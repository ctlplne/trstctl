// SPDX-License-Identifier: BUSL-1.1

// Package dbaccess names what a leased PostgreSQL, MySQL or MongoDB credential
// may do (A239-L1). A role's class comes from an explicit binding, or from a
// role name that is itself a class name; never from a substring of the name,
// because "readwrite" contains "read" and "viewer" or "reporting" contain
// nothing a grant can be read from.
package dbaccess

import "strings"

// Access is a database lease's class.
type Access uint8

const (
	// Unset is no class: a role without one is refused, never guessed.
	Unset Access = iota
	// Read reads rows: SELECT on PostgreSQL and MySQL, MongoDB's read role.
	Read
	// ReadWrite also writes rows: SELECT, INSERT, UPDATE and DELETE on
	// PostgreSQL and MySQL, MongoDB's readWrite role.
	ReadWrite
)

// The role_bindings values a database provider takes.
const (
	BindingRead      = "read"
	BindingReadWrite = "readwrite"
)

// String is the class's role_bindings spelling.
func (a Access) String() string {
	switch a {
	case Read:
		return BindingRead
	case ReadWrite:
		return BindingReadWrite
	}
	return "unset"
}

// ParseBinding reads a role_bindings value: read or readwrite, in any case
// (MongoDB's own readWrite spelling is the same class).
func ParseBinding(binding string) (Access, bool) {
	switch strings.ToLower(strings.TrimSpace(binding)) {
	case BindingRead:
		return Read, true
	case BindingReadWrite:
		return ReadWrite, true
	}
	return Unset, false
}

// classNames are the role names that state their own class.
var classNames = map[string]Access{
	"read": Read, "reader": Read, "readonly": Read, "read-only": Read, "read_only": Read,
	"readwrite": ReadWrite, "read-write": ReadWrite, "read_write": ReadWrite, "writer": ReadWrite,
}

// OfRole is a role's class: its binding when it has one, else the class its
// exact name states. ok is false for any other role, and for a binding that
// names no class.
func OfRole(role, binding string) (Access, bool) {
	if strings.TrimSpace(binding) != "" {
		return ParseBinding(binding)
	}
	access, ok := classNames[strings.ToLower(strings.TrimSpace(role))]
	return access, ok
}
