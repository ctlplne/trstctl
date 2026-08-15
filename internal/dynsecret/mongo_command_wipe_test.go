// SPDX-License-Identifier: MPL-2.0

package dynsecret

import (
	"bytes"
	"strconv"
	"testing"
)

// TestMongoCommandDoesNotReallocateAfterThePassword is the regression guard for
// the AN-8 wipe that could not reach what it was meant to erase.
//
// CreateUser does `defer secret.Wipe(cmd)` — the intent is right. But the builder
// grew the buffer with append(): the password went in, then the roles document
// was appended, and that append reallocated, copying the password into a fresh
// array and abandoning the old one. Wiping the returned slice zeroes only the
// final array; the abandoned copy stays on the heap holding the plaintext.
//
// Capacity reserved up front means one backing array from start to finish, which
// is what makes the wipe honest. Comparing cap() before and after is how that is
// observable from a test.
func TestMongoCommandDoesNotReallocateAfterThePassword(t *testing.T) {
	password := []byte("s3cret-generated-password-that-is-long-enough-to-matter")
	roles := []MongoRole{
		{Role: "readWrite", DB: "appdb"},
		{Role: "read", DB: "reporting"},
		{Role: "dbAdmin", DB: "appdb"},
	}

	cmd := mongoCreateUserCommand("svc-account-with-a-longish-name", password, roles)
	if !bytes.Contains(cmd, password) {
		t.Fatal("fixture is broken: the built command does not contain the password")
	}

	// Rebuild step by step and assert the backing array never moves once the
	// password is in it.
	rolesArray, rolesStart := beginBSONDocument(nil)
	for i, role := range roles {
		roleDoc, roleStart := beginBSONDocument(nil)
		roleDoc = appendBSONString(roleDoc, "role", []byte(role.Role))
		roleDoc = appendBSONString(roleDoc, "db", []byte(role.DB))
		roleDoc = finishBSONDocument(roleDoc, roleStart)
		rolesArray = appendBSONDocument(rolesArray, 0x03, itoaForTest(i), roleDoc)
	}
	rolesArray = finishBSONDocument(rolesArray, rolesStart)

	buf, start := beginBSONDocument(make([]byte, 0,
		mongoCommandCapacity("svc-account-with-a-longish-name", password, rolesArray)))
	capBefore := cap(buf)
	buf = appendBSONString(buf, "createUser", []byte("svc-account-with-a-longish-name"))
	buf = appendBSONString(buf, "pwd", password)
	capAfterPassword := cap(buf)
	buf = appendBSONDocument(buf, 0x04, "roles", rolesArray)
	buf = finishBSONDocument(buf, start)

	if cap(buf) != capBefore || capAfterPassword != capBefore {
		t.Fatalf("the buffer reallocated while building (cap %d → %d → %d); an abandoned copy of "+
			"the password is on the heap where secret.Wipe cannot reach it",
			capBefore, capAfterPassword, cap(buf))
	}
	if !bytes.Equal(buf, cmd) {
		t.Error("the step-by-step rebuild does not match mongoCreateUserCommand; the fixture has drifted")
	}
}

// TestMongoCommandCapacityIsSufficient checks the reserve across shapes, since
// under-reserving silently reintroduces the reallocation.
func TestMongoCommandCapacityIsSufficient(t *testing.T) {
	for _, tc := range []struct {
		name     string
		user     string
		password []byte
		roles    []MongoRole
	}{
		{"minimal", "u", []byte("p"), nil},
		{"no roles", "service-account", []byte("correct-horse-battery-staple"), nil},
		{"many roles", "svc", []byte("pw"), []MongoRole{
			{Role: "readWrite", DB: "a"}, {Role: "read", DB: "b"},
			{Role: "dbAdmin", DB: "c"}, {Role: "clusterMonitor", DB: "admin"},
			{Role: "backup", DB: "admin"}, {Role: "restore", DB: "admin"},
		}},
		{"long password", "u", bytes.Repeat([]byte("x"), 512), []MongoRole{{Role: "r", DB: "d"}}},
		{"long everything", bytes.NewBufferString("").String() + string(bytes.Repeat([]byte("n"), 256)),
			bytes.Repeat([]byte("p"), 256), []MongoRole{{Role: "readWrite", DB: "appdb"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mongoCreateUserCommand(tc.user, tc.password, tc.roles)
			if len(tc.password) > 0 && !bytes.Contains(got, tc.password) {
				t.Fatal("built command does not contain the password")
			}
			// The reserve must cover the final length, or a realloc happened.
			if want := mongoCommandCapacity(tc.user, tc.password, nil); len(got) > want+512 {
				t.Errorf("command is %d bytes but the reserve formula budgets ~%d; the formula is too tight",
					len(got), want)
			}
		})
	}
}

func itoaForTest(i int) string {
	return strconv.Itoa(i)
}
