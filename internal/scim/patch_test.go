// SPDX-License-Identifier: MPL-2.0

package scim

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestApplyUserPatchSupportsReplaceObjectAndScalarActive(t *testing.T) {
	u := User{
		UserName:    "old@example.com",
		DisplayName: "Old Name",
		Active:      true,
	}
	ops := []PatchOperation{
		{Op: "replace", Value: raw(`{"active":"false","userName":"new@example.com","displayName":"New Name"}`)},
		{Op: "replace", Path: "name.formatted", Value: raw(`"New Name"`)},
	}
	if err := ApplyUserPatch(&u, ops); err != nil {
		t.Fatalf("ApplyUserPatch: %v", err)
	}
	if u.Active {
		t.Fatal("active patch did not disable the user")
	}
	if u.UserName != "new@example.com" || u.DisplayName != "New Name" {
		t.Fatalf("unexpected user after patch: %#v", u)
	}
	if u.Name == nil || u.Name.Formatted != "New Name" {
		t.Fatalf("name.formatted was not applied: %#v", u.Name)
	}

	if err := ApplyUserPatch(&u, []PatchOperation{{Op: "replace", Path: "active", Value: raw(`not-bool`)}}); err == nil {
		t.Fatal("invalid active patch must fail closed")
	}
}

func TestParseGroupPatchSupportsMemberAddRemoveAndReplace(t *testing.T) {
	replaceName := "viewer"
	ops := []PatchOperation{
		{Op: "add", Path: "members", Value: raw(`[{"value":"alice@example.com"},{"value":"bob@example.com"}]`)},
		{Op: "remove", Path: `members[value eq "carol@example.com"]`},
		{Op: "replace", Value: raw(`{"displayName":"viewer","members":[{"value":"dave@example.com"}]}`)},
		{Op: "add", Path: "displayName", Value: raw(`"` + replaceName + `"`)},
	}
	got := ParseGroupPatch(ops)
	if !reflect.DeepEqual(got.Add, []string{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("add members mismatch: %#v", got.Add)
	}
	if !reflect.DeepEqual(got.Remove, []string{"carol@example.com"}) {
		t.Fatalf("remove members mismatch: %#v", got.Remove)
	}
	if got.ReplaceAll == nil || !reflect.DeepEqual(*got.ReplaceAll, []string{"dave@example.com"}) {
		t.Fatalf("replace members mismatch: %#v", got.ReplaceAll)
	}
	if got.DisplayName == nil || *got.DisplayName != "viewer" {
		t.Fatalf("displayName mismatch: %#v", got.DisplayName)
	}
}

func raw(s string) json.RawMessage {
	return json.RawMessage(s)
}
