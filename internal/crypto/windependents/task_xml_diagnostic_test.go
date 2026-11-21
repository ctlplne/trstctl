// SPDX-License-Identifier: BUSL-1.1

package windependents

import (
	"encoding/binary"
	"strings"
	"testing"
)

func taskXMLTestUTF16(text string) []byte {
	raw := make([]byte, 2*len(text))
	for i := range text {
		binary.LittleEndian.PutUint16(raw[i*2:], uint16(text[i]))
	}
	return raw
}

func TestTaskXMLDiagnosticNamesChangedElementWithoutExposingValues(t *testing.T) {
	before := taskXMLSegments(taskXMLTestUTF16(`<Task><RegistrationInfo><Date>old</Date></RegistrationInfo><Actions><Exec><Arguments>private-one</Arguments></Exec></Actions></Task>`))
	after := taskXMLSegments(taskXMLTestUTF16(`<Task><RegistrationInfo><Date>new</Date></RegistrationInfo><Actions><Exec><Arguments>private-two</Arguments></Exec></Actions></Task>`))
	where := firstTaskXMLDifference(before, after)
	if !strings.Contains(where, "Date") || strings.Contains(where, "old") || strings.Contains(where, "new") || strings.Contains(where, "private") {
		t.Fatalf("diagnostic did not safely identify changed element: %q", where)
	}
	added := taskXMLSegments(taskXMLTestUTF16(`<Task><RegistrationInfo><Date>old</Date><Author>user</Author></RegistrationInfo><Actions><Exec><Arguments>private-one</Arguments></Exec></Actions></Task>`))
	where = firstTaskXMLDifference(before, added)
	if !strings.Contains(where, "Author") || strings.Contains(where, "user") {
		t.Fatalf("diagnostic did not safely identify inserted element: %q", where)
	}
}
