// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"encoding/xml"
	"strings"
	"testing"
)

func checkTaskEventQuery(value string) bool {
	query, err := taskEventQuery(value)
	_, valid := canonicalTaskInstance(value)
	if err != nil {
		return !valid
	}
	if !valid || len(query) > 4096 {
		return false
	}
	var parsed struct {
		Queries []struct {
			Path    string `xml:"Path,attr"`
			Selects []struct {
				Path       string `xml:"Path,attr"`
				Expression string `xml:",chardata"`
			} `xml:"Select"`
		} `xml:"Query"`
	}
	if xml.Unmarshal([]byte(query), &parsed) != nil || len(parsed.Queries) != 1 || parsed.Queries[0].Path != nativeTaskChannel || len(parsed.Queries[0].Selects) != 1 || parsed.Queries[0].Selects[0].Path != nativeTaskChannel {
		return false
	}
	expression := parsed.Queries[0].Selects[0].Expression
	return strings.Contains(expression, "Microsoft-Windows-TaskScheduler") && strings.Contains(expression, "TaskInstanceId") && strings.Contains(expression, "InstanceId") && !strings.Contains(expression, "ActionName")
}
func TestTaskEventQueryIsFixedScopeA267(t *testing.T) {
	for _, value := range []string{"12345678-1234-4234-8234-123456789abc", "{12345678-1234-4234-8234-123456789ABC}", "", "00000000-0000-0000-0000-000000000000", "' or true() or '", "12345678-1234-4234-8234-123456789abc\\n"} {
		if !checkTaskEventQuery(value) {
			t.Fatal("native event query changed scope or emitted malformed XML")
		}
	}
}
func FuzzTaskEventQueryA267(f *testing.F) {
	f.Add("12345678-1234-4234-8234-123456789abc")
	f.Add("' or true()")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			return
		}
		if !checkTaskEventQuery(value) {
			t.Fatal("native event query scope/encoding differs")
		}
	})
}
