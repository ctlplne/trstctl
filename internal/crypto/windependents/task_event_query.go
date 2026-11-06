// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"errors"
	"fmt"
	"strings"
)

const nativeTaskChannel = "Microsoft-Windows-TaskScheduler/Operational"

func taskEventQuery(instance string) (string, error) {
	canonical, ok := canonicalTaskInstance(instance)
	if !ok {
		return "", errors.New("windows task: invalid native query instance")
	}
	values := []string{canonical, strings.ToUpper(canonical), "{" + canonical + "}", "{" + strings.ToUpper(canonical) + "}"}
	var predicates []string
	for _, name := range []string{"InstanceId", "TaskInstanceId"} {
		for _, value := range values {
			predicates = append(predicates, fmt.Sprintf("Data[@Name='%s']='%s'", name, value))
		}
	}
	xpath := "*[System[Provider[@Name='Microsoft-Windows-TaskScheduler'] and (EventID=100 or EventID=102 or EventID=201)] and EventData[" + strings.Join(predicates, " or ") + "]]"
	// Structured queries avoid XPath's 20-expression limit. All values are fixed
	// schema names or a validated GUID; no task path or caller expression enters.
	return `<QueryList><Query Id="0" Path="` + nativeTaskChannel + `"><Select Path="` + nativeTaskChannel + `">` + xpath + `</Select></Query></QueryList>`, nil
}
