// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import (
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (e *evaluation) conditions(conditions map[string]map[string]conditionValues) truth {
	result := yes
	operators := make([]string, 0, len(conditions))
	for operator := range conditions {
		operators = append(operators, operator)
	}
	sort.Strings(operators)
	for _, operator := range operators {
		if e.exhausted {
			return unknown
		}
		keys := conditions[operator]
		names := make([]string, 0, len(keys))
		for key := range keys {
			names = append(names, key)
		}
		sort.Strings(names)
		for _, key := range names {
			if e.exhausted {
				return unknown
			}
			values, present := e.context[strings.ToLower(key)]
			if !present && !e.request.Context.Complete && !e.absent[strings.ToLower(key)] {
				result = and(result, unknown)
				continue
			}
			result = and(result, e.condition(operator, values, present, keys[key]))
		}
	}
	return result
}
func (e *evaluation) condition(operator string, values []string, present bool, expected []string) truth {
	quantifier := ""
	for _, prefix := range []string{"ForAllValues:", "ForAnyValue:"} {
		if strings.HasPrefix(operator, prefix) {
			quantifier = prefix
			operator = strings.TrimPrefix(operator, prefix)
			break
		}
	}
	ifExists := strings.HasSuffix(operator, "IfExists")
	operator = strings.TrimSuffix(operator, "IfExists")
	negative := false
	switch operator {
	case "StringNotEquals":
		operator = "StringEquals"
		negative = true
	case "StringNotEqualsIgnoreCase":
		operator = "StringEqualsIgnoreCase"
		negative = true
	case "StringNotLike":
		operator = "StringLike"
		negative = true
	case "ArnNotEquals":
		operator = "ArnEquals"
		negative = true
	case "ArnNotLike":
		operator = "ArnLike"
		negative = true
	case "NumericNotEquals":
		operator = "NumericEquals"
		negative = true
	case "DateNotEquals":
		operator = "DateEquals"
		negative = true
	case "NotIpAddress":
		operator = "IpAddress"
		negative = true
	}
	switch operator {
	case "Null":
		if ifExists || quantifier != "" || len(expected) != 1 {
			return unknown
		}
		wanted, ok := conditionBool(expected[0])
		if !ok {
			return unknown
		}
		if wanted == !present {
			return yes
		}
		return no
	case "StringEquals", "StringEqualsIgnoreCase", "StringLike", "ArnEquals", "ArnLike", "Bool", "IpAddress", "NumericEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals":
	default:
		return unknown
	}
	if !present {
		if ifExists || quantifier == "ForAllValues:" {
			return yes
		}
		if quantifier == "ForAnyValue:" {
			return no
		}
		if negative {
			return yes
		}
		return no
	}
	if len(values) > 1 && quantifier == "" {
		return unknown
	}
	result := no
	if quantifier == "ForAllValues:" {
		result = yes
	}
	for _, actual := range values {
		if e.exhausted {
			return unknown
		}
		if quantifier != "" && actual == "" {
			return unknown
		}
		one := no
		for _, wanted := range expected {
			if e.exhausted {
				return unknown
			}
			one = or(one, e.compareCondition(operator, actual, wanted))
		}
		// A negated value list means none may match, rather than any may differ.
		if negative {
			one = not(one)
		}
		if quantifier == "ForAllValues:" {
			result = and(result, one)
		} else {
			result = or(result, one)
		}
	}
	return result
}
func (e *evaluation) compareCondition(operator, actual, wanted string) truth {
	if !e.spend(1 + len(actual) + len(wanted)) {
		return unknown
	}
	if strings.Contains(wanted, "${") {
		return unknown
	}
	switch operator {
	case "StringEquals":
		if actual == wanted {
			return yes
		}
		return no
	case "StringEqualsIgnoreCase":
		if strings.EqualFold(actual, wanted) {
			return yes
		}
		return no
	case "StringLike":
		return e.glob(wanted, actual, false)
	case "ArnEquals", "ArnLike":
		if !strings.HasPrefix(actual, "arn:") || len(strings.SplitN(actual, ":", 6)) != 6 {
			return unknown
		}
		if wanted != "*" && (!strings.HasPrefix(wanted, "arn:") || len(strings.SplitN(wanted, ":", 6)) != 6) {
			return unknown
		}
		return e.glob(wanted, actual, false)
	case "Bool":
		a, ok := conditionBool(actual)
		b, bok := conditionBool(wanted)
		if !ok || !bok {
			return unknown
		}
		if a == b {
			return yes
		}
		return no
	case "IpAddress":
		address, err := netip.ParseAddr(actual)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return unknown
		}
		prefix, err := netip.ParsePrefix(wanted)
		if err != nil {
			single, e := netip.ParseAddr(wanted)
			if e != nil || single.Zone() != "" || single.Is4In6() {
				return unknown
			}
			prefix = netip.PrefixFrom(single, single.BitLen())
		}
		if prefix.Contains(address) {
			return yes
		}
		return no
	}
	if strings.HasPrefix(operator, "Numeric") {
		a, ok := conditionNumber(actual)
		b, bok := conditionNumber(wanted)
		if !ok || !bok {
			return unknown
		}
		comparison := 0
		if a < b {
			comparison = -1
		} else if a > b {
			comparison = 1
		}
		return orderedCondition(strings.TrimPrefix(operator, "Numeric"), comparison)
	}
	if strings.HasPrefix(operator, "Date") {
		a, ok := conditionDate(actual)
		b, bok := conditionDate(wanted)
		if !ok || !bok {
			return unknown
		}
		return orderedCondition(strings.TrimPrefix(operator, "Date"), a.Compare(b))
	}
	return unknown
}
func conditionBool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// Restrict numeric comparisons to ordinary finite decimal values with at most
// 15 digits. Unmodeled precision or extreme magnitude stays indeterminate.
func conditionNumber(value string) (float64, bool) {
	if len(value) == 0 || len(value) > 96 {
		return 0, false
	}
	mantissa := strings.SplitN(strings.ToLower(value), "e", 2)[0]
	digits := 0
	for _, v := range value {
		if !strings.ContainsRune("0123456789+-.eE", v) {
			return 0, false
		}
	}
	for _, v := range mantissa {
		if v >= '0' && v <= '9' {
			digits++
		}
	}
	if digits > 15 {
		return 0, false
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	if number != 0 && (math.Abs(number) < 1e-200 || math.Abs(number) > 1e200) {
		return 0, false
	}
	if number == 0 && strings.ContainsAny(mantissa, "123456789") {
		return 0, false
	}
	return number, true
}
func conditionDate(value string) (time.Time, bool) {
	if len(value) > 64 {
		return time.Time{}, false
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, true
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < -62135596800 || seconds > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}
func orderedCondition(operator string, comparison int) truth {
	matched := false
	switch operator {
	case "Equals":
		matched = comparison == 0
	case "LessThan":
		matched = comparison < 0
	case "LessThanEquals":
		matched = comparison <= 0
	case "GreaterThan":
		matched = comparison > 0
	case "GreaterThanEquals":
		matched = comparison >= 0
	default:
		return unknown
	}
	if matched {
		return yes
	}
	return no
}
