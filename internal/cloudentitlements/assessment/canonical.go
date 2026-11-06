// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// canonicalJSON preserves exact decimal meaning, including numbers above the
// float64 integer range. PostgreSQL JSONB may reorder keys or expand exponents.
func canonicalJSON(raw []byte) ([]byte, error) {
	if len(raw) > 1<<20 {
		return nil, errors.New("canonical evidence exceeds byte bound")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	budget := canonicalBudget{nodes: 100000, expanded: 1 << 20}
	if err := budget.normalize(value, 0); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

type canonicalBudget struct{ nodes, expanded int }

func (b *canonicalBudget) normalize(value any, depth int) error {
	b.nodes--
	if b.nodes < 0 || depth > 64 {
		return errors.New("canonical evidence exceeds structural bound")
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			b.expanded -= len(key) + 4
			if number, ok := item.(json.Number); ok {
				b.nodes--
				if b.nodes < 0 {
					return errors.New("canonical evidence exceeds node bound")
				}
				normalized, size, err := decimalNumber(number)
				if err != nil {
					return err
				}
				v[key] = normalized
				b.expanded -= size
			} else if err := b.normalize(item, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			b.expanded--
			if number, ok := item.(json.Number); ok {
				b.nodes--
				if b.nodes < 0 {
					return errors.New("canonical evidence exceeds node bound")
				}
				normalized, size, err := decimalNumber(number)
				if err != nil {
					return err
				}
				v[i] = normalized
				b.expanded -= size
			} else if err := b.normalize(item, depth+1); err != nil {
				return err
			}
		}
	case string:
		b.expanded -= len(v) + 2
	case bool, nil:
		b.expanded -= 5
	}
	if b.expanded < 0 {
		return errors.New("canonical evidence exceeds expanded byte bound")
	}
	return nil
}
func decimalNumber(number json.Number) (json.Number, int, error) {
	text := number.String()
	sign := ""
	if strings.HasPrefix(text, "-") {
		sign = "-"
		text = text[1:]
	}
	exponent := 0
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		suffix := text[index+1:]
		if len(suffix) > 6 {
			return "", 0, errors.New("JSON exponent exceeds bound")
		}
		var err error
		exponent, err = strconv.Atoi(suffix)
		if err != nil || exponent > 4096 || exponent < -4096 {
			return "", 0, errors.New("JSON exponent exceeds bound")
		}
		text = text[:index]
	}
	fraction := 0
	if index := strings.IndexByte(text, '.'); index >= 0 {
		fraction = len(text) - index - 1
		text = text[:index] + text[index+1:]
	}
	digits := strings.TrimLeft(text, "0")
	if digits == "" {
		return json.Number("0"), 1, nil
	}
	power := exponent - fraction
	trimmed := strings.TrimRight(digits, "0")
	power += len(digits) - len(trimmed)
	digits = trimmed
	expanded := len(digits) + 1
	if power >= 0 {
		expanded = len(digits) + power
	} else if len(digits)+power <= 0 {
		expanded = 2 - power
	}
	expanded += len(sign)
	if power == 0 {
		return json.Number(sign + digits), expanded, nil
	}
	return json.Number(sign + digits + "e" + strconv.Itoa(power)), expanded, nil
}
