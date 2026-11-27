// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bufio"
	"bytes"
	"errors"
	"math"
	"strconv"
	"testing"
)

func TestRESPLengthsStayWithinBudgetBeforeAllocation(t *testing.T) {
	large := strconv.FormatInt(math.MaxInt64, 10)
	for name, raw := range map[string]string{
		"bulk":     "$" + large + "\r\n",
		"verbatim": "=" + large + "\r\n",
		"map":      "%" + large + "\r\n",
		"array":    "*" + large + "\r\n",
		"set":      "~" + large + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			budget := maxRESPReplyBytes
			_, err := readRESPValue(bufio.NewReader(bytes.NewBufferString(raw)), 0, &budget)
			if !errors.Is(err, ErrAccessUnreadable) {
				t.Fatalf("length admission = %v, want unreadable reply", err)
			}
		})
	}
}

func FuzzReadRESPValueStaysWithinBudget(f *testing.F) {
	for _, raw := range []string{"+OK\r\n", "$3\r\nabc\r\n", "%1\r\n+key\r\n+value\r\n", "$9223372036854775807\r\n", "%9223372036854775807\r\n"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		budget := maxRESPReplyBytes
		_, _ = readRESPValue(bufio.NewReader(bytes.NewReader(raw)), 0, &budget)
		if budget < 0 || budget > maxRESPReplyBytes {
			t.Fatalf("remaining reply budget = %d", budget)
		}
	})
}
