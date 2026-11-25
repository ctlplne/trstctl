// SPDX-License-Identifier: BUSL-1.1

package netdevicetest

import (
	"strings"
	"testing"
)

func TestIOSXEEditorCtrlUKeepsTheSuffixAfterCursorMove(t *testing.T) {
	for _, move := range []string{"\x01", strings.Repeat("\x02", len("write memory")), strings.Repeat("\x1b[D", len("write memory"))} {
		reader := &lineReader{r: strings.NewReader("write memory" + move + "\x15\r"), dialect: IOSXE}
		line, ok := reader.next()
		if !ok || line != "write memory" {
			t.Errorf("move %q then Ctrl-U: next = %q, %v; want the retained protected command", move, line, ok)
		}
	}
}
