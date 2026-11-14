// SPDX-License-Identifier: BUSL-1.1

package relp

import (
	"bufio"
	"bytes"
	"testing"
)

// P5-L3: transaction numbers run from 1 to 999,999,999 and then start at 1
// again.
func TestTransactionNumbersWrapToOneP5L3(t *testing.T) {
	s := &session{txnr: maxTxnr - 1}
	if got := s.queue("syslog", []byte("a")); got != maxTxnr {
		t.Fatalf("txnr = %d, want %d", got, maxTxnr)
	}
	if got := s.queue("syslog", []byte("a")); got != 1 {
		t.Fatalf("txnr after the last = %d, want 1", got)
	}
	if want := "999999999 syslog 1 a\n1 syslog 1 a\n"; string(s.out) != want {
		t.Fatalf("frames = %q, want %q", s.out, want)
	}
}

// FuzzReadFrame reads whatever a receiver sends: a frame it returns keeps
// RELP's limits, and nothing panics.
func FuzzReadFrame(f *testing.F) {
	for _, seed := range []string{
		"1 rsp 6 200 OK\n",
		"0 serverclose 0\n",
		"1 rsp 70 200 OK\nrelp_version=0\nrelp_software=librelp,1.11.0,https://x\ncommands=syslog\n",
		"3 rsp 0\n",
		"2 rsp 14 500 not taken\n",
		"1 rsp 1234567890 x\n",
		"1  rsp 6 200 OK\n",
		"1 rsp 6 200 OK",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		for range 4 {
			fr, err := readFrame(r)
			if err != nil {
				return
			}
			if fr.txnr < 0 || fr.txnr > maxTxnr || len(fr.command) == 0 || len(fr.command) > 32 || len(fr.data) > maxAnswer {
				t.Fatalf("frame out of RELP's limits: %d %q %d bytes", fr.txnr, fr.command, len(fr.data))
			}
			_, _ = status(fr.data)
		}
	})
}
