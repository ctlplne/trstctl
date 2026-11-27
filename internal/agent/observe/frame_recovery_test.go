// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestC0001CaptureReplayReportsParserPanicWithoutKillingAgent(t *testing.T) {
	for _, tc := range []struct {
		path  string
		ports []uint16
	}{
		{"testdata/x1l4-mysql-plaintext.pcap", []uint16{3306}},
		{"testdata/x1l3r-tls12-dumpcap.pcapng", []uint16{8443}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			capture, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			a := NewAssembler(tc.ports, 16, time.Minute, func(Event) {
				panic("synthetic parser fault")
			})
			_, err = ReplayPcap(bytes.NewReader(capture), a)
			if err == nil || !strings.Contains(err.Error(), "captured frame") || strings.Contains(err.Error(), "synthetic parser fault") {
				t.Fatalf("capture replay parser failure = %v; want a bounded, redacted error", err)
			}
		})
	}
}
