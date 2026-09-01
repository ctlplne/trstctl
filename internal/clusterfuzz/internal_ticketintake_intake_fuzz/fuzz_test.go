// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/ticketintake"
)

// FuzzParseProviderPageAUD47 keeps both untrusted provider decoders on the
// normal Go fuzzing path. Any byte sequence may be rejected, but it must not
// panic or escape the decoder's bounded result contract.
func FuzzParseProviderPageAUD47(f *testing.F) {
	f.Add(byte(0), []byte(`{"result":[{"sys_id":"tick-000001","subject":"api.example","profile":"tls-server"}]}`))
	f.Add(byte(1), []byte(`{"issues":[{"id":"10001","key":"NHI-1","fields":{"subject":"api.example","profile":"tls-server"}}],"isLast":true,"total":1}`))
	f.Add(byte(0), []byte(`{"result":`))
	f.Add(byte(1), []byte(`null`))

	f.Fuzz(func(t *testing.T, provider byte, payload []byte) {
		intent := ticketintake.SyncIntent{
			SubjectField: "subject",
			ProfileField: "profile",
			PageLimit:    ticketintake.MaxTickets,
		}
		if provider%2 == 0 {
			intent.System = ticketintake.SystemServiceNow
		} else {
			intent.System = ticketintake.SystemJira
		}

		page, err := ticketintake.ParsePage(bytes.NewReader(payload), intent)
		if err != nil {
			return
		}
		if len(page.SourceRefs) > ticketintake.MaxTickets || len(page.Tickets) > ticketintake.MaxTickets {
			t.Fatalf("decoder escaped %d-ticket bound: %+v", ticketintake.MaxTickets, page)
		}
	})
}
