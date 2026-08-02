// SPDX-License-Identifier: MPL-2.0

// Package netexecgood is the positive fixture: an ordinary outbound caller that
// obtains its client from the reviewed constructor instead of building one, and
// therefore must produce no diagnostics.
package netexecgood

import (
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func fetch(url string) error {
	client := netsec.SafeClient(10 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
