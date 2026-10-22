// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"errors"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
)

// B6-2: the receipt names the install step that failed; the error itself
// stays on the host.
func TestHostInstallFailurePhraseNamesTheStep(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("nginx: write certificate: %w", connector.ErrDenied), transport.RenewInstallRefusedWrite},
		{errors.New("nginx: configuration test failed, not reloading: connector: activation failed: exit status 1 (bounded output redacted)"), transport.RenewInstallFailedConfigTest},
		{errors.New("nginx: reload: connector: activation failed: exit status 1 (bounded output redacted)"), transport.RenewInstallFailedReload},
		{errors.New("relay: host exec profile is not usable: connector: local allowed root \"/x\": not a directory"), transport.RenewInstallFailed},
	} {
		if got := hostInstallFailurePhrase(tc.err); got != tc.want {
			t.Fatalf("%v -> %q, want %q", tc.err, got, tc.want)
		}
	}
}
