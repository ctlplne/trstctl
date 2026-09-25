// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider_test

// The local grant command requires the production event privacy catalog, just
// as the assembled binary does. Load it outside package provider to avoid a
// provider -> ee -> provider import cycle; do not replace it with a test policy.
import _ "trstctl.com/trstctl/ee"
