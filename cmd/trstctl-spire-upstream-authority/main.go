// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"trstctl.com/trstctl/internal/spireupstream"
)

func main() {
	plugin := spireupstream.New()
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
